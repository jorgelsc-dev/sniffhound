"""Minimal, stdlib-only netlink client used to flip a WiFi interface between
managed and monitor mode via nl80211 (NL80211_CMD_SET_INTERFACE).

Deliberately narrow in scope: family resolution (CTRL_CMD_GETFAMILY),
NL80211_CMD_SET_INTERFACE, and ioctl-based interface up/down. No channel
selection, no scanning, no multipart/dump message handling — those aren't
needed for the manual monitor-mode toggle this module backs. No third-party
libraries and no shelling out to `iw`/`ip`/`airmon-ng`; everything goes
through `socket.AF_NETLINK` and `fcntl.ioctl`, both stdlib.

One deliberate exception: on a desktop where NetworkManager manages the
wireless interface, it actively fights an externally-set monitor mode —
confirmed live (see `set_networkmanager_managed`'s docstring) — bringing the
device back up after our mode switch makes NetworkManager reassociate it and
silently flip it right back to managed within seconds. There is no netlink
message that fixes this (it's NetworkManager's own device-management state,
not a kernel/driver setting), so `set_networkmanager_managed` shells out to
`nmcli` as a narrowly-scoped, best-effort control-plane call — not packet
parsing, and not a third-party library. It's a no-op (returns False) on any
system without `nmcli` on PATH, e.g. systemd-networkd/plain-wpa_supplicant
setups, or when NetworkManager isn't managing the interface at all.

Known remaining limitation: on a machine running a standalone system-wide
`wpa_supplicant.service` *alongside* NetworkManager (seen on this project's
own Kali dev box — common on pentesting-oriented setups that keep it enabled
for other WiFi tooling), that second daemon can independently reassociate
the interface even after NetworkManager has released it, reverting the mode
switch the same way. Fixing that would mean stopping/restarting a systemd
service around every toggle, which is a meaningfully bigger, riskier
intervention (a crash mid-toggle could leave the service stopped) — left as
a documented limitation rather than handled automatically; a user who hits
this needs to stop that service themselves before enabling monitor mode.
"""

from __future__ import annotations

import fcntl
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Callable

NETLINK_ROUTE = 0
NETLINK_GENERIC = 16

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03

NL80211_CMD_SET_INTERFACE = 6
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_IFTYPE = 5

NL80211_IFTYPE_STATION = 2
NL80211_IFTYPE_MONITOR = 6

IFF_UP = 0x1
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

_NLMSG_HDR = struct.Struct("=IHHII")  # nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid
_GENL_HDR = struct.Struct("=BBH")  # cmd, version, reserved
_ATTR_HDR = struct.Struct("=HH")  # nla_len, nla_type

_family_id_cache: dict[str, int] = {}


class NetlinkError(Exception):
    """Raised when the kernel NACKs a netlink request."""


class WifiMonitorModeError(Exception):
    """Raised when switching WiFi monitor mode fails for any reason."""


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _encode_attr(attr_type: int, payload: bytes) -> bytes:
    header = _ATTR_HDR.pack(_ATTR_HDR.size + len(payload), attr_type)
    body = header + payload
    return body + b"\x00" * (_align4(len(body)) - len(body))


def _decode_attrs(data: bytes) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + _ATTR_HDR.size <= len(data):
        nla_len, nla_type = _ATTR_HDR.unpack_from(data, offset)
        if nla_len < _ATTR_HDR.size:
            break
        payload = data[offset + _ATTR_HDR.size : offset + nla_len]
        attrs[nla_type & 0x3FFF] = payload
        offset += _align4(nla_len)
    return attrs


def _encode_nlmsg(msg_type: int, flags: int, seq: int, payload: bytes, pid: int = 0) -> bytes:
    total_len = _NLMSG_HDR.size + len(payload)
    return _NLMSG_HDR.pack(total_len, msg_type, flags, seq, pid) + payload


class NetlinkSocket:
    """Thin wrapper around an AF_NETLINK/NETLINK_GENERIC socket.

    `sock_factory` can be injected in tests to avoid opening a real netlink
    socket (which needs CAP_NET_ADMIN and doesn't exist in most sandboxes).
    """

    def __init__(self, sock_factory: Callable[[], object] | None = None):
        if sock_factory is not None:
            self._sock = sock_factory()
        else:
            self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
            self._sock.bind((0, 0))
        self._seq = 0

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def request(self, msg_type: int, cmd: int, attrs: dict[int, bytes], *, version: int = 0) -> bytes:
        """Send a generic-netlink request and return the response's genl payload bytes."""
        self._seq += 1
        seq = self._seq
        attr_bytes = b"".join(_encode_attr(t, v) for t, v in attrs.items())
        genl_payload = _GENL_HDR.pack(cmd, version, 0) + attr_bytes
        message = _encode_nlmsg(msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, genl_payload)
        self._sock.send(message)
        return self._read_response(seq)

    def _read_response(self, expected_seq: int) -> bytes:
        data = self._sock.recv(65536)
        offset = 0
        while offset + _NLMSG_HDR.size <= len(data):
            nlmsg_len, nlmsg_type, _flags, nlmsg_seq, _pid = _NLMSG_HDR.unpack_from(data, offset)
            if nlmsg_len < _NLMSG_HDR.size:
                break
            body = data[offset + _NLMSG_HDR.size : offset + nlmsg_len]
            offset += _align4(nlmsg_len)
            if nlmsg_seq != expected_seq:
                continue
            if nlmsg_type == NLMSG_ERROR:
                (errno,) = struct.unpack_from("=i", body, 0)
                if errno != 0:
                    raise NetlinkError(f"netlink request failed: errno={-errno}")
                return b""
            if nlmsg_type == NLMSG_DONE:
                return b""
            return body[_GENL_HDR.size :]
        return b""


def resolve_family_id(sock: NetlinkSocket, family_name: str = "nl80211") -> int:
    cached = _family_id_cache.get(family_name)
    if cached is not None:
        return cached
    name_bytes = family_name.encode("ascii") + b"\x00"
    response = sock.request(
        GENL_ID_CTRL,
        CTRL_CMD_GETFAMILY,
        {CTRL_ATTR_FAMILY_NAME: name_bytes},
    )
    attrs = _decode_attrs(response)
    raw = attrs.get(CTRL_ATTR_FAMILY_ID)
    if not raw or len(raw) < 2:
        raise NetlinkError(f"could not resolve netlink family '{family_name}'")
    family_id = struct.unpack_from("=H", raw, 0)[0]
    _family_id_cache[family_name] = family_id
    return family_id


def set_interface_type(sock: NetlinkSocket, family_id: int, ifindex: int, iftype: int) -> None:
    sock.request(
        family_id,
        NL80211_CMD_SET_INTERFACE,
        {
            NL80211_ATTR_IFINDEX: struct.pack("=I", ifindex),
            NL80211_ATTR_IFTYPE: struct.pack("=I", iftype),
        },
    )


def set_interface_up(interface: str, up: bool) -> None:
    ifname = interface.encode("ascii")[:15]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifreq = struct.pack("16sH", ifname, 0) + b"\x00" * 14
        try:
            result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
        except OSError as exc:
            raise WifiMonitorModeError(f"could not read interface flags for {interface}: {exc}") from exc
        flags = struct.unpack("16sH", result[:18])[1]
        if up:
            flags |= IFF_UP
        else:
            flags &= ~IFF_UP
        ifreq = struct.pack("16sH", ifname, flags) + b"\x00" * 14
        try:
            fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)
        except OSError as exc:
            raise WifiMonitorModeError(f"could not set interface flags for {interface}: {exc}") from exc


def set_networkmanager_managed(interface: str, managed: bool) -> bool:
    """Best-effort: tell NetworkManager to (not) manage `interface`.

    Confirmed live during QA: switching a NetworkManager-managed interface to
    monitor mode via nl80211 alone "worked" for a few seconds, but bringing
    the interface back up (required so it can actually receive frames) made
    NetworkManager notice it, reassociate to the saved connection profile,
    and silently flip the type back to managed — defeating the toggle
    entirely with no error surfaced anywhere. Releasing the device from NM's
    management before the mode switch (and handing it back afterward, so
    normal connectivity resumes automatically) is the standard fix, used by
    tools like airmon-ng.

    Returns True if the `nmcli` call ran and succeeded; False if `nmcli`
    isn't on PATH or the call failed — always safe to ignore the return
    value, since plenty of systems (systemd-networkd, plain wpa_supplicant,
    or an interface NetworkManager was never managing) don't need this at
    all and the netlink mode switch still applies either way.
    """
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return False
    try:
        result = subprocess.run(
            [nmcli, "device", "set", interface, "managed", "yes" if managed else "no"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_wireless_interface(interface: str) -> bool:
    if not interface:
        return False
    try:
        return Path(f"/sys/class/net/{interface}/wireless").exists()
    except Exception:
        return False


def set_monitor_mode(interface: str, *, enabled: bool) -> None:
    """Switch `interface` into monitor mode (or back to managed/station mode)."""
    if not interface:
        raise WifiMonitorModeError("no interface specified")
    if not is_wireless_interface(interface):
        raise WifiMonitorModeError(f"{interface} is not a wireless interface")

    try:
        ifindex = socket.if_nametoindex(interface)
    except OSError as exc:
        raise WifiMonitorModeError(f"unknown interface {interface}: {exc}") from exc

    if enabled:
        # Release the device from NetworkManager *before* touching it, so it
        # doesn't reassociate and silently revert the mode switch once the
        # interface comes back up below.
        if set_networkmanager_managed(interface, False):
            time.sleep(0.3)  # give NM a moment to actually let go

    set_interface_up(interface, False)

    sock = None
    try:
        try:
            sock = NetlinkSocket()
        except PermissionError as exc:
            raise WifiMonitorModeError(
                f"insufficient privileges to open a netlink socket (need root/CAP_NET_ADMIN): {exc}"
            ) from exc
        except OSError as exc:
            raise WifiMonitorModeError(f"could not open netlink socket: {exc}") from exc

        try:
            family_id = resolve_family_id(sock)
            iftype = NL80211_IFTYPE_MONITOR if enabled else NL80211_IFTYPE_STATION
            set_interface_type(sock, family_id, ifindex, iftype)
        except NetlinkError as exc:
            raise WifiMonitorModeError(f"nl80211 SET_INTERFACE failed on {interface}: {exc}") from exc
        except PermissionError as exc:
            raise WifiMonitorModeError(
                f"insufficient privileges to change wiphy interface type (need root/CAP_NET_ADMIN): {exc}"
            ) from exc
    finally:
        if sock is not None:
            sock.close()

    set_interface_up(interface, True)

    if not enabled:
        # Hand the device back so NetworkManager resumes normal operation —
        # it will auto-reconnect using its saved profile, same as before the
        # interface was ever touched.
        set_networkmanager_managed(interface, True)
