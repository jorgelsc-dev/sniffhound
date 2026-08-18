from __future__ import annotations

import struct
import unittest
from unittest.mock import MagicMock, patch

from sniffhound import netlink


class _FakeNetlinkSocket:
    """Stands in for a real AF_NETLINK socket (which needs CAP_NET_ADMIN and
    doesn't exist in most CI sandboxes) — returns canned responses keyed off
    what was actually sent, so the encode -> send -> decode round trip is
    exercised without any real kernel interaction."""

    def __init__(self, *, family_id: int = 0x1234, errno: int = 0):
        self.sent: list[bytes] = []
        self._family_id = family_id
        self._errno = errno

    def send(self, data: bytes):
        self.sent.append(data)

    def recv(self, _bufsize: int) -> bytes:
        last = self.sent[-1]
        nlmsg_len, nlmsg_type, flags, seq, pid = netlink._NLMSG_HDR.unpack_from(last, 0)
        if nlmsg_type == netlink.GENL_ID_CTRL:
            attr = netlink._encode_attr(netlink.CTRL_ATTR_FAMILY_ID, struct.pack("=H", self._family_id) + b"\x00\x00")
            genl = netlink._GENL_HDR.pack(0, 1, 0) + attr
            return netlink._encode_nlmsg(nlmsg_type, 0, seq, genl)
        body = struct.pack("=i", -self._errno if self._errno else 0)
        return netlink._encode_nlmsg(netlink.NLMSG_ERROR, 0, seq, body)

    def close(self):
        pass


class TestNetlinkAttrEncoding(unittest.TestCase):
    def test_attr_round_trip(self):
        encoded = netlink._encode_attr(7, b"hello")
        decoded = netlink._decode_attrs(encoded)
        self.assertEqual(decoded[7], b"hello")

    def test_attrs_are_4byte_aligned(self):
        encoded = netlink._encode_attr(1, b"abc")  # 4(header)+3 = 7, padded to 8
        self.assertEqual(len(encoded) % 4, 0)


class TestResolveFamilyId(unittest.TestCase):
    def setUp(self):
        netlink._family_id_cache.clear()

    def test_resolves_and_caches(self):
        fake = _FakeNetlinkSocket(family_id=0x4321)
        sock = netlink.NetlinkSocket(sock_factory=lambda: fake)
        family_id = netlink.resolve_family_id(sock, "nl80211")
        self.assertEqual(family_id, 0x4321)
        self.assertEqual(netlink._family_id_cache["nl80211"], 0x4321)

    def test_uses_cache_without_a_second_request(self):
        netlink._family_id_cache["nl80211"] = 0x9999
        fake = _FakeNetlinkSocket(family_id=0x1111)
        sock = netlink.NetlinkSocket(sock_factory=lambda: fake)
        family_id = netlink.resolve_family_id(sock, "nl80211")
        self.assertEqual(family_id, 0x9999)
        self.assertEqual(fake.sent, [])  # never actually sent a request


class TestSetInterfaceType(unittest.TestCase):
    def test_ack_succeeds(self):
        fake = _FakeNetlinkSocket()
        sock = netlink.NetlinkSocket(sock_factory=lambda: fake)
        netlink.set_interface_type(sock, 0x1234, ifindex=3, iftype=netlink.NL80211_IFTYPE_MONITOR)
        self.assertEqual(len(fake.sent), 1)

    def test_nack_raises_netlink_error(self):
        fake = _FakeNetlinkSocket(errno=1)
        sock = netlink.NetlinkSocket(sock_factory=lambda: fake)
        with self.assertRaises(netlink.NetlinkError):
            netlink.set_interface_type(sock, 0x1234, ifindex=3, iftype=netlink.NL80211_IFTYPE_MONITOR)


class TestSetNetworkManagerManaged(unittest.TestCase):
    """set_networkmanager_managed is the fix for a real bug found in live QA:
    NetworkManager reasserts control of a managed interface and silently
    reverts an externally-set monitor mode within seconds unless it's told
    to release the device first."""

    def test_returns_false_without_nmcli(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(netlink.set_networkmanager_managed("wlan0", False))

    def test_calls_nmcli_with_managed_no(self):
        completed = MagicMock(returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nmcli"), \
             patch("subprocess.run", return_value=completed) as run:
            result = netlink.set_networkmanager_managed("wlan0", False)
        self.assertTrue(result)
        args = run.call_args[0][0]
        self.assertEqual(args, ["/usr/bin/nmcli", "device", "set", "wlan0", "managed", "no"])

    def test_calls_nmcli_with_managed_yes(self):
        completed = MagicMock(returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nmcli"), \
             patch("subprocess.run", return_value=completed) as run:
            netlink.set_networkmanager_managed("wlan0", True)
        args = run.call_args[0][0]
        self.assertEqual(args, ["/usr/bin/nmcli", "device", "set", "wlan0", "managed", "yes"])

    def test_nonzero_returncode_is_false(self):
        completed = MagicMock(returncode=1)
        with patch("shutil.which", return_value="/usr/bin/nmcli"), \
             patch("subprocess.run", return_value=completed):
            self.assertFalse(netlink.set_networkmanager_managed("wlan0", False))

    def test_subprocess_exception_is_false_not_raised(self):
        with patch("shutil.which", return_value="/usr/bin/nmcli"), \
             patch("subprocess.run", side_effect=OSError("boom")):
            self.assertFalse(netlink.set_networkmanager_managed("wlan0", False))


class TestIsWirelessInterface(unittest.TestCase):
    def test_nonexistent_interface_is_false(self):
        self.assertFalse(netlink.is_wireless_interface("definitely-not-a-real-nic-xyz"))

    def test_empty_string_is_false(self):
        self.assertFalse(netlink.is_wireless_interface(""))


if __name__ == "__main__":
    unittest.main()
