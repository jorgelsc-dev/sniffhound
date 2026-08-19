from __future__ import annotations

import errno
import os
import shlex
import socket
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
import webbrowser
from dataclasses import dataclass
from pathlib import Path

from .ipc import generate_ipc_token
from .process_control import request_process_shutdown, reset_process_shutdown_request
from .settings import DB_PATH, HOST, PORT, resolve_ipc_socket, resolve_ipc_token

try:
    import readline
except ImportError:  # pragma: no cover - platform dependent
    readline = None

try:
    import termios
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None


@dataclass(frozen=True)
class ConsoleCommandSpec:
    command: str
    help_text: str
    aliases: tuple[str, ...] = ()
    completions: tuple[str, ...] = ()


CONSOLE_COMMAND_SPECS = (
    ConsoleCommandSpec("/help", "Show this help"),
    ConsoleCommandSpec(
        "/status",
        "Show runtime and WebSocket status",
        aliases=("/stats",),
    ),
    ConsoleCommandSpec(
        "/mode",
        "Switch mode: sniffer | honeypot",
        completions=("sniffer", "honeypot"),
    ),
    ConsoleCommandSpec("/start", "Start the active engine", aliases=("/run",)),
    ConsoleCommandSpec("/stop", "Stop the active engine"),
    ConsoleCommandSpec("/token", "Show the current security code"),
    ConsoleCommandSpec("/url", "Show the current dashboard URL"),
    ConsoleCommandSpec("/clients", "List connected WebSocket clients"),
    ConsoleCommandSpec("/broadcast", "Broadcast an operator note", aliases=("/say",)),
    ConsoleCommandSpec("/open", "Open the dashboard in the browser"),
    ConsoleCommandSpec("/quit", "Stop SniffHound", aliases=("/exit",)),
)

CONSOLE_COMMAND_ALIASES = {
    alias: spec.command
    for spec in CONSOLE_COMMAND_SPECS
    for alias in spec.aliases
}
CONSOLE_COMPLETION_TOKENS = tuple(
    sorted({spec.command for spec in CONSOLE_COMMAND_SPECS} | set(CONSOLE_COMMAND_ALIASES))
)

BANNER_INNER_WIDTH = 64


def _display_width(value: str) -> int:
    width = 0
    for char in str(value or ""):
        if char in "\r\n":
            continue
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return width


def _trim_to_display_width(value: str, max_width: int) -> str:
    chars: list[str] = []
    width = 0
    for char in str(value or ""):
        if char in "\r\n":
            continue
        char_width = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
        if width + char_width > max_width:
            break
        chars.append(char)
        width += char_width
    return "".join(chars)


def _fit_banner_text(value: str = "", *, align: str = "left") -> str:
    text = _trim_to_display_width(value, BANNER_INNER_WIDTH)
    padding = max(0, BANNER_INNER_WIDTH - _display_width(text))
    if align == "center":
        left = padding // 2
        right = padding - left
        return f"{' ' * left}{text}{' ' * right}"
    if align == "right":
        return f"{' ' * padding}{text}"
    return f"{text}{' ' * padding}"


def _banner_rule(left: str, fill: str, right: str) -> str:
    return f"{left}{fill * BANNER_INNER_WIDTH}{right}"


def _banner_line(value: str = "", *, align: str = "left") -> str:
    return f"║{_fit_banner_text(value, align=align)}║"


def _snapshot_tty_attrs():
    """Save the controlling terminal's current line-discipline settings,
    if any."""
    if termios is None or not sys.stdin.isatty():
        return None
    try:
        return termios.tcgetattr(sys.stdin.fileno())
    except termios.error:
        return None


def _restore_tty_attrs(attrs) -> None:
    """Undo whatever `sudo`'s authentication prompt for the capture child
    did to the shared controlling terminal. A password or fingerprint-
    reader (PAM) prompt commonly switches the tty to raw mode - notably
    without ONLCR, so a bare "\\n" stops returning the cursor to column 0
    and every subsequent printed line drifts further right than the last,
    staircasing the startup banner. `sudo` keeps the same controlling
    terminal as this process even though the capture child's stdout/
    stderr are redirected to a log file (redirection only affects those
    fds, not tty line discipline), so it has to be put back explicitly
    before printing anything of our own."""
    if termios is None or attrs is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, attrs)
    except termios.error:
        pass


def _print_startup_banner(host: str, port: int):
    """Print the startup banner with the active security code."""
    from .auth import REQUIRE_AUTH, get_security_code
    from . import __version__

    token = get_security_code()
    base_url = f"http://{host}:{port}"
    lines = [
        _banner_rule("╔", "═", "╗"),
        _banner_line(f"🐕 SNIFFHOUND v{__version__}", align="center"),
        _banner_rule("╠", "═", "╣"),
        _banner_line(),
        _banner_line("  Starting server"),
        _banner_line(f"  Link: {base_url}/"),
        _banner_line(f"  Auth Required: {'YES' if REQUIRE_AUTH else 'NO'}"),
        _banner_line(),
        _banner_line("  SECURITY CODE (required to unlock the frontend):"),
        _banner_line(),
        _banner_line(f"    {token}"),
        _banner_line(),
        _banner_line("  Copy the code above and paste it in the auth prompt"),
        _banner_line(),
        _banner_rule("╠", "═", "╣"),
        _banner_line("  Press Ctrl+C to stop"),
        _banner_rule("╚", "═", "╝"),
    ]
    print("\n" + "\n".join(lines))


def _candidate_ports(preferred_port: int) -> tuple[int, ...]:
    """Try the requested port first, then scan the rest of its 10-port block."""
    block_start = max(1, (preferred_port // 10) * 10)
    block_end = min(65535, block_start + 9)
    candidates = [preferred_port]
    candidates.extend(port for port in range(block_start, block_end + 1) if port != preferred_port)
    return tuple(candidates)


def _port_is_available(host: str, port: int) -> bool:
    """Return False when the target TCP address is already in use."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def _select_listen_port(host: str, preferred_port: int) -> int | None:
    """Pick the first free port from the preferred port and its nearby fallback block."""
    for candidate in _candidate_ports(preferred_port):
        if _port_is_available(host, candidate):
            return candidate
    return None


def _print_port_fallback_notice(preferred_port: int, selected_port: int) -> None:
    """Explain when SniffHound switches to a nearby free port."""
    print(
        f"\n[i] Port {preferred_port} is busy. Using {selected_port} instead.\n",
        file=sys.stderr,
    )


def _print_address_in_use_error(host: str, preferred_port: int) -> None:
    """Print a clean error when no port is free in the fallback scan range."""
    block_start = max(1, (preferred_port // 10) * 10)
    block_end = min(65535, block_start + 9)
    print(
        f"\n[!] Cannot start SniffHound: no free port available on {host} in {block_start}-{block_end}.",
        file=sys.stderr,
    )
    print(
        "    Stop the existing process or set SNIFFHOUND_HOST/SNIFFHOUND_PORT to another value.\n",
        file=sys.stderr,
    )


def _resolve_db_path() -> Path:
    path = Path(DB_PATH)
    return path if path.is_absolute() else Path.cwd() / path


def _print_db_permission_error(exc: sqlite3.OperationalError) -> None:
    """SniffHound's web process (this one) never runs as root - it opens
    the SQLite database as the invoking user. A "readonly database" error
    here almost always means the db file (or its -wal/-shm siblings) is
    left over from a run under `sudo`, so this process can no longer write
    to it."""
    db_path = _resolve_db_path()
    print(f"\n[!] Cannot open the SniffHound database: {exc}", file=sys.stderr)
    print(f"    Path: {db_path}", file=sys.stderr)
    print(
        "    This usually means the database was previously created by a "
        "privileged (root/sudo) run and this unprivileged process can't write "
        "to it anymore.",
        file=sys.stderr,
    )
    print(
        f"    Fix: sudo chown \"$(id -un):$(id -gn)\" {db_path} {db_path}-wal {db_path}-shm 2>/dev/null\n"
        "    (or delete those files to let SniffHound recreate them, or point "
        "SNIFFHOUND_DB_PATH at a location you own).\n",
        file=sys.stderr,
    )


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _print_root_invocation_error() -> None:
    """Refusing to ever start this process as root is what makes the
    permission error in _print_db_permission_error() unable to recur: as
    long as SniffHound.db is only ever created by an unprivileged run, no
    future unprivileged run can find it root-owned and unwritable."""
    print("\n[!] Do not run this with `sudo` / as root.", file=sys.stderr)
    print(
        "    The web server and database are meant to run as your normal user - "
        "it spawns the privileged capture child itself (via sudo) when it needs "
        "raw-socket access. Running the whole process as root instead leaves "
        "SniffHound.db owned by root, which then breaks every later "
        "unprivileged run with 'attempt to write a readonly database'.",
        file=sys.stderr,
    )
    print("    Run it as yourself instead, without sudo.\n", file=sys.stderr)


# Policy: capture (raw-socket sniffing, honeypot low-port binds, WiFi
# monitor mode) always requires root — a demo/no-capture mode that silently
# runs unprivileged is more confusing than useful, and there is no env var
# to bypass this. This process (the web server) never elevates itself
# anymore; it spawns `sniffhound-capture` as a privileged child and talks
# to it over the local IPC socket (see sniffhound/ipc.py,
# sniffhound/capture_service.py). If elevation of the child fails, this
# process refuses to start rather than silently serving without capture.


def _build_capture_relaunch_command(ipc_socket: str, ipc_token: str, owner_uid: int) -> list[str]:
    command = ["sudo", "env"]
    for key in sorted(os.environ):
        if key.startswith("SNIFFHOUND_"):
            command.append(f"{key}={os.environ[key]}")
    # The Debian package doesn't install `sniffhound` into system
    # site-packages - it's only importable via PYTHONPATH pointing at the
    # vendored copy under /usr/lib/sniffhound/vendor (see
    # scripts/deb_wrapper.sh). `sudo env ...` does not inherit our
    # PYTHONPATH on its own (sudo resets the environment by default), so it
    # has to be forwarded explicitly or the privileged child can't import
    # the package at all.
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        command.append(f"PYTHONPATH={pythonpath}")
    command.append(f"SNIFFHOUND_IPC_SOCKET={ipc_socket}")
    command.append(f"SNIFFHOUND_IPC_TOKEN={ipc_token}")
    command.append(f"SNIFFHOUND_IPC_OWNER_UID={owner_uid}")
    command.extend([sys.executable, "-m", "sniffhound.capture_service"])
    return command


def _print_capture_elevation_error() -> None:
    print("[!] The capture process requires root/administrator privileges and will not start without them.", file=sys.stderr)
    print("    Raw-socket packet capture is not possible as a regular user.", file=sys.stderr)
    print("    Install sudo, or run `sniffhound-capture` yourself as root and point this process at it", file=sys.stderr)
    print("    with SNIFFHOUND_IPC_SOCKET / SNIFFHOUND_IPC_TOKEN.", file=sys.stderr)


def _capture_log_path(ipc_socket: str) -> Path:
    return Path(ipc_socket).with_suffix(".log")


def _open_capture_log(ipc_socket: str):
    log_path = _capture_log_path(ipc_socket)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return open(log_path, "ab", buffering=0)
    except OSError:
        return None


def _spawn_capture_child(ipc_socket: str, ipc_token: str):
    if shutil.which("sudo") is None:
        _print_capture_elevation_error()
        return None
    command = _build_capture_relaunch_command(ipc_socket, ipc_token, os.getuid())

    # The capture child (and the `sudo`/PAM prompt in front of it) must not
    # inherit this process's stdout/stderr: both processes would then write
    # to the same terminal concurrently and, since each does its own
    # line-buffered flushing, their output interleaves unpredictably -
    # producing exactly the garbled/staircased banner this fixes. `sudo`
    # still shows its password/fingerprint prompt fine either way, since it
    # talks to /dev/tty directly rather than through stdout/stderr.
    log_file = _open_capture_log(ipc_socket)
    try:
        process = subprocess.Popen(
            command,
            stdout=log_file if log_file is not None else subprocess.DEVNULL,
            stderr=log_file if log_file is not None else subprocess.DEVNULL,
        )
    except OSError as exc:
        print(f"[!] Unable to launch the capture process: {exc}", file=sys.stderr)
        return None
    finally:
        if log_file is not None:
            log_file.close()

    if log_file is not None:
        print(f"[i] Capture process output is logged to {_capture_log_path(ipc_socket)}", file=sys.stderr)
    return process


def _wait_for_process(process, timeout: float) -> bool:
    """`Popen.wait()`, but a KeyboardInterrupt while waiting (the user
    getting impatient - e.g. `sudo` is still blocked on a fingerprint/
    password prompt for the capture child) is treated as "not done yet"
    instead of propagating and aborting the rest of shutdown."""
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False
    except KeyboardInterrupt:
        print(
            "\n[i] Still stopping the capture process (it may be waiting on a "
            "sudo prompt) - hang on...",
            file=sys.stderr,
        )
        return False


def _stop_capture_child(process, *, timeout: float = 5.0) -> None:
    if process is None or process.poll() is not None:
        return
    print("[i] Stopping the capture process...", file=sys.stderr)
    try:
        process.terminate()
    except Exception:
        pass

    if _wait_for_process(process, timeout):
        return

    # Graceful shutdown didn't finish in time (or got interrupted again) -
    # SIGKILL is unblockable, so this is guaranteed to actually end the
    # privileged child rather than leaving it orphaned.
    try:
        process.kill()
    except Exception:
        pass
    _wait_for_process(process, 2.0)


def _print_console_help() -> None:
    lines = ["[console] Commands:"]
    for spec in CONSOLE_COMMAND_SPECS:
        label = spec.command
        if spec.completions:
            label = f"{label} <value>"
        elif spec.command == "/broadcast":
            label = f"{label} <text>"
        lines.append(f"  {label:<22}{spec.help_text}")
        if spec.aliases:
            lines.append(f"  {'aliases:':<22}{', '.join(spec.aliases)}")
    lines.append("  <text>                Save and broadcast an operator note")
    print("\n".join(lines))


def _resolve_console_command(command: str) -> str:
    normalized = str(command or "").strip().lower()
    return CONSOLE_COMMAND_ALIASES.get(normalized, normalized)


def _build_console_completion_candidates(buffer: str, text: str, begidx: int) -> list[str]:
    current = str(text or "").strip().lower()
    if begidx == 0:
        if current and not current.startswith("/"):
            return []
        return [token for token in CONSOLE_COMPLETION_TOKENS if token.startswith(current)]

    tokens = str(buffer[:begidx] or "").split()
    if not tokens:
        return []

    command = _resolve_console_command(tokens[0])
    if command == "/mode":
        return [item for item in ("sniffer", "honeypot") if item.startswith(current)]
    if command == "/help":
        return [token for token in CONSOLE_COMPLETION_TOKENS if token.startswith(current)]
    return []


def _console_readline_completer(text: str, state: int) -> str | None:
    if readline is None:
        return None
    buffer = readline.get_line_buffer()
    matches = _build_console_completion_candidates(buffer, text, readline.get_begidx())
    if state < len(matches):
        return matches[state]
    return None


def _configure_console_autocomplete() -> bool:
    if readline is None:
        return False
    try:
        bind_command = "bind ^I rl_complete" if "libedit" in str(readline.__doc__ or "").lower() else "tab: complete"
        readline.parse_and_bind(bind_command)
        readline.set_completer_delims(" \t\n")
        readline.set_completer(_console_readline_completer)
        return True
    except Exception:
        return False


def _format_runtime_status(runtime, client_count: int) -> str:
    snapshot = runtime.snapshot()
    mode = str(snapshot.get("mode") or "sniffer")
    active = snapshot.get("active") or {}
    running = "yes" if active.get("running") else "no"
    packets = active.get("packets_seen") or active.get("packets") or 0
    return (
        f"[status] mode={mode} running={running} "
        f"packets={packets} ws_clients={client_count}"
    )


def _handle_console_line(
    raw_line: str,
    *,
    host: str,
    port: int,
    runtime,
    hub,
    append_chat_message,
) -> None:
    line = str(raw_line or "").strip()
    if not line:
        return

    if not line.startswith("/"):
        message = append_chat_message(
            line,
            author="operator",
            kind="cli",
            meta={"source": "terminal"},
            broadcast=True,
        )
        if message.get("content"):
            print(f"[note] {message['content']}")
        return

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        print(f"[console] Invalid command: {exc}")
        return
    if not parts:
        return

    command = _resolve_console_command(parts[0])
    args = parts[1:]

    if command == "/help":
        _print_console_help()
        return

    if command == "/status":
        print(_format_runtime_status(runtime, len(hub.list_clients())))
        return

    if command == "/mode":
        target_mode = str(args[0] if args else "").strip().lower()
        if target_mode not in {"sniffer", "honeypot"}:
            print("[console] Usage: /mode sniffer|honeypot")
            return
        snapshot = runtime.set_mode(target_mode)
        print(f"[console] Runtime mode set to {snapshot.get('mode')}")
        return

    if command == "/start":
        snapshot = runtime.start()
        active = snapshot.get("active") or {}
        print(f"[console] Active engine started (running={bool(active.get('running'))})")
        return

    if command == "/stop":
        snapshot = runtime.stop()
        active = snapshot.get("active") or {}
        print(f"[console] Active engine stopped (running={bool(active.get('running'))})")
        return

    if command == "/token":
        from .auth import get_security_code

        print(f"[console] Security code: {get_security_code()}")
        return

    if command == "/url":
        print(f"[console] Dashboard: http://{host}:{port}/")
        return

    if command == "/clients":
        clients = hub.list_clients()
        if not clients:
            print("[console] No WebSocket clients connected.")
            return
        print(f"[console] WebSocket clients: {len(clients)}")
        for client in clients:
            print(
                f"  - id={client.get('id')} addr={client.get('addr')} "
                f"connected_at={client.get('connected_at')}"
            )
        return

    if command == "/broadcast":
        message_text = " ".join(args).strip()
        if not message_text:
            print("[console] Usage: /broadcast <text>")
            return
        message = append_chat_message(
            message_text,
            author="operator",
            kind="broadcast",
            meta={"source": "terminal"},
            broadcast=True,
        )
        print(f"[console] Broadcast sent: {message.get('content')}")
        return

    if command == "/open":
        url = f"http://{host}:{port}/"
        opened = webbrowser.open(url)
        print(f"[console] Browser {'opened' if opened else 'not opened'}: {url}")
        return

    if command == "/quit":
        if request_process_shutdown():
            print("[console] Stopping SniffHound...")
        else:
            print("[console] Shutdown already in progress.")
        return

    print(f"[console] Unknown command: {command}. Type /help.")


def _start_interactive_console(
    *,
    host: str,
    port: int,
    runtime,
    hub,
    append_chat_message,
) -> threading.Thread | None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None

    def _console_loop():
        autocomplete_ready = _configure_console_autocomplete()
        hint = " Press Tab to autocomplete commands." if autocomplete_ready else ""
        print(f"[console] Interactive shell ready. Type /help.{hint} Plain text becomes an operator note.")
        while True:
            try:
                line = input("sniffhound> ")
            except (EOFError, OSError, ValueError):
                break
            except KeyboardInterrupt:
                print()
                request_process_shutdown()
                break
            _handle_console_line(
                line,
                host=host,
                port=port,
                runtime=runtime,
                hub=hub,
                append_chat_message=append_chat_message,
            )

    thread = threading.Thread(
        target=_console_loop,
        name="sniffhound-console",
        daemon=True,
    )
    thread.start()
    return thread


def _stop_interactive_console(
    thread: threading.Thread | None,
    *,
    input_stream=None,
    join_timeout: float = 1.0,
) -> None:
    if thread is None:
        return
    stream = sys.stdin if input_stream is None else input_stream
    try:
        if stream is not None and not getattr(stream, "closed", False):
            stream.close()
    except Exception:
        pass
    if thread.is_alive():
        try:
            thread.join(timeout=join_timeout)
        except KeyboardInterrupt:
            pass


def main():
    """Combined single-command entry point (`sniffhound`). Runs the web
    server + database as the invoking (unprivileged) user, and spawns a
    privileged `sniffhound-capture` child over local IPC for raw-socket
    access. Only the capture child ever needs root - see CLAUDE.md."""
    if _running_as_root():
        _print_root_invocation_error()
        return 1
    reset_process_shutdown_request()
    tty_attrs = _snapshot_tty_attrs()
    host = str(HOST)
    requested_port = int(PORT)
    selected_port = _select_listen_port(host, requested_port)
    console_thread = None
    capture_process = None

    if selected_port is None:
        _print_address_in_use_error(host, requested_port)
        return 1

    ipc_socket = resolve_ipc_socket(selected_port)
    ipc_token = resolve_ipc_token() or generate_ipc_token()
    os.environ["SNIFFHOUND_IPC_SOCKET"] = ipc_socket
    os.environ["SNIFFHOUND_IPC_TOKEN"] = ipc_token

    # Import (and so construct sniffhound.app's SniffStore, as this
    # unprivileged user) *before* spawning the privileged capture child.
    # Both processes open the same SQLite file; whichever one creates it
    # first owns it on disk, and a root-owned DB file/WAL is unwritable by
    # this process afterwards. Importing first guarantees the web process
    # wins that race regardless of how fast the capture child starts.
    try:
        from .app import app, append_chat_message, bootstrap_capture, connect_capture_service, hub, runtime, shutdown_capture
    except sqlite3.OperationalError as exc:
        _print_db_permission_error(exc)
        return 1

    capture_process = _spawn_capture_child(ipc_socket, ipc_token)
    if capture_process is None:
        return 1

    try:
        time.sleep(0.2)
        if capture_process.poll() is not None:
            print(f"[!] Capture process exited immediately (code {capture_process.returncode}).", file=sys.stderr)
            return 1
        if not connect_capture_service():
            print("[!] SniffHound cannot start without the capture process. See the error above.", file=sys.stderr)
            return 1

        # sudo's password/fingerprint prompt for the capture child we just
        # waited on can leave the shared controlling terminal in raw mode
        # (see _restore_tty_attrs) - put it back before printing anything.
        _restore_tty_attrs(tty_attrs)

        if selected_port != requested_port:
            _print_port_fallback_notice(requested_port, selected_port)
        _print_startup_banner(host, selected_port)
        console_thread = _start_interactive_console(
            host=host,
            port=selected_port,
            runtime=runtime,
            hub=hub,
            append_chat_message=append_chat_message,
        )
        bootstrap_capture()
        app.run(host, selected_port)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            _print_address_in_use_error(host, requested_port)
            return 1
        raise
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down gracefully...\n")
    finally:
        _stop_interactive_console(console_thread)
        shutdown_capture()
        _stop_capture_child(capture_process)
        reset_process_shutdown_request()
    return 0


def main_web():
    """Standalone entry point for the unprivileged web process
    (`sniffhound-web`). Never elevates privileges and never spawns a
    capture child - expects SNIFFHOUND_IPC_SOCKET/SNIFFHOUND_IPC_TOKEN to
    already point at a `sniffhound-capture` process started separately
    (its own systemd unit, a different user, a different host, ...)."""
    if _running_as_root():
        _print_root_invocation_error()
        return 1
    reset_process_shutdown_request()
    host = str(HOST)
    requested_port = int(PORT)
    selected_port = _select_listen_port(host, requested_port)
    console_thread = None

    if selected_port is None:
        _print_address_in_use_error(host, requested_port)
        return 1

    try:
        from .app import app, append_chat_message, bootstrap_capture, connect_capture_service, hub, runtime, shutdown_capture
    except sqlite3.OperationalError as exc:
        _print_db_permission_error(exc)
        return 1

    try:
        if not connect_capture_service():
            print("[!] sniffhound-web cannot start without a reachable capture process.", file=sys.stderr)
            return 1

        if selected_port != requested_port:
            _print_port_fallback_notice(requested_port, selected_port)
        _print_startup_banner(host, selected_port)
        console_thread = _start_interactive_console(
            host=host,
            port=selected_port,
            runtime=runtime,
            hub=hub,
            append_chat_message=append_chat_message,
        )
        bootstrap_capture()
        app.run(host, selected_port)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            _print_address_in_use_error(host, requested_port)
            return 1
        raise
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down gracefully...\n")
    finally:
        _stop_interactive_console(console_thread)
        shutdown_capture()
        reset_process_shutdown_request()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
