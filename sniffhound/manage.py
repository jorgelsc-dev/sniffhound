from __future__ import annotations

import errno
import os
import shlex
import signal
import socket
import shutil
import sys
import threading
import unicodedata
import webbrowser
from dataclasses import dataclass

from .settings import CAPTURE_AUTO_START, CAPTURE_DEMO_MODE, HOST, PORT

try:
    import readline
except ImportError:  # pragma: no cover - platform dependent
    readline = None


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
    ConsoleCommandSpec("/token", "Show the current access token"),
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


def _print_startup_banner(host: str, port: int):
    """Print beautiful startup banner with access token."""
    from .auth import get_session_token, REQUIRE_AUTH
    from . import __version__

    token = get_session_token()
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
        _banner_line("  ACCESS TOKEN (use this to login):"),
        _banner_line(),
        _banner_line(f"    {token}"),
        _banner_line(),
        _banner_line("  Copy the token above and paste it in the login prompt"),
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


def _admin_relaunch_required() -> bool:
    override = os.getenv("SNIFFHOUND_REQUIRE_ADMIN")
    if override is not None:
        return override.strip().lower() in {"1", "true", "yes", "on", "y"}
    return bool(CAPTURE_AUTO_START and not CAPTURE_DEMO_MODE)


def _is_running_as_admin() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        try:
            return int(geteuid()) == 0
        except Exception:
            return False
    return False


def _build_admin_relaunch_command() -> list[str]:
    command = ["sudo", "env"]
    for key in sorted(os.environ):
        if key.startswith("SNIFFHOUND_"):
            command.append(f"{key}={os.environ[key]}")
    command.extend([sys.executable, "-m", "sniffhound.manage", *sys.argv[1:]])
    return command


def _print_admin_required_message() -> None:
    command = shlex.join([sys.executable, "-m", "sniffhound.manage", *sys.argv[1:]])
    print("[!] SniffHound needs administrator privileges for packet capture.", file=sys.stderr)
    print(f"    Re-run with: sudo {command}", file=sys.stderr)


def _ensure_admin_privileges() -> bool:
    if not _admin_relaunch_required() or _is_running_as_admin():
        return True

    if shutil.which("sudo") is None:
        _print_admin_required_message()
        return False

    try:
        os.execvp("sudo", _build_admin_relaunch_command())
    except OSError as exc:
        print(f"[!] Unable to elevate SniffHound automatically: {exc}", file=sys.stderr)
        _print_admin_required_message()
        return False
    return True


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
        from .auth import get_session_token

        print(f"[console] Access token: {get_session_token()}")
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
        print("[console] Stopping SniffHound...")
        os.kill(os.getpid(), signal.SIGINT)
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
                os.kill(os.getpid(), signal.SIGINT)
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
    host = str(HOST)
    requested_port = int(PORT)
    selected_port = _select_listen_port(host, requested_port)
    console_thread = None

    if selected_port is None:
        _print_address_in_use_error(host, requested_port)
        return 1

    if not _ensure_admin_privileges():
        return 1

    from .app import app, append_chat_message, bootstrap_capture, hub, runtime, shutdown_capture

    try:
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
