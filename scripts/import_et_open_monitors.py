#!/usr/bin/env python3
"""One-off/repeatable importer: converts a subset of the Emerging Threats
Open Suricata ruleset (https://rules.emergingthreats.net/open/, Proofpoint)
into SniffHound builtin monitors and writes sniffhound/data/default_monitors.json.

SniffHound's monitor schema (sniffhound/monitors.py, sniffhound/rulesets.py)
is intentionally much simpler than Suricata's: one flat match dict per
monitor (protocols/ports/payload_contains/payload_regex/lengths), evaluated
against a single lower-cased text blob built from the packet's summary,
decoded payload text, and addresses (see rulesets.build_packet_text) - there
is no flow state, no per-buffer matching (http.uri/dns.query/tls.sni are all
the same flat blob here), and payload_contains entries are OR'd together
(not AND'd like Suricata's multiple `content` keywords). This script adapts
rules to that simpler model rather than attempting a lossless conversion:

- proto: only mapped when SniffHound's own parser tags packets with the same
  value (tcp/udp/icmp/modbus/dnp3/snmp/tftp/mqtt/...); app-layer-named
  Suricata protocols (http/tls/dns/ftp/ssh/...) are left unconstrained here
  so a protocol-name mismatch never causes a false negative - the extracted
  content/regex still carries the actual signal.
- ports: only a single literal numeric port (from either side of the rule)
  is kept; $HOME_NET/$EXTERNAL_NET/$HTTP_PORTS-style variables and ranges
  are dropped rather than guessed.
- content: hex-escaped `|4A 4B|`-style bytes are decoded and kept only if
  the result is printable ASCII (byte-exact/binary matching isn't possible
  against a decoded text blob). When a rule has several `content` keywords
  (normally AND'd in Suricata), only the single longest/most distinctive
  one is kept as payload_contains, to avoid turning an AND of specific
  literals into an OR of generic substrings (e.g. bare "UPDATE"/"SET").
- pcre: kept as payload_regex only if it still compiles under Python's `re`
  after stripping Suricata-only pcre flags/modifiers; dropped otherwise.
- severity: taken from the rule's `metadata: ... signature_severity <X>`
  when present (Critical/Major/Minor/Informational -> critical/high/
  medium/info), falling back to a small classtype table.
- selection: every rule that survives conversion with at least one usable
  criterion is scored (severity + classtype value) and the top N are kept,
  with a per-classtype cap so a handful of extremely repetitive categories
  (single-IOC "domain-c2" DNS rules number in the thousands) can't crowd
  out everything else.

Usage:
    python scripts/import_et_open_monitors.py \\
        --rules-file /path/to/emerging-all.rules \\
        --target-total 1000

The 46MB ruleset itself is not vendored in this repo - download it from
https://rules.emergingthreats.net/open/suricata-<version>/emerging-all.rules
before running this script. Re-running is safe and idempotent: it always
regenerates sniffhound/data/default_monitors.json from the existing
DEFAULT_MONITORS in sniffhound/monitors.py plus a freshly re-selected ET
Open slice - it does not read or merge the previous JSON output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from sniffhound.monitors import DEFAULT_MONITORS, normalize_monitor  # noqa: E402

OUTPUT_PATH = ROOT_DIR / "sniffhound" / "data" / "default_monitors.json"

# Suricata proto token -> SniffHound `packet["proto"]` value. Only protocols
# SniffHound's own parser actually tags packets with are mapped; everything
# else is left unconstrained (see module docstring).
PROTO_MAP = {
    "tcp": "tcp",
    "tcp-pkt": "tcp",
    "tcp-stream": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "modbus": "modbus",
    "dnp3": "dnp3",
    "snmp": "snmp",
    "tftp": "tftp",
    "mqtt": "mqtt",
}

# metadata signature_severity -> SniffHound severity.
SEVERITY_FROM_SIGNATURE = {
    "critical": "critical",
    "major": "high",
    "minor": "medium",
    "informational": "info",
}

# classtype -> SniffHound severity, used when signature_severity metadata is
# absent. Anything not listed here falls back to "medium".
SEVERITY_FROM_CLASSTYPE = {
    "trojan-activity": "critical",
    "command-and-control": "critical",
    "domain-c2": "critical",
    "exploit-kit": "high",
    "shellcode-detect": "critical",
    "attempted-admin": "high",
    "attempted-user": "high",
    "web-application-attack": "high",
    "credential-theft": "high",
    "targeted-activity": "high",
    "attempted-dos": "high",
    "bad-unknown": "medium",
    "social-engineering": "medium",
    "attempted-recon": "medium",
    "pup-activity": "low",
    "policy-violation": "low",
    "misc-activity": "low",
    "web-application-activity": "low",
    "protocol-command-decode": "low",
    "not-suspicious": "info",
    "unknown": "info",
}

# Selection priority per classtype (higher first) and a per-classtype cap so
# a handful of very repetitive categories (thousands of near-identical
# single-domain "domain-c2" DNS lookups) can't crowd out everything else.
CLASSTYPE_WEIGHT = {
    "trojan-activity": (100, 220),
    "command-and-control": (95, 120),
    "web-application-attack": (90, 200),
    "exploit-kit": (85, 80),
    "shellcode-detect": (85, 30),
    "credential-theft": (80, 60),
    "attempted-admin": (75, 60),
    "attempted-user": (70, 60),
    "domain-c2": (65, 150),
    "bad-unknown": (55, 60),
    "targeted-activity": (55, 30),
    "social-engineering": (50, 30),
    "attempted-recon": (45, 30),
    "attempted-dos": (45, 20),
    "protocol-command-decode": (35, 20),
    "pup-activity": (30, 30),
    "misc-activity": (20, 30),
    "web-application-activity": (20, 20),
    "policy-violation": (10, 20),
}
DEFAULT_CLASSTYPE_WEIGHT = (15, 20)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

PAIR_RE = re.compile(r'(\w+)(?::("(?:[^"\\]|\\.)*"|[^;]*))?;')
HEX_TOKEN_RE = re.compile(r"\|([0-9A-Fa-f \t]+)\|")


def _strip_quotes(value: str | None) -> str:
    if value is None:
        return ""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\;", ";").replace("\\\\", "\\")


def _decode_hex_content(raw: str) -> str | None:
    """Decode `content:"...|4A 4B|..."` into plain text, keeping it only if
    the whole result is printable ASCII - our matching runs against decoded
    text, so a binary payload can't be represented as a substring of it."""

    def _replace(match: re.Match) -> str:
        hex_bytes = match.group(1).split()
        try:
            decoded = bytes(int(byte, 16) for byte in hex_bytes)
        except ValueError:
            raise _BinaryContentError from None
        try:
            text = decoded.decode("ascii")
        except UnicodeDecodeError:
            raise _BinaryContentError from None
        if not text.isprintable():
            raise _BinaryContentError
        return text

    try:
        return HEX_TOKEN_RE.sub(_replace, raw)
    except _BinaryContentError:
        return None


class _BinaryContentError(Exception):
    pass


def _parse_pairs(body: str) -> list[tuple[str, str]]:
    return [(key, _strip_quotes(value)) for key, value in PAIR_RE.findall(body)]


def _parse_header(header: str) -> dict | None:
    tokens = header.split()
    if len(tokens) < 7:
        return None
    action, proto, src_ip, src_port, direction, dst_ip, dst_port = tokens[:7]
    return {
        "action": action,
        "proto": proto.lower(),
        "src_port": src_port,
        "dst_port": dst_port,
    }


def _literal_port(*candidates: str) -> int | None:
    for candidate in candidates:
        if re.fullmatch(r"\d+", candidate):
            port = int(candidate)
            if 1 <= port <= 65535:
                return port
    return None


def _best_content(pairs: list[tuple[str, str]]) -> str | None:
    candidates = []
    for key, value in pairs:
        if key != "content" or not value:
            continue
        decoded = _decode_hex_content(value) if "|" in value else value
        if decoded is None:
            continue
        text = decoded.strip()
        if len(text) < 4:
            continue
        candidates.append(text)
    if not candidates:
        return None
    # Longest wins - a longer literal is almost always the more specific,
    # less generic one (a URI path or parameter name vs. a bare SQL/HTML
    # keyword also present in the same rule's other `content` keywords).
    return max(candidates, key=len)


def _best_regex(pairs: list[tuple[str, str]]) -> str | None:
    for key, value in pairs:
        if key != "pcre" or not value:
            continue
        match = re.match(r"^/(.*)/([A-Za-z]*)$", value, re.DOTALL)
        if not match:
            continue
        pattern = match.group(1)
        try:
            re.compile(pattern)
        except re.error:
            continue
        return pattern
    return None


def _severity_for(pairs: list[tuple[str, str]], classtype: str) -> str:
    for key, value in pairs:
        if key != "metadata":
            continue
        found = re.search(r"signature_severity\s+(\w+)", value)
        if found:
            mapped = SEVERITY_FROM_SIGNATURE.get(found.group(1).strip().lower())
            if mapped:
                return mapped
    return SEVERITY_FROM_CLASSTYPE.get(classtype, "medium")


def convert_rule(line: str, index: int) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "(" not in line or not line.endswith(")"):
        return None
    header, _, rest = line.partition("(")
    body = rest[:-1]  # drop trailing ")"
    parsed_header = _parse_header(header.strip())
    if parsed_header is None:
        return None
    pairs = _parse_pairs(body)
    pair_dict_first = {}
    for key, value in pairs:
        pair_dict_first.setdefault(key, value)

    sid = pair_dict_first.get("sid", "").strip()
    msg = pair_dict_first.get("msg", "").strip()
    classtype = pair_dict_first.get("classtype", "").strip().lower()
    if not sid or not msg:
        return None

    content = _best_content(pairs)
    regex = _best_regex(pairs)
    if not content and not regex:
        return None  # no usable literal signal to adapt

    match: dict = {}
    proto_value = PROTO_MAP.get(parsed_header["proto"])
    if proto_value:
        match["protocols"] = [proto_value]
    port = _literal_port(parsed_header["src_port"], parsed_header["dst_port"])
    if port:
        match["ports"] = [port]
    if content:
        match["payload_contains"] = [content]
    if regex:
        match["payload_regex"] = [regex]

    severity = _severity_for(pairs, classtype)
    weight, _cap = CLASSTYPE_WEIGHT.get(classtype, DEFAULT_CLASSTYPE_WEIGHT)
    score = weight * 10 + SEVERITY_RANK.get(severity, 2)

    return {
        "id": f"et-open-{sid}",
        "name": msg[:160],
        "description": f"Adapted from Emerging Threats Open (Proofpoint), sid {sid}, classtype {classtype or 'n/a'}.",
        "enabled": True,
        "priority": 500 + (index % 400),
        "source": "builtin",
        "mode": "regex" if regex and not content else "rule",
        "match": match,
        "action": {
            "tag": f"et-{classtype or 'signature'}",
            "label": msg[:160],
            "severity": severity,
        },
        "_classtype": classtype,
        "_score": score,
    }


def select_monitors(candidates: list[dict], target_total: int, existing_count: int) -> list[dict]:
    budget = max(0, target_total - existing_count)
    seen_signatures: set[tuple] = set()
    deduped: list[dict] = []
    for monitor in candidates:
        match = monitor["match"]
        signature = (
            tuple(match.get("payload_contains", [])),
            tuple(match.get("payload_regex", [])),
            tuple(match.get("protocols", [])),
            tuple(match.get("ports", [])),
        )
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        deduped.append(monitor)

    deduped.sort(key=lambda item: item["_score"], reverse=True)

    per_classtype_count: Counter = Counter()
    selected: list[dict] = []
    for monitor in deduped:
        if len(selected) >= budget:
            break
        classtype = monitor["_classtype"]
        _weight, cap = CLASSTYPE_WEIGHT.get(classtype, DEFAULT_CLASSTYPE_WEIGHT)
        if per_classtype_count[classtype] >= cap:
            continue
        per_classtype_count[classtype] += 1
        selected.append(monitor)

    # Second pass: if the per-classtype caps left the budget unfilled
    # (fewer high-value rules existed than the cap allowed), top up from
    # whatever is left over, ignoring the cap, still ordered by score.
    if len(selected) < budget:
        chosen_ids = {item["id"] for item in selected}
        for monitor in deduped:
            if len(selected) >= budget:
                break
            if monitor["id"] in chosen_ids:
                continue
            selected.append(monitor)

    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules-file", required=True, type=Path, help="Path to a downloaded emerging-all.rules file")
    parser.add_argument("--target-total", type=int, default=1000, help="Total builtin monitor count to reach (existing + imported)")
    args = parser.parse_args()

    if not args.rules_file.exists():
        print(f"Rules file not found: {args.rules_file}", file=sys.stderr)
        return 1

    existing = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
    existing_ids = {item["id"] for item in existing}

    candidates: list[dict] = []
    with args.rules_file.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            converted = convert_rule(line, index)
            if converted is None or converted["id"] in existing_ids:
                continue
            candidates.append(converted)

    print(f"Parsed {len(candidates)} convertible candidate rules out of the ruleset.")

    selected = select_monitors(candidates, args.target_total, len(existing))
    print(f"Selected {len(selected)} monitors to reach a target of {args.target_total} "
          f"(existing builtins: {len(existing)}).")

    classtype_counts = Counter(item["_classtype"] for item in selected)
    for classtype, count in classtype_counts.most_common():
        print(f"  {classtype or '(none)'}: {count}")

    validated: list[dict] = []
    failures = 0
    for monitor in selected:
        monitor.pop("_classtype", None)
        monitor.pop("_score", None)
        try:
            normalize_monitor(monitor, allow_source=True)
        except Exception as exc:  # noqa: BLE001 - we want to skip and count, not crash the import
            failures += 1
            print(f"  SKIP {monitor.get('id')}: {exc}", file=sys.stderr)
            continue
        validated.append(monitor)

    if failures:
        print(f"{failures} generated monitors failed normalize_monitor() validation and were dropped.", file=sys.stderr)

    combined = existing + validated
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(combined, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(combined)} total monitors ({len(existing)} existing + {len(validated)} imported) to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
