#!/usr/bin/env python3
"""One-off/repeatable maintenance: re-checks every already-converted
`et-open-*` monitor in sniffhound/data/default_monitors.json against the
strengthened specificity rules in import_et_open_monitors.py
(content_is_specific_enough / _regex_is_specific_enough) and disables any
that no longer clear the bar.

Why this is a separate script instead of just re-running
import_et_open_monitors.py: that importer converts rules from the original
46MB Emerging Threats Open ruleset file, which isn't vendored in this repo
and isn't available on a machine that only has the already-generated
default_monitors.json. The multi-`content`-AND-condition structure of the
original rules is gone once conversion already flattened it to a single
payload_contains/payload_regex - there's no way to re-derive a *better*
literal from what's left, only to judge whether the one that's there is
still good enough. So this script never edits an existing match, it only
flips `enabled` to False for monitors whose sole content/regex signal is
now recognized as too generic - preserving the historical record (id,
description, original match) exactly as scripts/import_et_open_monitors.py
produced it, same as store._seed_new_builtin_monitors()'s own pruning
philosophy for removed ids.

Usage:
    python scripts/curate_default_monitors.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.import_et_open_monitors import content_is_specific_enough, _regex_is_specific_enough  # noqa: E402

MONITORS_PATH = ROOT_DIR / "sniffhound" / "data" / "default_monitors.json"


def monitor_is_still_specific_enough(monitor: dict) -> bool:
    match = monitor.get("match") if isinstance(monitor.get("match"), dict) else {}
    contents = [str(item) for item in match.get("payload_contains", []) if str(item).strip()]
    regexes = [str(item) for item in match.get("payload_regex", []) if str(item).strip()]
    if not contents and not regexes:
        return True  # scoped by protocol/port/length only - nothing for this check to judge
    if any(content_is_specific_enough(text) for text in contents):
        return True
    if any(_regex_is_specific_enough(pattern) for pattern in regexes):
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing the file")
    args = parser.parse_args()

    monitors = json.loads(MONITORS_PATH.read_text(encoding="utf-8"))
    disabled = []
    for monitor in monitors:
        monitor_id = str(monitor.get("id") or "")
        if not monitor_id.startswith("et-open-"):
            continue
        if not monitor.get("enabled", True):
            continue
        if not monitor_is_still_specific_enough(monitor):
            monitor["enabled"] = False
            disabled.append((monitor_id, monitor.get("name")))

    print(f"{len(disabled)} monitor(s) no longer specific enough, out of "
          f"{sum(1 for m in monitors if str(m.get('id') or '').startswith('et-open-'))} et-open-* monitors checked.")
    for monitor_id, name in disabled:
        print(f"  DISABLE {monitor_id}: {name}")

    if args.dry_run:
        print("Dry run - default_monitors.json not written.")
        return 0

    if disabled:
        MONITORS_PATH.write_text(json.dumps(monitors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {MONITORS_PATH}")
    else:
        print("No changes to write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
