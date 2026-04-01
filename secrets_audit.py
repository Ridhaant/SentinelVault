#!/usr/bin/env python3
# © 2026 Ridhaant Ajoy Thackur. All rights reserved.
"""
Scan the repo for strings that look like live secrets (Telegram bots, long hex tokens).

Default: print warnings and exit 0 (AlgoStack keeps config defaults for autohealer).

Use ``--strict`` for CI that must fail on any finding (does not apply to deployment
with intentional defaults in ``config.py`` unless you pass ``--include-config``).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
    "mcps",
    "._claude_zip_extract",
}

# Telegram bot token shape; API keys; ngrok-style tokens
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("telegram_bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("long_hex", re.compile(r"\b[0-9a-f]{32,}\b", re.I)),
]


def _should_scan(path: Path) -> bool:
    parts = path.parts
    if "files" in parts or "job_automator" in parts:
        return False
    if SKIP_DIRS & set(parts):
        return False
    if path.suffix.lower() not in {".py", ".env"}:
        return False
    return True


def scan(root: Path, *, include_config: bool) -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if not _should_scan(p):
            continue
        if p.name == "config.py" and not include_config:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if "secrets_audit.py" in str(p) and "re.compile" in line:
                continue
            for name, pat in _PATTERNS:
                if pat.search(line):
                    findings.append((p, i, name, line.strip()[:200]))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="AlgoStack secret-pattern scanner")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any pattern matches (use with --include-config for full audit).",
    )
    ap.add_argument(
        "--include-config",
        action="store_true",
        help="Also scan config.py (normally skipped because defaults are intentional).",
    )
    ap.add_argument("--root", type=Path, default=Path("."))
    args = ap.parse_args()
    root = args.root.resolve()
    findings = scan(root, include_config=args.include_config)
    if not findings:
        print("secrets_audit: no findings (excluding config.py unless --include-config)")
        return 0
    for p, line_no, name, line in findings:
        print(f"{p.relative_to(root)}:{line_no} [{name}] {line}")
    if args.strict:
        print(f"\nsecrets_audit: {len(findings)} finding(s) — FAILED (--strict)", file=sys.stderr)
        return 1
    print(f"\nsecrets_audit: {len(findings)} warning(s) — exit 0 (use --strict to fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
