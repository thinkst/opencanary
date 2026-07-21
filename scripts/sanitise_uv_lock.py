#!/usr/bin/env python3

from pathlib import Path
import sys

LOCK_FILE = Path("uv.lock")

REPLACEMENTS = [
    (
        'url = "https://thinkst.packageproxy.dev/pypi/packages/',
        'url = "https://files.pythonhosted.org/packages/',
    ),
    (
        'registry = "https://thinkst.packageproxy.dev/pypi/"',
        'registry = "https://pypi.org/simple"',
    ),
]

REMOVALS = [
    'exclude-newer = "0001-01-01T00:00:00Z" # This has no effect and is included for backwards compatibility when using relative exclude-newer values.',
    'exclude-newer-span = "P7D"',
]


def main() -> int:
    if not LOCK_FILE.exists():
        print(f"{LOCK_FILE} not found.", file=sys.stderr)
        return 1

    original = LOCK_FILE.read_text(encoding="utf-8")
    updated = original

    # Apply the more specific replacement first.
    for old, new in REPLACEMENTS:
        updated = updated.replace(old, new)

    for removal in REMOVALS:
        updated = updated.replace(removal, "")

    if updated != original:
        LOCK_FILE.write_text(updated, encoding="utf-8")
        print(f"Updated {LOCK_FILE}.")
    else:
        print(f"{LOCK_FILE} already contains public package URLs.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
