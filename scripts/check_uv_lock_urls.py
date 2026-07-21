#!/usr/bin/env python3

import os
from pathlib import Path
import subprocess
import sys

LOCK_FILE = Path("uv.lock")

FORBIDDEN_URLS = (
    "https://thinkst.packageproxy.dev/pypi/",
    "https://thinkst.packageproxy.dev/pypi",
)


def read_file_from_commit(commit: str, path: Path) -> str | None:
    """Read a file as stored in a Git commit.

    Returns None when the file does not exist in that commit.
    """
    result = subprocess.run(
        ["git", "show", f"{commit}:{path.as_posix()}"],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        return result.stdout

    # Exit code 128 normally means the path or revision does not exist.
    if result.returncode == 128:
        return None

    print(
        f"Unable to inspect {path} in commit {commit}:",
        file=sys.stderr,
    )
    print(result.stderr.strip(), file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    remote_url = os.environ.get("PRE_COMMIT_REMOTE_URL", "")
    commit = os.environ.get("PRE_COMMIT_TO_REF", "")

    # Run this check only for pushes to GitHub.
    if remote_url and "github.com" not in remote_url.lower():
        return 0

    if not commit:
        print(
            "PRE_COMMIT_TO_REF is unavailable; cannot determine which "
            "commit is being pushed.",
            file=sys.stderr,
        )
        return 2

    # Git uses an all-zero object ID when deleting a remote branch.
    if set(commit) == {"0"}:
        return 0

    contents = read_file_from_commit(commit, LOCK_FILE)

    if contents is None:
        # The pushed commit does not contain uv.lock.
        return 0

    found_urls = [url for url in FORBIDDEN_URLS if url in contents]

    if not found_urls:
        return 0

    print(
        "uv.lock in the commit being pushed contains internal " "package-index URLs:",
        file=sys.stderr,
    )

    for url in found_urls:
        print(f"  - {url}", file=sys.stderr)

    print(
        "\nRun the uv.lock sanitisation script, stage uv.lock, "
        "and commit the change before pushing.",
        file=sys.stderr,
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
