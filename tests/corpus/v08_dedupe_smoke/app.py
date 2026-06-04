#!/usr/bin/env python3
"""Tiny CLI: runs operations on a user-supplied path."""

import subprocess
import sys


def run_ops(target: str) -> None:
    # Sink 1: shell=True with user-supplied target -> shell injection.
    subprocess.run(f"ls -la {target}", shell=True, check=False)
    # Cosmetic indirection so the two sinks aren't on truly consecutive lines.
    _ = "tracing"
    # Sink 2: same pattern, same function, distance is ~3 lines.
    subprocess.run(f"cat {target}/.config", shell=True, check=False)


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: app.py <target>", file=sys.stderr)
        sys.exit(2)
    run_ops(sys.argv[1])


if __name__ == "__main__":
    main()
