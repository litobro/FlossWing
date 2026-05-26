"""Trivial CLI for v0.2 integration testing.

The user-supplied `name` flows into a subprocess call via os.system,
which is a textbook command_injection sink — Recon should reasonably
queue a command_injection hunt task.
"""

from __future__ import annotations

import os
import sys


def greet(name: str) -> None:
    # Intentionally bad: command_injection sink for the integration test.
    os.system(f"echo Hello, {name}")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: v02-smoke <name>", file=sys.stderr)
        sys.exit(2)
    greet(sys.argv[1])
