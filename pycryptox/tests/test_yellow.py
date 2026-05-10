"""Tests for the YELLOW protocol (steganography placeholder)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_yellow() -> tuple[int, int]:
    print("=" * 60)
    print("YELLOW protocol")
    print("=" * 60)
    c = Counter()

    # -- v0.0 returns strings --
    c.assert_true("stega v0.0 returns a string",
                  lambda: isinstance(crx.yellow.stega("0.0"), str))
    c.assert_true("unstega v0.0 returns a string",
                  lambda: isinstance(crx.yellow.unstega("0.0"), str))

    # -- unknown version --
    c.assert_raise("stega rejects unknown version",
                   crx.VersionNotFoundError,
                   lambda: crx.yellow.stega("99"))
    c.assert_raise("unstega rejects unknown version",
                   crx.VersionNotFoundError,
                   lambda: crx.yellow.unstega("99"))

    p, f = c.summary()
    print(f"\n  YELLOW: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_yellow()
    sys.exit(0 if f == 0 else 1)
