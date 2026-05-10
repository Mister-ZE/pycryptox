"""Tests for the PURPLE protocol (password-based encryption)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_purple() -> tuple[int, int]:
    print("=" * 60)
    print("PURPLE protocol")
    print("=" * 60)
    c = Counter()

    # -- encrypt / decrypt round-trip --
    c.assert_ok("encrypt returns a string",
                lambda: isinstance(crx.purple.encrypt("1", "pwd", "hello"), str))
    c.assert_eq("decrypt recovers plaintext",
                lambda: crx.purple.decrypt("1", "pwd",
                        crx.purple.encrypt("1", "pwd", "hello world")),
                "hello world")
    c.assert_eq("empty message round-trip",
                lambda: crx.purple.decrypt("1", "pwd",
                        crx.purple.encrypt("1", "pwd", "")),
                "")
    c.assert_eq("unicode message round-trip",
                lambda: crx.purple.decrypt("1", "pwd",
                        crx.purple.encrypt("1", "pwd", "日本語 café 🔑")),
                "日本語 café 🔑")
    c.assert_true("long message round-trip (10 KB)",
                  lambda: crx.purple.decrypt("1", "pwd",
                          crx.purple.encrypt("1", "pwd", "x" * 10000)) == "x" * 10000)

    # -- different bundles for same input --
    ct1 = crx.purple.encrypt("1", "pwd", "same")
    ct2 = crx.purple.encrypt("1", "pwd", "same")
    c.assert_true("two encryptions produce different bundles",
                  lambda: ct1 != ct2)

    # -- wrong password --
    ct = crx.purple.encrypt("1", "correct", "secret")
    c.assert_raise("wrong password raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.purple.decrypt("1", "wrong", ct))

    # -- version specifier --
    ct = crx.purple.encrypt("1.0", "pwd", "test")
    c.assert_eq("major-only specifier accepts matching bundle",
                lambda: crx.purple.decrypt("1", "pwd", ct), "test")
    c.assert_eq("exact specifier accepts matching bundle",
                lambda: crx.purple.decrypt("1.0", "pwd", ct), "test")

    # -- version mismatch --
    c.assert_raise("decrypt rejects version mismatch",
                   crx.DecryptionError,
                   lambda: crx.purple.decrypt("0", "pwd", ct))

    # -- getversion --
    c.assert_eq("getversion extracts version",
                lambda: crx.purple.getversion(ct), "1.0")

    # -- genkeys --
    passphrase = crx.purple.genkeys("1")
    c.assert_true("genkeys returns a string", lambda: isinstance(passphrase, str))
    c.assert_true("genkeys returns 6 words",
                  lambda: len(passphrase.split()) == 6)
    c.assert_true("two genkeys are different",
                  lambda: crx.purple.genkeys("1") != crx.purple.genkeys("1"))

    # -- genkeys produces usable passphrase --
    pp = crx.purple.genkeys("1")
    c.assert_eq("genkeys passphrase works as key",
                lambda: crx.purple.decrypt("1", pp,
                        crx.purple.encrypt("1", pp, "test")),
                "test")

    # -- type validation --
    c.assert_raise("encrypt rejects non-str key",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.encrypt("1", 123, "msg"))
    c.assert_raise("encrypt rejects non-str msg",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.encrypt("1", "pwd", 123))
    c.assert_raise("decrypt rejects non-str key",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.decrypt("1", 123,
                           crx.purple.encrypt("1", "pwd", "test")))
    c.assert_raise("getversion rejects non-str msg",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.getversion(123))

    # -- unknown version --
    c.assert_raise("encrypt rejects unknown version",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.encrypt("99", "pwd", "msg"))

    p, f = c.summary()
    print(f"\n  PURPLE: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_purple()
    sys.exit(0 if f == 0 else 1)
