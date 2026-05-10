"""Tests for the BLUE protocol (deniable asymmetric encryption)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_blue() -> tuple[int, int]:
    print("=" * 60)
    print("BLUE protocol")
    print("=" * 60)
    c = Counter()

    # -- genkeys --
    keys = crx.blue.genkeys("1")
    c.assert_eq("genkeys returns 3 keys",
                lambda: set(keys.keys()), {"gpubkey", "xprivkey", "yprivkey"})
    c.assert_true("all keys are non-empty strings",
                  lambda: all(isinstance(v, str) and len(v) > 0
                              for v in keys.values()))
    c.assert_true("two genkeys produce different keys",
                  lambda: crx.blue.genkeys("1")["gpubkey"] != keys["gpubkey"])

    # -- dual mode round-trip --
    keys = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real", ymsg="decoy")
    c.assert_eq("dual mode: xprivkey decrypts xmsg",
                lambda: crx.blue.decrypt("1", keys["xprivkey"], bundle), "real")
    c.assert_eq("dual mode: yprivkey decrypts ymsg",
                lambda: crx.blue.decrypt("1", keys["yprivkey"], bundle), "decoy")

    # -- mono-x mode --
    keys = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="x-only")
    c.assert_eq("mono-x: xprivkey recovers msg",
                lambda: crx.blue.decrypt("1", keys["xprivkey"], bundle), "x-only")

    # -- mono-y mode --
    keys = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1", keys["gpubkey"], ymsg="y-only")
    c.assert_eq("mono-y: yprivkey recovers msg",
                lambda: crx.blue.decrypt("1", keys["yprivkey"], bundle), "y-only")

    # -- wrong key rejects --
    k1 = crx.blue.genkeys("1")
    k2 = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1", k1["gpubkey"], xmsg="for k1")
    c.assert_raise("wrong key raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.blue.decrypt("1", k2["xprivkey"], bundle))

    # -- unicode round-trip --
    keys = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1", keys["gpubkey"],
                              xmsg="日本語 café 🔑", ymsg="emoji 🎉")
    c.assert_eq("unicode xmsg round-trip",
                lambda: crx.blue.decrypt("1", keys["xprivkey"], bundle),
                "日本語 café 🔑")
    c.assert_eq("unicode ymsg round-trip",
                lambda: crx.blue.decrypt("1", keys["yprivkey"], bundle),
                "emoji 🎉")

    # -- bundle indistinguishability --
    keys = crx.blue.genkeys("1")
    b1 = crx.blue.encrypt("1", keys["gpubkey"], xmsg="same", ymsg="same")
    b2 = crx.blue.encrypt("1", keys["gpubkey"], xmsg="same", ymsg="same")
    c.assert_true("two encryptions produce different bundles",
                  lambda: b1 != b2)

    # -- getversion --
    keys = crx.blue.genkeys("1")
    bundle = crx.blue.encrypt("1.0", keys["gpubkey"], xmsg="test")
    c.assert_eq("getversion extracts version",
                lambda: crx.blue.getversion(bundle), "1.0")

    # -- version specifier --
    c.assert_eq("major-only specifier works for decrypt",
                lambda: crx.blue.decrypt("1", keys["xprivkey"], bundle), "test")

    # -- at least one message required --
    keys = crx.blue.genkeys("1")
    c.assert_raise("no message raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("1", keys["gpubkey"]))

    # -- bucket mismatch --
    keys = crx.blue.genkeys("1")
    c.assert_raise("different buckets raise EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("1", keys["gpubkey"],
                                            xmsg="short",
                                            ymsg="x" * 5000))

    # -- type validation --
    keys = crx.blue.genkeys("1")
    c.assert_raise("non-str gpubkey raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.encrypt("1", 123, xmsg="msg"))
    c.assert_raise("non-str xmsg raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.encrypt("1", keys["gpubkey"], xmsg=123))
    c.assert_raise("non-str privkey raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.decrypt("1", 123,
                           crx.blue.encrypt("1", keys["gpubkey"], xmsg="test")))

    # -- unknown version --
    c.assert_raise("unknown version raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.encrypt("99", keys["gpubkey"], xmsg="msg"))

    p, f = c.summary()
    print(f"\n  BLUE: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_blue()
    sys.exit(0 if f == 0 else 1)
