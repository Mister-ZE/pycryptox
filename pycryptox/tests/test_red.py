"""Tests for the RED protocol (threshold encryption)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_red() -> tuple[int, int]:
    print("=" * 60)
    print("RED protocol")
    print("=" * 60)
    c = Counter()

    # -- genkeys --
    keys = crx.red.genkeys("1", 2, 3)
    c.assert_eq("genkeys returns gpubkey + privkeys",
                lambda: set(keys.keys()), {"gpubkey", "privkeys"})
    c.assert_eq("genkeys produces n=3 shares",
                lambda: len(keys["privkeys"]), 3)
    c.assert_true("all shares are non-empty strings",
                  lambda: all(isinstance(s, str) and len(s) > 0
                              for s in keys["privkeys"]))

    # -- threshold 2-of-3 --
    keys = crx.red.genkeys("1", 2, 3)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "secret message")
    c.assert_eq("2-of-3: shares [0,1] decrypt",
                lambda: crx.red.decrypt("1", keys["privkeys"][:2], bundle),
                "secret message")
    c.assert_eq("2-of-3: shares [0,2] decrypt",
                lambda: crx.red.decrypt("1", [keys["privkeys"][0], keys["privkeys"][2]], bundle),
                "secret message")
    c.assert_eq("2-of-3: shares [1,2] decrypt",
                lambda: crx.red.decrypt("1", keys["privkeys"][1:], bundle),
                "secret message")

    # -- threshold 3-of-5 --
    keys = crx.red.genkeys("1", 3, 5)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "five-way secret")
    c.assert_eq("3-of-5: any 3 shares decrypt",
                lambda: crx.red.decrypt("1", keys["privkeys"][:3], bundle),
                "five-way secret")

    # -- threshold 1-of-5 (redundancy) --
    keys = crx.red.genkeys("1", 1, 5)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "any single share works")
    for i in range(5):
        c.assert_eq(f"1-of-5: share [{i}] alone decrypts",
                    lambda i=i: crx.red.decrypt("1", [keys["privkeys"][i]], bundle),
                    "any single share works")

    # -- insufficient shares --
    keys = crx.red.genkeys("1", 3, 5)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "need 3")
    c.assert_raise("2 of 3 needed shares raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.red.decrypt("1", keys["privkeys"][:2], bundle))

    # -- duplicate shares --
    keys = crx.red.genkeys("1", 2, 3)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "test")
    c.assert_raise("duplicate shares raise DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.red.decrypt("1",
                           [keys["privkeys"][0], keys["privkeys"][0]], bundle))

    # -- mixed shares from different genkeys --
    k1 = crx.red.genkeys("1", 2, 3)
    k2 = crx.red.genkeys("1", 2, 3)
    bundle = crx.red.encrypt("1", k1["gpubkey"], "for k1 only")
    c.assert_raise("mixed shares from different genkeys raise DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.red.decrypt("1",
                           [k1["privkeys"][0], k2["privkeys"][1]], bundle))

    # -- getversion --
    keys = crx.red.genkeys("1", 2, 3)
    bundle = crx.red.encrypt("1.0", keys["gpubkey"], "v-test")
    c.assert_eq("getversion extracts version",
                lambda: crx.red.getversion(bundle), "1.0")

    # -- unicode --
    keys = crx.red.genkeys("1", 2, 3)
    bundle = crx.red.encrypt("1", keys["gpubkey"], "日本語 🔐")
    c.assert_eq("unicode round-trip",
                lambda: crx.red.decrypt("1", keys["privkeys"][:2], bundle),
                "日本語 🔐")

    # -- invalid threshold parameters --
    c.assert_raise("t=0 raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.red.genkeys("1", 0, 3))
    c.assert_raise("t > n raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.red.genkeys("1", 4, 3))
    c.assert_raise("n=256 raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.red.genkeys("1", 1, 256))

    # -- type validation --
    c.assert_raise("float t raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.red.genkeys("1", 2.0, 3))
    c.assert_raise("bool t raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.red.genkeys("1", True, 3))
    keys_t = crx.red.genkeys("1", 2, 3)
    bundle_t = crx.red.encrypt("1", keys_t["gpubkey"], "type-test")
    c.assert_raise("non-list privkeys raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.red.decrypt("1", "not-a-list", bundle_t))

    p, f = c.summary()
    print(f"\n  RED: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_red()
    sys.exit(0 if f == 0 else 1)
