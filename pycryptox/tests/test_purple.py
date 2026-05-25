"""Tests for the PURPLE protocol (password-based encryption).

Per project policy, only the latest stable version of each protocol is
tested. PURPLE's current stable is v2.0. Older minors (v1.0, v1.1) are
exercised indirectly through `update_bundle` because that function is
itself a v2.0+ feature."""

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

    # ===================== PURPLE v2.0 =====================

    # -- v2.0 round-trip at each level --
    for lvl in ("low", "normal", "strong", "extreme"):
        ct = crx.purple.encrypt("2", "pwd", f"hello-{lvl}", level=lvl)
        c.assert_eq(f"v2.0 round-trip at level={lvl}",
                    lambda ct=ct, lvl=lvl: crx.purple.decrypt("2", "pwd", ct),
                    f"hello-{lvl}")
        c.assert_eq(f"v2.0 getlevel reads back level={lvl}",
                    lambda ct=ct, lvl=lvl: crx.purple.getlevel(ct), lvl)

    # -- v2.0 default level is "strong" --
    ct_default = crx.purple.encrypt("2", "pwd", "default-test")
    c.assert_eq("v2.0 default level is 'strong'",
                lambda: crx.purple.getlevel(ct_default), "strong")

    # -- v2.0 empty / unicode / long --
    c.assert_eq("v2.0 empty message round-trip",
                lambda: crx.purple.decrypt("2", "pwd",
                        crx.purple.encrypt("2", "pwd", "", level="low")),
                "")
    c.assert_eq("v2.0 unicode round-trip",
                lambda: crx.purple.decrypt("2", "pwd",
                        crx.purple.encrypt("2", "pwd", "日本語 café 🔑", level="normal")),
                "日本語 café 🔑")
    c.assert_true("v2.0 long message round-trip (10 KB)",
                  lambda: crx.purple.decrypt("2", "pwd",
                          crx.purple.encrypt("2", "pwd", "x" * 10000, level="low")) == "x" * 10000)

    # -- v2.0 wrong password --
    ct = crx.purple.encrypt("2", "right", "secret", level="low")
    c.assert_raise("v2.0 wrong password raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.purple.decrypt("2", "wrong", ct))

    # -- v2.0 type validation --
    c.assert_raise("v2.0 encrypt rejects non-str key",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.encrypt("2", 123, "msg"))
    c.assert_raise("v2.0 encrypt rejects non-str msg",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.encrypt("2", "pwd", 123))
    c.assert_raise("v2.0 encrypt rejects non-str level",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.encrypt("2", "pwd", "msg", level=42))
    c.assert_raise("v2.0 decrypt rejects non-str key",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.decrypt("2", 123, ct))

    # -- v2.0 invalid level --
    c.assert_raise("v2.0 invalid level raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.purple.encrypt("2", "pwd", "msg", level="ultra"))

    # -- v2.0 version mismatch --
    c.assert_raise("v2.0 decrypt rejects v0.0 specifier on v2.0 bundle",
                   crx.DecryptionError,
                   lambda: crx.purple.decrypt("0", "pwd", ct))

    # -- v2.0 getversion --
    ct2_0 = crx.purple.encrypt("2.0", "pwd", "version-test", level="low")
    c.assert_eq("v2.0 getversion returns 2.0",
                lambda: crx.purple.getversion(ct2_0), "2.0")
    c.assert_raise("getversion rejects non-str msg",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.getversion(123))

    # -- v2.0 unknown version --
    c.assert_raise("encrypt rejects unknown version",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.encrypt("99", "pwd", "msg"))

    # -- v2.0 nondeterminism --
    c1 = crx.purple.encrypt("2", "pwd", "same", level="low")
    c2 = crx.purple.encrypt("2", "pwd", "same", level="low")
    c.assert_true("v2.0 two encryptions produce different bundles",
                  lambda: c1 != c2)

    # -- getlevel --
    c.assert_raise("getlevel rejects non-str",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.getlevel(42))
    c.assert_raise("getlevel rejects malformed b64",
                   crx.DecryptionError,
                   lambda: crx.purple.getlevel("$$$"))

    # -- v2.0 corrupted level byte detected at decrypt --
    import base64 as _b64
    ct = crx.purple.encrypt("2", "pwd", "msg", level="normal")
    raw = bytearray(_b64.urlsafe_b64decode(ct))
    raw[2] = 99  # invalid level byte (valid range: 0..3)
    ct_bad = _b64.urlsafe_b64encode(bytes(raw)).decode()
    c.assert_raise("v2.0 invalid level byte detected at decrypt",
                   crx.DecryptionError,
                   lambda: crx.purple.decrypt("2", "pwd", ct_bad))

    # -- v2.0 genkeys --
    pp = crx.purple.genkeys("2")
    c.assert_true("v2.0 genkeys default returns 8-word str (strong level)",
                  lambda: isinstance(pp, str) and len(pp.split()) == 8)
    c.assert_true("v2.0 two genkeys are different",
                  lambda: crx.purple.genkeys("2") != crx.purple.genkeys("2"))
    c.assert_eq("v2.0 genkeys passphrase usable as key",
                lambda: crx.purple.decrypt("2", pp,
                        crx.purple.encrypt("2", pp, "via-v2-genkeys")),
                "via-v2-genkeys")

    # -- v2.0 genkeys with explicit level --
    for level, expected_words in (("low", 6), ("normal", 7), ("strong", 8), ("extreme", 10)):
        c.assert_true(f"v2.0 genkeys level={level!r} returns {expected_words}-word str",
                      lambda lv=level, n=expected_words:
                          len(crx.purple.genkeys("2", level=lv).split()) == n)
    c.assert_raise("v2.0 genkeys rejects unknown level",
                   crx.EncryptionError,
                   lambda: crx.purple.genkeys("2", level="bogus"))
    c.assert_raise("v2.0 genkeys rejects non-str level",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.genkeys("2", level=42))

    # ===================== update_bundle (v2.0+ feature) =====================
    # Older PURPLE versions are exercised here only as INPUT to update_bundle.
    # This is testing the v2.0+ migration feature, not v1.x crypto itself.

    # -- 1.0 -> 2.0 round-trip --
    ct10 = crx.purple.encrypt("1.0", "pwd", "migrate")
    ct2 = crx.purple.update_bundle("1.0 to 2", "pwd", ct10, level="strong")
    c.assert_eq("update_bundle 1.0->2 produces v2.0 bundle",
                lambda: crx.purple.getversion(ct2), "2.0")
    c.assert_eq("update_bundle 1.0->2 sets requested level",
                lambda: crx.purple.getlevel(ct2), "strong")
    c.assert_eq("update_bundle 1.0->2 plaintext preserved",
                lambda: crx.purple.decrypt("2", "pwd", ct2), "migrate")

    # -- 1.0 -> 2.0 with explicit level --
    ct2x = crx.purple.update_bundle("1.0 to 2", "pwd", ct10, level="extreme")
    c.assert_eq("update_bundle 1.0->2 with explicit level=extreme",
                lambda: crx.purple.getlevel(ct2x), "extreme")

    # -- spec parser accepts the documented forms --
    for spec in ("1.0 to 2", "1.0 to 2.0"):
        ctn = crx.purple.update_bundle(spec, "pwd", ct10, level="low")
        c.assert_eq(f"update_bundle accepts spec '{spec}'",
                    lambda ctn=ctn: crx.purple.decrypt("2", "pwd", ctn), "migrate")

    # -- same-version no-op returns input unchanged --
    ct = crx.purple.encrypt("2", "pwd", "stable", level="normal")
    ct_noop = crx.purple.update_bundle("2 to 2", "pwd", ct)
    c.assert_true("update_bundle 2->2 is no-op (exact same string)",
                  lambda: ct_noop == ct)
    ct_noop2 = crx.purple.update_bundle("2.0 to 2", "pwd", ct)
    c.assert_true("update_bundle 2.0->2 is no-op too",
                  lambda: ct_noop2 == ct)

    # -- downgrade rejected by default --
    ct2 = crx.purple.encrypt("2", "pwd", "down", level="low")
    c.assert_raise("downgrade 2->1.0 default raises DowngradeError",
                   crx.DowngradeError,
                   lambda: crx.purple.update_bundle("2 to 1.0", "pwd", ct2))

    # -- downgrade=True allows --
    ct10_back = crx.purple.update_bundle("2 to 1.0", "pwd", ct2, downgrade=True)
    c.assert_eq("update_bundle downgrade=True produces v1.0 bundle",
                lambda: crx.purple.getversion(ct10_back), "1.0")
    c.assert_eq("update_bundle downgrade=True plaintext preserved",
                lambda: crx.purple.decrypt("1.0", "pwd", ct10_back), "down")

    # -- malformed spec --
    c.assert_raise("update_bundle 'garbage' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.update_bundle("garbage", "pwd", ct10))
    c.assert_raise("update_bundle missing 'to' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.update_bundle("1.0->2", "pwd", ct10))

    # -- unknown source/target version --
    c.assert_raise("update_bundle '99 to 2' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.update_bundle("99 to 2", "pwd", ct10))
    c.assert_raise("update_bundle '1.0 to 99' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.purple.update_bundle("1.0 to 99", "pwd", ct10))

    # -- wrong password during update_bundle --
    c.assert_raise("update_bundle with wrong key raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.purple.update_bundle("1.0 to 2", "wrong", ct10))

    # -- type validation on update_bundle --
    c.assert_raise("update_bundle non-str old_to_new raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.update_bundle(12, "pwd", ct10))
    c.assert_raise("update_bundle non-str key raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.update_bundle("1.0 to 2", 12, ct10))
    c.assert_raise("update_bundle non-str old_msg raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.update_bundle("1.0 to 2", "pwd", 12))
    c.assert_raise("update_bundle non-str level raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.update_bundle("1.0 to 2", "pwd", ct10, level=42))
    c.assert_raise("update_bundle non-bool downgrade raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.purple.update_bundle("1.0 to 2", "pwd", ct10, downgrade="yes"))

    p, f = c.summary()
    print(f"\n  PURPLE: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_purple()
    sys.exit(0 if f == 0 else 1)
