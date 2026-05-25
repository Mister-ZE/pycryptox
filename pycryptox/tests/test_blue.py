"""Tests for the BLUE protocol (deniable asymmetric encryption).

Per project policy, only the latest stable version is tested. BLUE's
current stable is v2.0. v1.0 is exercised indirectly through
`update_bundle` (which is itself a v2.0+ feature)."""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_blue() -> tuple[int, int]:
    print("=" * 60)
    print("BLUE protocol")
    print("=" * 60)
    c = Counter()

    keys = crx.blue.genkeys("2")
    keys2 = crx.blue.genkeys("2")

    # =============== genkeys ===============
    c.assert_eq("v2.0 genkeys returns gpubkey + xprivkey + yprivkey",
                lambda: sorted(keys.keys()),
                ["gpubkey", "xprivkey", "yprivkey"])
    c.assert_true("v2.0 keys are non-empty strs",
                  lambda: all(isinstance(v, str) and v for v in keys.values()))
    c.assert_true("v2.0 two genkeys produce different keys",
                  lambda: keys["xprivkey"] != keys2["xprivkey"])

    # =============== sync encrypt/decrypt ===============

    # Dual mode round-trip
    ct = crx.blue.encrypt("2", keys["gpubkey"], xmsg="hello x", ymsg="hello y")
    c.assert_eq("v2.0 dual: xprivkey decrypts xmsg with slot='x'",
                lambda: crx.blue.decrypt("2", keys["xprivkey"], ct, slot="x"),
                "hello x")
    c.assert_eq("v2.0 dual: yprivkey decrypts ymsg with slot='y'",
                lambda: crx.blue.decrypt("2", keys["yprivkey"], ct, slot="y"),
                "hello y")

    # Mono-x: only xmsg, ymsg is a decoy
    ct_mono_x = crx.blue.encrypt("2", keys["gpubkey"], xmsg="alone-x")
    c.assert_eq("v2.0 mono-x: xprivkey recovers xmsg",
                lambda: crx.blue.decrypt("2", keys["xprivkey"], ct_mono_x, slot="x"),
                "alone-x")

    # Mono-y
    ct_mono_y = crx.blue.encrypt("2", keys["gpubkey"], ymsg="alone-y")
    c.assert_eq("v2.0 mono-y: yprivkey recovers ymsg",
                lambda: crx.blue.decrypt("2", keys["yprivkey"], ct_mono_y, slot="y"),
                "alone-y")

    # Wrong key
    c.assert_raise("v2.0 wrong privkey raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.blue.decrypt("2", keys2["xprivkey"], ct, slot="x"))

    # Unicode
    ct_u = crx.blue.encrypt("2", keys["gpubkey"], xmsg="日本語 café 🔑", ymsg="другой")
    c.assert_eq("v2.0 unicode xmsg round-trip",
                lambda: crx.blue.decrypt("2", keys["xprivkey"], ct_u, slot="x"),
                "日本語 café 🔑")
    c.assert_eq("v2.0 unicode ymsg round-trip",
                lambda: crx.blue.decrypt("2", keys["yprivkey"], ct_u, slot="y"),
                "другой")

    # Different bundles for same inputs (random order flag + random salt)
    c1 = crx.blue.encrypt("2", keys["gpubkey"], xmsg="same", ymsg="same")
    c2 = crx.blue.encrypt("2", keys["gpubkey"], xmsg="same", ymsg="same")
    c.assert_true("v2.0 two encryptions produce different bundles",
                  lambda: c1 != c2)

    # getversion
    c.assert_eq("v2.0 getversion returns 2.0",
                lambda: crx.blue.getversion(ct), "2.0")

    # Major-only specifier
    ct_major = crx.blue.encrypt("2", keys["gpubkey"], xmsg="major-only")
    c.assert_eq("v2.0 major-only specifier works",
                lambda: crx.blue.decrypt("2", keys["xprivkey"], ct_major, slot="x"),
                "major-only")

    # =============== validation ===============
    c.assert_raise("v2.0 encrypt rejects non-str gpubkey",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.encrypt("2", 123, xmsg="msg"))
    c.assert_raise("v2.0 encrypt rejects non-str xmsg",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.encrypt("2", keys["gpubkey"], xmsg=42))
    c.assert_raise("v2.0 encrypt rejects non-str ymsg",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.encrypt("2", keys["gpubkey"], ymsg=42))
    c.assert_raise("v2.0 encrypt no msg raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("2", keys["gpubkey"]))
    c.assert_raise("v2.0 encrypt different buckets raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("2", keys["gpubkey"], xmsg="short", ymsg="x" * (10 * 1024)))
    c.assert_raise("v2.0 encrypt rejects unknown version",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.encrypt("99", keys["gpubkey"], xmsg="msg"))

    c.assert_raise("v2.0 decrypt rejects non-str privkey",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.decrypt("2", 123, ct, slot="x"))
    c.assert_raise("v2.0 decrypt rejects invalid slot",
                   crx.DecryptionError,
                   lambda: crx.blue.decrypt("2", keys["xprivkey"], ct, slot="z"))
    c.assert_raise("v2.0 decrypt rejects non-str slot",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.decrypt("2", keys["xprivkey"], ct, slot=1))

    # =============== async (id-based job mode) ===============

    # Basic async encrypt
    result_immediate = crx.blue.encrypt("2", keys["gpubkey"], xmsg="async msg", id="job1")
    c.assert_true("v2.0 async encrypt returns None immediately",
                  lambda: result_immediate is None)

    # Progress between 0 and 1 (or already 1 if very fast)
    p = crx.blue.show_encryption_progress(id="job1")
    c.assert_true("v2.0 async show progress returns a float in [0, 1]",
                  lambda: isinstance(p, float) and 0.0 <= p <= 1.0)

    # Retrieve result
    bundle_async = crx.blue.get_encryption_result(id="job1")
    c.assert_eq("v2.0 async result has correct version",
                lambda: crx.blue.getversion(bundle_async), "2.0")
    c.assert_eq("v2.0 async result decrypts correctly",
                lambda: crx.blue.decrypt("2", keys["xprivkey"], bundle_async, slot="x"),
                "async msg")

    # Auto-clean after get_result
    c.assert_raise("v2.0 async job auto-cleaned after get_result",
                   crx.EncryptionError,
                   lambda: crx.blue.show_encryption_progress(id="job1"))

    # id collision
    crx.blue.encrypt("2", keys["gpubkey"], xmsg="first", id="collide")
    c.assert_raise("v2.0 duplicate id raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("2", keys["gpubkey"], xmsg="second", id="collide"))
    crx.blue.get_encryption_result(id="collide")   # clean up

    # No job with given id
    c.assert_raise("v2.0 show_encryption_progress on unknown id raises",
                   crx.EncryptionError,
                   lambda: crx.blue.show_encryption_progress(id="nonexistent"))
    c.assert_raise("v2.0 get_encryption_result on unknown id raises",
                   crx.EncryptionError,
                   lambda: crx.blue.get_encryption_result(id="nonexistent"))

    # Async forbidden on v1.0
    c.assert_raise("v1.0 async encrypt forbidden",
                   crx.EncryptionError,
                   lambda: crx.blue.encrypt("1", keys["gpubkey"], xmsg="msg", id="forbid"))

    # Cross-kind id confusion: an encrypt id cannot be retrieved as decrypt result
    crx.blue.encrypt("2", keys["gpubkey"], xmsg="confused", id="kind_test")
    c.assert_raise("v2.0 encrypt id rejected by show_decryption_progress",
                   crx.DecryptionError,
                   lambda: crx.blue.show_decryption_progress(id="kind_test"))
    crx.blue.get_encryption_result(id="kind_test")   # clean up

    # Async decrypt
    bundle_for_async_decrypt = crx.blue.encrypt("2", keys["gpubkey"], xmsg="decrypt me async")

    def _async_decrypt_round_trip() -> str:
        crx.blue.decrypt("2", keys["xprivkey"], bundle_for_async_decrypt, slot="x", id="djob1")
        return crx.blue.get_decryption_result(id="djob1")
    c.assert_eq("v2.0 async decrypt round-trip",
                _async_decrypt_round_trip, "decrypt me async")

    # Async decrypt error propagation (wrong key)
    def _async_decrypt_bad() -> str:
        crx.blue.decrypt("2", keys2["xprivkey"], bundle_for_async_decrypt, slot="x", id="dbad")
        return crx.blue.get_decryption_result(id="dbad")
    c.assert_raise("v2.0 async decrypt with wrong key raises DecryptionError on get_result",
                   crx.DecryptionError,
                   _async_decrypt_bad)

    # =============== update_bundle ===============

    # v1.0 source bundle  ---  these tests require real ML-KEM round-trip; we
    # exercise the full pipeline. With stub liboqs, the underlying decrypt
    # will fail and these will be reported as failures (acceptable: real run
    # validates them).
    keys_v1 = crx.blue.genkeys("1")
    ct_v1 = crx.blue.encrypt("1", keys_v1["gpubkey"], xmsg="migrate-x", ymsg="migrate-y")

    # v1 -> v2 with xprivkey only: xmsg preserved, ymsg becomes decoy
    def _migrate_x_only() -> str:
        ct_v2_local = crx.blue.update_bundle("1 to 2", keys_v1["gpubkey"], ct_v1,
                                             xprivkey=keys_v1["xprivkey"])
        return crx.blue.getversion(ct_v2_local)
    c.assert_eq("update_bundle 1->2 produces v2.0",
                _migrate_x_only, "2.0")

    def _migrate_x_preserved() -> str:
        ct_v2_local = crx.blue.update_bundle("1 to 2", keys_v1["gpubkey"], ct_v1,
                                             xprivkey=keys_v1["xprivkey"])
        return crx.blue.decrypt("2", keys_v1["xprivkey"], ct_v2_local, slot="x")
    c.assert_eq("update_bundle 1->2 (xprivkey only) preserves xmsg",
                _migrate_x_preserved, "migrate-x")

    # v1 -> v2 with both privkeys: both messages preserved
    def _migrate_both_x() -> str:
        ct_v2_full = crx.blue.update_bundle("1 to 2", keys_v1["gpubkey"], ct_v1,
                                            xprivkey=keys_v1["xprivkey"],
                                            yprivkey=keys_v1["yprivkey"])
        return crx.blue.decrypt("2", keys_v1["xprivkey"], ct_v2_full, slot="x")
    c.assert_eq("update_bundle 1->2 (both privkeys) preserves xmsg",
                _migrate_both_x, "migrate-x")

    def _migrate_both_y() -> str:
        ct_v2_full = crx.blue.update_bundle("1 to 2", keys_v1["gpubkey"], ct_v1,
                                            xprivkey=keys_v1["xprivkey"],
                                            yprivkey=keys_v1["yprivkey"])
        return crx.blue.decrypt("2", keys_v1["yprivkey"], ct_v2_full, slot="y")
    c.assert_eq("update_bundle 1->2 (both privkeys) preserves ymsg",
                _migrate_both_y, "migrate-y")

    # All four spec forms
    for spec in ("1.0 to 2", "1 to 2.0", "1 to 2", "1.0 to 2.0"):
        def _migrate_spec(s: str = spec) -> str:
            ct_n = crx.blue.update_bundle(s, keys_v1["gpubkey"], ct_v1,
                                          xprivkey=keys_v1["xprivkey"])
            return crx.blue.decrypt("2", keys_v1["xprivkey"], ct_n, slot="x")
        c.assert_eq(f"update_bundle accepts spec '{spec}'",
                    _migrate_spec, "migrate-x")

    # Same-version no-op (returns input unchanged): does NOT need real KEM round-trip
    ct_stable = crx.blue.encrypt("2", keys["gpubkey"], xmsg="stable")
    c.assert_true("update_bundle 2->2 is no-op",
                  lambda: crx.blue.update_bundle("2 to 2", keys["gpubkey"], ct_stable,
                                                 xprivkey=keys["xprivkey"]) == ct_stable)
    c.assert_true("update_bundle 2.0->2 is no-op",
                  lambda: crx.blue.update_bundle("2.0 to 2", keys["gpubkey"], ct_stable,
                                                 xprivkey=keys["xprivkey"]) == ct_stable)

    # Downgrade rejected by default (does NOT need round-trip: the check is upfront)
    c.assert_raise("update_bundle 2->1 default raises DowngradeError",
                   crx.DowngradeError,
                   lambda: crx.blue.update_bundle("2 to 1", keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))

    # Downgrade=True allows: requires real KEM (decrypt v2.0 + encrypt v1.0)
    def _downgrade() -> str:
        ct_back = crx.blue.update_bundle("2 to 1", keys["gpubkey"], ct_stable,
                                         xprivkey=keys["xprivkey"], downgrade=True)
        return crx.blue.getversion(ct_back)
    c.assert_eq("update_bundle downgrade=True produces v1.0",
                _downgrade, "1.0")

    # Validation
    c.assert_raise("update_bundle 'garbage' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.update_bundle("garbage", keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle missing 'to' raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.update_bundle("1->2", keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle unknown source raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.update_bundle("99 to 2", keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle unknown target raises VersionNotFoundError",
                   crx.VersionNotFoundError,
                   lambda: crx.blue.update_bundle("2 to 99", keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle no privkey raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.update_bundle("1 to 2", keys["gpubkey"], ct_v1))

    # Type validation on update_bundle
    c.assert_raise("update_bundle non-str old_to_new raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.update_bundle(12, keys["gpubkey"], ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle non-str gpubkey raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.update_bundle("1 to 2", 12, ct_stable,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle non-str old_msg raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.update_bundle("1 to 2", keys["gpubkey"], 12,
                                                  xprivkey=keys["xprivkey"]))
    c.assert_raise("update_bundle non-str xprivkey raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.update_bundle("1 to 2", keys["gpubkey"], ct_v1,
                                                  xprivkey=12))
    c.assert_raise("update_bundle non-bool downgrade raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: crx.blue.update_bundle("1 to 2", keys["gpubkey"], ct_v1,
                                                  xprivkey=keys["xprivkey"], downgrade="yes"))

    # =============== ETA functions ===============

    crx.blue.encrypt("2", keys["gpubkey"], xmsg="eta_test", id="eta1")
    # Before consumption — show_eta should be a float, 0.0, or None depending on timing
    c.assert_true("v2.0 show_encryption_eta returns float-or-None",
                  lambda: (crx.blue.show_encryption_eta(id="eta1") is None
                           or isinstance(crx.blue.show_encryption_eta(id="eta1"), float)))
    crx.blue.get_encryption_result(id="eta1")
    # Unknown id
    c.assert_raise("v2.0 show_encryption_eta on unknown id raises EncryptionError",
                   crx.EncryptionError,
                   lambda: crx.blue.show_encryption_eta(id="nonexistent_eta"))
    c.assert_raise("v2.0 show_decryption_eta on unknown id raises DecryptionError",
                   crx.DecryptionError,
                   lambda: crx.blue.show_decryption_eta(id="nonexistent_eta"))
    # Cross-kind id
    crx.blue.encrypt("2", keys["gpubkey"], xmsg="eta_cross", id="eta_cross")
    c.assert_raise("v2.0 encrypt id rejected by show_decryption_eta",
                   crx.DecryptionError,
                   lambda: crx.blue.show_decryption_eta(id="eta_cross"))
    crx.blue.get_encryption_result(id="eta_cross")

    p, f = c.summary()
    print(f"\n  BLUE: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_blue()
    sys.exit(0 if f == 0 else 1)
