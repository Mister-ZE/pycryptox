"""Tests for keyx.bluekeys (keys + ckeys) and cross-module discrimination."""

import sys
import shutil
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_bluekeys() -> tuple[int, int]:
    print("=" * 60)
    print("keyx.bluekeys (keys + ckeys)")
    print("=" * 60)
    c = Counter()

    tmp = Path(tempfile.mkdtemp(prefix="bk_"))
    keys_db = tmp / "channels.keys"
    ckeys_db = tmp / "vault.ckeys"
    PWD = "master-pass"

    bk = crx.keyx.bluekeys.keys
    ck = crx.keyx.bluekeys.ckeys

    alice = crx.blue.genkeys("1")
    bob = crx.blue.genkeys("1")

    # ===================== bluekeys.keys =====================
    print("\n  --- bluekeys.keys ---")

    # -- createdb --
    c.assert_ok("keys: createdb creates file", lambda: bk.createdb(PWD, keys_db))
    c.assert_true("keys: file exists", lambda: keys_db.exists())
    c.assert_raise("keys: createdb refuses .purple extension",
                   crx.KeyxError, lambda: bk.createdb(PWD, tmp / "x.purple"))
    c.assert_raise("keys: createdb refuses .ckeys extension",
                   crx.KeyxError, lambda: bk.createdb(PWD, tmp / "x.ckeys"))

    # -- verify --
    c.assert_true("keys: verify True", lambda: bk.verify(PWD, keys_db) is True)
    c.assert_true("keys: verify False", lambda: bk.verify("wrong", keys_db) is False)

    # -- open + session --
    c.assert_raise("keys: open WrongPasswordError",
                   crx.WrongPasswordError, lambda: bk.open("wrong", keys_db))

    with bk.open(PWD, keys_db) as s:
        c.assert_eq("keys: empty len == 0", lambda: len(s), 0)

        s.add("alice", alice["gpubkey"], bob["gpubkey"], alice["xprivkey"])
        s.add("bob", bob["gpubkey"], alice["gpubkey"], bob["yprivkey"])

        c.assert_eq("keys: len after 2 adds", lambda: len(s), 2)
        c.assert_true("keys: __contains__", lambda: "alice" in s)
        c.assert_eq("keys: listallnames sorted",
                    lambda: s.listallnames(), ["alice", "bob"])

        # -- get --
        e = s.get("alice")
        c.assert_eq("keys: get returns 3-field dict",
                    lambda: set(e.keys()), {"mygpubkey", "hgpubkey", "privkey"})
        c.assert_eq("keys: get mygpubkey value",
                    lambda: e["mygpubkey"], alice["gpubkey"])
        c.assert_eq("keys: get privkey value",
                    lambda: e["privkey"], alice["xprivkey"])

        # -- get returns independent copy --
        e["mygpubkey"] = "tampered"
        c.assert_true("keys: get returns independent copy",
                      lambda: s.get("alice")["mygpubkey"] == alice["gpubkey"])

        # -- add validations --
        c.assert_raise("keys: add duplicate raises KeyNameError",
                       crx.KeyNameError,
                       lambda: s.add("alice", "a", "b", "c"))
        c.assert_raise("keys: add empty name raises KeyNameError",
                       crx.KeyNameError, lambda: s.add("", "a", "b", "c"))
        c.assert_raise("keys: add empty privkey raises KeyxError",
                       crx.KeyxError,
                       lambda: s.add("x", alice["gpubkey"], bob["gpubkey"], ""))
        c.assert_raise("keys: add non-str raises ArgumentTypeError",
                       crx.ArgumentTypeError,
                       lambda: s.add("x", 42, bob["gpubkey"], alice["xprivkey"]))

        # -- update partial --
        s.update("alice", privkey=alice["yprivkey"])
        c.assert_eq("keys: update only privkey changes that field",
                    lambda: s.get("alice")["privkey"], alice["yprivkey"])
        c.assert_eq("keys: update preserves mygpubkey",
                    lambda: s.get("alice")["mygpubkey"], alice["gpubkey"])
        c.assert_raise("keys: update unknown raises KeyNameError",
                       crx.KeyNameError, lambda: s.update("ghost", privkey="x"))
        c.assert_raise("keys: update empty value raises KeyxError",
                       crx.KeyxError, lambda: s.update("alice", privkey=""))

        # -- rename --
        s.rename("bob", "bobby")
        c.assert_true("keys: rename works",
                      lambda: "bobby" in s and "bob" not in s)
        c.assert_raise("keys: rename to existing raises",
                       crx.KeyNameError, lambda: s.rename("alice", "bobby"))

        # -- delete --
        s.delete("bobby")
        c.assert_eq("keys: delete removes entry", lambda: len(s), 1)

        # -- search --
        c.assert_true("keys: search 'ali' finds alice",
                      lambda: "alice" in s.search("ali"))

        # -- backup --
        bkp = tmp / "backup.keys"
        s.backup(bkp)
        c.assert_true("keys: backup created", lambda: bkp.exists())

    # -- persistence --
    with bk.open(PWD, keys_db) as s2:
        c.assert_true("keys: data persists",
                      lambda: s2.get("alice")["privkey"] == alice["yprivkey"])

    # -- abandon on exception --
    try:
        with bk.open(PWD, keys_db) as s3:
            s3.add("temp", alice["gpubkey"], bob["gpubkey"], alice["xprivkey"])
            raise RuntimeError("abort")
    except RuntimeError:
        pass
    with bk.open(PWD, keys_db) as s3b:
        c.assert_true("keys: exception aborts commit", lambda: "temp" not in s3b)

    # -- changepwd --
    with bk.open(PWD, keys_db) as s4:
        s4.changepwd(PWD, "new-pwd")
    c.assert_raise("keys: old pwd rejected",
                   crx.WrongPasswordError, lambda: bk.open(PWD, keys_db))
    with bk.open("new-pwd", keys_db) as s4b:
        c.ok("keys: new pwd accepted")
        s4b.changepwd("new-pwd", PWD)

    # -- destroy --
    target = tmp / "doomed.keys"
    bk.createdb(PWD, target)
    bk.destroy(PWD, target)
    c.assert_true("keys: destroy removes file", lambda: not target.exists())

    # ===================== bluekeys.ckeys =====================
    print("\n  --- bluekeys.ckeys ---")

    c.assert_ok("ckeys: createdb creates file", lambda: ck.createdb(PWD, ckeys_db))

    with ck.open(PWD, ckeys_db) as s:
        s.add("alice", alice["gpubkey"], bob["gpubkey"], alice["yprivkey"])
        e = s.get("alice")
        c.assert_eq("ckeys: schema uses cprivkey",
                    lambda: set(e.keys()), {"mygpubkey", "hgpubkey", "cprivkey"})
        c.assert_eq("ckeys: cprivkey value",
                    lambda: e["cprivkey"], alice["yprivkey"])

        s.update("alice", cprivkey=alice["xprivkey"])
        c.assert_eq("ckeys: update cprivkey works",
                    lambda: s.get("alice")["cprivkey"], alice["xprivkey"])

        c.assert_raise("ckeys: add empty cprivkey raises",
                       crx.KeyxError,
                       lambda: s.add("x", alice["gpubkey"], bob["gpubkey"], ""))

    with ck.open(PWD, ckeys_db) as s2:
        c.assert_true("ckeys: data persists",
                      lambda: s2.get("alice")["cprivkey"] == alice["xprivkey"])

    # ===================== Cross-module discrimination =====================
    print("\n  --- cross-module discrimination ---")

    pk_db = tmp / "p.purple"
    crx.keyx.purplekeys.createdb(PWD, pk_db)

    # -- extension-level --
    c.assert_raise("purplekeys rejects .keys extension",
                   crx.KeyxError,
                   lambda: crx.keyx.purplekeys.open(PWD, keys_db))
    c.assert_raise("keys rejects .purple extension",
                   crx.KeyxError,
                   lambda: bk.open(PWD, pk_db))
    c.assert_raise("keys rejects .ckeys extension",
                   crx.KeyxError,
                   lambda: bk.open(PWD, ckeys_db))
    c.assert_raise("ckeys rejects .keys extension",
                   crx.KeyxError,
                   lambda: ck.open(PWD, keys_db))

    # -- magic-level (spoofed extension) --
    spoof = tmp / "spoof.keys"
    shutil.copy(ckeys_db, spoof)
    c.assert_raise("keys rejects spoofed .ckeys-as-.keys (magic mismatch)",
                   crx.KeyxError,
                   lambda: bk.open(PWD, spoof))

    spoof2 = tmp / "spoof.purple"
    shutil.copy(keys_db, spoof2)
    c.assert_raise("purplekeys rejects spoofed .keys-as-.purple (magic mismatch)",
                   crx.KeyxError,
                   lambda: crx.keyx.purplekeys.open(PWD, spoof2))

    # ===================== Levels (v3.0.0+) =====================
    print("\n  --- levels (v3.0.0+) ---")

    # -- bluekeys.keys: createdb at each level + getlevel --
    for lvl in ("low", "normal", "strong", "extreme"):
        lvl_db = tmp / f"keys_lvl_{lvl}.keys"
        bk.createdb(PWD, lvl_db, level=lvl)
        with bk.open(PWD, lvl_db) as s:
            c.assert_eq(f"keys createdb(level={lvl}) -> session.getlevel()",
                        lambda s=s, lvl=lvl: s.getlevel(), lvl)

    # -- bluekeys.keys: default level is "strong" --
    def_keys = tmp / "default.keys"
    bk.createdb(PWD, def_keys)
    with bk.open(PWD, def_keys) as s:
        c.assert_eq("keys default createdb level is 'strong'",
                    lambda: s.getlevel(), "strong")

    # -- bluekeys.keys: changelevel persists --
    cl_keys = tmp / "cl.keys"
    bk.createdb(PWD, cl_keys, level="normal")
    with bk.open(PWD, cl_keys) as s:
        s.add("alice", alice["gpubkey"], bob["gpubkey"], alice["xprivkey"])
        s.changelevel("extreme")
    with bk.open(PWD, cl_keys) as s2:
        c.assert_eq("keys changelevel persists after re-open",
                    lambda: s2.getlevel(), "extreme")
        c.assert_eq("keys changelevel preserves entries",
                    lambda: s2.get("alice")["privkey"], alice["xprivkey"])

    # -- bluekeys.keys: changelevel bad input --
    cl_bad = tmp / "cl_bad.keys"
    bk.createdb(PWD, cl_bad)
    with bk.open(PWD, cl_bad) as s:
        c.assert_raise("keys changelevel to unknown raises KeyxError",
                       crx.KeyxError,
                       lambda s=s: s.changelevel("godlike"))
        c.assert_raise("keys changelevel non-str raises ArgumentTypeError",
                       crx.ArgumentTypeError,
                       lambda s=s: s.changelevel(7))

    # -- bluekeys.keys: createdb invalid level --
    c.assert_raise("keys createdb with unknown level raises KeyxError",
                   crx.KeyxError,
                   lambda: bk.createdb(PWD, tmp / "bad.keys", level="godlike"))
    c.assert_raise("keys createdb non-str level raises ArgumentTypeError",
                   crx.ArgumentTypeError,
                   lambda: bk.createdb(PWD, tmp / "bad2.keys", level=2))

    # -- bluekeys.ckeys: createdb at each level + getlevel --
    for lvl in ("low", "normal", "strong", "extreme"):
        lvl_db = tmp / f"ckeys_lvl_{lvl}.ckeys"
        ck.createdb(PWD, lvl_db, level=lvl)
        with ck.open(PWD, lvl_db) as s:
            c.assert_eq(f"ckeys createdb(level={lvl}) -> session.getlevel()",
                        lambda s=s, lvl=lvl: s.getlevel(), lvl)

    # -- bluekeys.ckeys: default level is "strong" --
    def_ck = tmp / "default.ckeys"
    ck.createdb(PWD, def_ck)
    with ck.open(PWD, def_ck) as s:
        c.assert_eq("ckeys default createdb level is 'strong'",
                    lambda: s.getlevel(), "strong")

    # -- bluekeys.ckeys: changelevel persists --
    cl_ck = tmp / "cl.ckeys"
    ck.createdb(PWD, cl_ck, level="low")
    with ck.open(PWD, cl_ck) as s:
        s.add("alice", alice["gpubkey"], bob["gpubkey"], alice["yprivkey"])
        s.changelevel("strong")
    with ck.open(PWD, cl_ck) as s2:
        c.assert_eq("ckeys changelevel persists after re-open",
                    lambda: s2.getlevel(), "strong")
        c.assert_eq("ckeys changelevel preserves entries",
                    lambda: s2.get("alice")["cprivkey"], alice["yprivkey"])

    # -- bluekeys.ckeys: changelevel bad input --
    cl_ck_bad = tmp / "cl_bad.ckeys"
    ck.createdb(PWD, cl_ck_bad)
    with ck.open(PWD, cl_ck_bad) as s:
        c.assert_raise("ckeys changelevel to unknown raises KeyxError",
                       crx.KeyxError,
                       lambda s=s: s.changelevel("hyperstrong"))

    # -- bluekeys.ckeys: createdb invalid level --
    c.assert_raise("ckeys createdb with unknown level raises KeyxError",
                   crx.KeyxError,
                   lambda: ck.createdb(PWD, tmp / "bad.ckeys", level="hyperstrong"))

    # ===================== End-to-end with BLUE =====================
    print("\n  --- end-to-end with BLUE ---")

    e2e_keys = tmp / "e2e.keys"
    bk.createdb(PWD, e2e_keys)
    blue_keys = crx.blue.genkeys("1")

    with bk.open(PWD, e2e_keys) as s:
        s.add("channel", blue_keys["gpubkey"], bob["gpubkey"], blue_keys["xprivkey"])

    with bk.open(PWD, e2e_keys) as s:
        entry = s.get("channel")
        bundle = crx.blue.encrypt("1", entry["mygpubkey"],
                                  xmsg="stored key works", ymsg="decoy")
        pt = crx.blue.decrypt("1", entry["privkey"], bundle)
        c.assert_eq("stored key encrypts/decrypts correctly",
                    lambda: pt, "stored key works")

    shutil.rmtree(tmp, ignore_errors=True)

    p, f = c.summary()
    print(f"\n  bluekeys: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_bluekeys()
    sys.exit(0 if f == 0 else 1)
