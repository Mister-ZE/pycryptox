"""Tests for keyx.purplekeys (encrypted name/key storage)."""

import sys
import shutil
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_purplekeys() -> tuple[int, int]:
    print("=" * 60)
    print("keyx.purplekeys")
    print("=" * 60)
    c = Counter()

    tmp = Path(tempfile.mkdtemp(prefix="pk_"))
    db = tmp / "store.purple"
    PWD = "master-pass"
    pk = crx.keyx.purplekeys

    # -- createdb --
    c.assert_ok("createdb creates file", lambda: pk.createdb(PWD, db))
    c.assert_true("file exists after createdb", lambda: db.exists())
    c.assert_raise("createdb refuses existing path",
                   crx.KeystoreError, lambda: pk.createdb(PWD, db))
    c.assert_raise("createdb refuses bad extension",
                   crx.KeystoreError, lambda: pk.createdb(PWD, tmp / "x.txt"))
    c.assert_raise("createdb refuses non-str password",
                   crx.ArgumentTypeError, lambda: pk.createdb(123, tmp / "x.purple"))

    nested = tmp / "deep" / "store.purple"
    c.assert_ok("createdb auto-creates parent dirs", lambda: pk.createdb(PWD, nested))

    # -- verify --
    c.assert_true("verify True with correct password",
                  lambda: pk.verify(PWD, db) is True)
    c.assert_true("verify False with wrong password",
                  lambda: pk.verify("wrong", db) is False)
    c.assert_raise("verify raises on missing file",
                   crx.KeystoreError, lambda: pk.verify(PWD, tmp / "ghost.purple"))

    # -- open --
    c.assert_raise("open raises WrongPasswordError",
                   crx.WrongPasswordError, lambda: pk.open("wrong", db))
    c.assert_raise("open refuses non-str password",
                   crx.ArgumentTypeError, lambda: pk.open(123, db))

    # -- session: add / getkey / exists / len / listallnames --
    with pk.open(PWD, db) as s:
        c.assert_eq("empty session: len == 0", lambda: len(s), 0)
        s.add("gmail", "GmailPass-42")
        s.add("bank", "v3rySafe!")
        s.add("netflix", "NflxStream")
        c.assert_eq("len after 3 adds", lambda: len(s), 3)
        c.assert_eq("getkey returns stored value",
                    lambda: s.getkey("gmail"), "GmailPass-42")
        c.assert_true("__contains__ true for present", lambda: "gmail" in s)
        c.assert_true("__contains__ false for missing", lambda: "ghost" not in s)
        c.assert_true("exists works", lambda: s.exists("bank"))
        c.assert_eq("listallnames sorted",
                    lambda: s.listallnames(), ["bank", "gmail", "netflix"])

        # -- add validations --
        c.assert_raise("add duplicate raises KeyNameError",
                       crx.KeyNameError, lambda: s.add("gmail", "x"))
        c.assert_raise("add empty name raises KeyNameError",
                       crx.KeyNameError, lambda: s.add("", "x"))
        c.assert_raise("add non-str name raises ArgumentTypeError",
                       crx.ArgumentTypeError, lambda: s.add(42, "x"))
        c.assert_raise("add non-str key raises ArgumentTypeError",
                       crx.ArgumentTypeError, lambda: s.add("foo", 42))

        # -- getkey unknown --
        c.assert_raise("getkey unknown raises KeyNameError",
                       crx.KeyNameError, lambda: s.getkey("ghost"))

        # -- search --
        c.assert_eq("search 'gma' finds gmail", lambda: s.search("gma"), ["gmail"])
        c.assert_eq("search 'xyz' returns []", lambda: s.search("xyz"), [])

        # -- update --
        s.update("gmail", "newpass-2025")
        c.assert_eq("update changes value",
                    lambda: s.getkey("gmail"), "newpass-2025")
        c.assert_raise("update unknown raises KeyNameError",
                       crx.KeyNameError, lambda: s.update("ghost", "x"))

        # -- rename --
        s.rename("netflix", "nflx")
        c.assert_true("rename: new present, old absent",
                      lambda: "nflx" in s and "netflix" not in s)
        c.assert_raise("rename to existing raises KeyNameError",
                       crx.KeyNameError, lambda: s.rename("nflx", "bank"))
        c.assert_raise("rename to empty raises KeyNameError",
                       crx.KeyNameError, lambda: s.rename("nflx", ""))
        s.rename("nflx", "nflx")
        c.ok("rename to same name is no-op")

        # -- delete --
        s.delete("nflx")
        c.assert_true("delete removes entry",
                      lambda: "nflx" not in s and len(s) == 2)
        c.assert_raise("delete unknown raises KeyNameError",
                       crx.KeyNameError, lambda: s.delete("ghost"))

        # -- getdb --
        d = s.getdb()
        c.assert_true("getdb returns expected entries",
                      lambda: d == {"gmail": "newpass-2025", "bank": "v3rySafe!"})
        d["mutation"] = "x"
        c.assert_true("getdb returns independent copy",
                      lambda: "mutation" not in s)

        # -- backup --
        bkp = tmp / "backup.purple"
        s.backup(bkp)
        c.assert_true("backup file created", lambda: bkp.exists())

    # -- backup readable --
    with pk.open(PWD, bkp) as sb:
        c.assert_eq("backup readable with same password",
                    lambda: sb.getkey("gmail"), "newpass-2025")

    # -- persistence --
    with pk.open(PWD, db) as s2:
        c.assert_eq("data persists across sessions",
                    lambda: s2.getkey("gmail"), "newpass-2025")

    # -- abandon on exception --
    try:
        with pk.open(PWD, db) as s3:
            s3.add("temp", "x")
            raise RuntimeError("abort")
    except RuntimeError:
        pass
    with pk.open(PWD, db) as s3b:
        c.assert_true("exception aborts commit", lambda: "temp" not in s3b)

    # -- closed session --
    sc = pk.open(PWD, db)
    sc.close()
    c.assert_raise("closed session: getkey raises",
                   crx.KeystoreError, lambda: sc.getkey("gmail"))
    try:
        sc.close()
        c.ok("close() is idempotent")
    except Exception as e:
        c.fail("close() is idempotent", f"{type(e).__name__}: {e}")

    # -- changepwd --
    with pk.open(PWD, db) as s4:
        s4.changepwd(PWD, "new-pwd")
    c.assert_raise("old password rejected after changepwd",
                   crx.WrongPasswordError, lambda: pk.open(PWD, db))
    with pk.open("new-pwd", db) as s4b:
        c.ok("new password accepted")
        s4b.changepwd("new-pwd", PWD)

    # -- destroy --
    target = tmp / "doomed.purple"
    pk.createdb(PWD, target)
    c.assert_raise("destroy with wrong password raises",
                   crx.WrongPasswordError, lambda: pk.destroy("nope", target))
    c.assert_true("file still exists after wrong password", lambda: target.exists())
    pk.destroy(PWD, target)
    c.assert_true("destroy removes file", lambda: not target.exists())

    pk.createdb(PWD, target)
    pk.destroy("anything", target, passwordrequired=False)
    c.assert_true("force destroy removes file", lambda: not target.exists())

    # -- unicode names --
    pk.createdb(PWD, tmp / "uni.purple")
    with pk.open(PWD, tmp / "uni.purple") as su:
        su.add("café", "k1")
        su.add("日本語", "k2")
        su.add("emoji-🔑", "k3")
    with pk.open(PWD, tmp / "uni.purple") as su2:
        c.assert_eq("unicode name persists", lambda: su2.getkey("café"), "k1")
        c.assert_eq("japanese name persists", lambda: su2.getkey("日本語"), "k2")
        c.assert_eq("emoji name persists", lambda: su2.getkey("emoji-🔑"), "k3")

    shutil.rmtree(tmp, ignore_errors=True)

    p, f = c.summary()
    print(f"\n  purplekeys: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_purplekeys()
    sys.exit(0 if f == 0 else 1)
