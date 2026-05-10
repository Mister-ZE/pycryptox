"""
Keyx BLUE critical keys:
Encrypted store for BLUE critical channel records, sealed in a `.purple`
file with the PURPLE protocol. Each entry is a (name, channel) pair where
channel is `{mygpubkey, hgpubkey, cprivkey}`. Same shape as `bluekeys.keys`
but with a distinct file format so the two stores cannot be opened
interchangeably. The store is opened as a session via `open()` and
operations stay in memory until session close.
"""


# Imports:
from typing import Any
import os
import builtins
from pathlib import Path
from ..._exceptions._exceptions import *
from ..._colorx import purple
from rapidfuzz import process
from . import _common


# Functions:
_MAGIC = b"CRXKX_BLUECKEY_1"
_REQUIRED_EXTENSION = ".ckeys"
_FORMAT_TAG = "cryptox-keyx-bluekeys-c"
_FORMAT_VERSION = 1
_REQUIRED_FIELDS = frozenset({"mygpubkey", "hgpubkey", "cprivkey"})


def _validate_entry(entry: dict[str, str]) -> None:
    if set(entry.keys()) != _REQUIRED_FIELDS:
        raise KeystoreError("entry must have fields: mygpubkey, hgpubkey, cprivkey")
    for k, v in entry.items():
        if not isinstance(v, str):
            raise ArgumentTypeError(k, type(v))
        if v == "":
            raise KeystoreError(f"field '{k}' must not be empty")


# Classes:
class _CKeysSession:
    def __init__(self, password: str, dbpath: Path, entries: dict[str, dict[str, str]]) -> None:
        self._password = password
        self._dbpath = dbpath
        self._entries = {k: dict(v) for k, v in entries.items()}
        self._dirty = False
        self._closed = False

    def __enter__(self) -> "_CKeysSession":
        self._check_open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close(commit=(exc_type is None))

    def __contains__(self, name: object) -> bool:
        self._check_open()
        return isinstance(name, str) and name in self._entries

    def __len__(self) -> int:
        self._check_open()
        return len(self._entries)

    def listallnames(self) -> list[str]:
        """Return all names sorted."""
        self._check_open()
        return sorted(self._entries.keys())

    def search(self, keyword: str, maxlen: int = 20) -> list[str]:
        """Fuzzy search on names. Returns up to `maxlen` matches by relevance."""
        self._check_open()
        if not isinstance(keyword, str):
            raise ArgumentTypeError("keyword", type(keyword))
        if not isinstance(maxlen, int) or maxlen <= 0:
            raise ArgumentTypeError("maxlen", type(maxlen))
        if not keyword:
            return sorted(self._entries.keys())[:maxlen]
        candidates = list(self._entries.keys())
        if not candidates:
            return []
        results = process.extract(keyword, candidates, scorer=_common._fuzzy_score, limit=maxlen)
        return [name for name, score, _ in results if score > 0]

    def exists(self, name: str) -> bool:
        """Return True if `name` exists."""
        self._check_open()
        return name in self._entries

    def get(self, name: str) -> dict[str, str]:
        """Return the entry for `name` as a dict with `mygpubkey`, `hgpubkey`, `cprivkey`."""
        self._check_open()
        if name not in self._entries:
            raise KeyNameError(f"no entry named '{name}'")
        return dict(self._entries[name])

    def getdb(self) -> dict[str, dict[str, str]]:
        """Return a copy of all entries."""
        self._check_open()
        return {k: dict(v) for k, v in self._entries.items()}

    def add(self, name: str, mygpubkey: str, hgpubkey: str, cprivkey: str) -> None:
        """Add a new entry."""
        self._check_open()
        if not isinstance(name, str):
            raise ArgumentTypeError("name", type(name))
        if name == "":
            raise KeyNameError("name must not be empty")
        if name in self._entries:
            raise KeyNameError(f"entry '{name}' already exists")
        entry = {"mygpubkey": mygpubkey, "hgpubkey": hgpubkey, "cprivkey": cprivkey}
        _validate_entry(entry)
        self._entries[name] = entry
        self._dirty = True

    def update(
        self,
        name: str,
        mygpubkey: str | None = None,
        hgpubkey: str | None = None,
        cprivkey: str | None = None,
    ) -> None:
        """Update fields of `name`. Only fields passed (non-None) are changed."""
        self._check_open()
        if name not in self._entries:
            raise KeyNameError(f"no entry named '{name}'")
        if mygpubkey is None and hgpubkey is None and cprivkey is None:
            return
        entry = dict(self._entries[name])
        if mygpubkey is not None:
            entry["mygpubkey"] = mygpubkey
        if hgpubkey is not None:
            entry["hgpubkey"] = hgpubkey
        if cprivkey is not None:
            entry["cprivkey"] = cprivkey
        _validate_entry(entry)
        self._entries[name] = entry
        self._dirty = True

    def rename(self, old_name: str, new_name: str) -> None:
        """Rename `old_name` to `new_name`."""
        self._check_open()
        if not isinstance(new_name, str):
            raise ArgumentTypeError("new_name", type(new_name))
        if new_name == "":
            raise KeyNameError("new_name must not be empty")
        if old_name not in self._entries:
            raise KeyNameError(f"no entry named '{old_name}'")
        if new_name == old_name:
            return
        if new_name in self._entries:
            raise KeyNameError(f"entry '{new_name}' already exists")
        self._entries[new_name] = self._entries.pop(old_name)
        self._dirty = True

    def delete(self, name: str) -> None:
        """Delete the entry `name`."""
        self._check_open()
        if name not in self._entries:
            raise KeyNameError(f"no entry named '{name}'")
        del self._entries[name]
        self._dirty = True

    def changepwd(self, old_password: str, new_password: str) -> None:
        """Change the master password."""
        self._check_open()
        if not isinstance(old_password, str):
            raise ArgumentTypeError("old_password", type(old_password))
        if not isinstance(new_password, str):
            raise ArgumentTypeError("new_password", type(new_password))
        if old_password != self._password:
            raise WrongPasswordError("old password does not match")
        self._password = new_password
        self._dirty = True

    def backup(self, target_path: str | os.PathLike) -> None:
        """Write a copy of the encrypted store to `target_path`."""
        self._check_open()
        target = Path(target_path)
        _common._validate_extension(target, _REQUIRED_EXTENSION)
        head_ct = _common._make_head(self._password)
        payload_ct = _common._make_payload(self._password, self._entries, _FORMAT_TAG, _FORMAT_VERSION)
        _common._write_layout(target, _MAGIC, head_ct, payload_ct)

    def close(self, commit: bool = True) -> None:
        """Close the session. Flush pending changes if `commit=True`."""
        if self._closed:
            return
        try:
            if commit and self._dirty:
                head_ct = _common._make_head(self._password)
                payload_ct = _common._make_payload(self._password, self._entries, _FORMAT_TAG, _FORMAT_VERSION)
                _common._write_layout(self._dbpath, _MAGIC, head_ct, payload_ct)
                self._dirty = False
        finally:
            self._password = ""
            self._entries.clear()
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise KeystoreError("session is closed")


# -- Main functions: --
__all__ = [
    "createdb",
    "destroy",
    "verify",
    "open",
]


def createdb(password: str, dbpath: str | os.PathLike) -> None:
    """Create a new empty keystore at `dbpath`, encrypted with `password`."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _common._validate_extension(dbpath, _REQUIRED_EXTENSION)
    if dbpath.exists():
        raise KeystoreError(f"database already exists at '{dbpath}'")
    head_ct = _common._make_head(password)
    payload_ct = _common._make_payload(password, {}, _FORMAT_TAG, _FORMAT_VERSION)
    _common._write_layout(dbpath, _MAGIC, head_ct, payload_ct)


def destroy(password: str, dbpath: str | os.PathLike, passwordrequired: bool = True) -> None:
    """Destroy the keystore at `dbpath`.\n
    By default verifies `password` first. Set `passwordrequired=False`\n
    to delete unconditionally (useful for corrupted stores).\n
    NOTE: on SSDs, overwriting before deletion is best-effort only due\n
    to wear leveling. For absolute deletion, use platform tools."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _common._validate_extension(dbpath, _REQUIRED_EXTENSION)
    if not dbpath.exists():
        raise KeystoreError(f"database not found at '{dbpath}'")
    if passwordrequired:
        head_ct, _ = _common._read_layout(dbpath, _MAGIC)
        try:
            purple.decrypt(_common._PURPLE_VERSION, password, head_ct)
        except DecryptionError:
            raise WrongPasswordError("password does not match")
    try:
        size = dbpath.stat().st_size
        with builtins.open(dbpath, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    os.unlink(dbpath)


def verify(password: str, dbpath: str | os.PathLike) -> bool:
    """Return True if `password` decrypts the keystore head."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _common._validate_extension(dbpath, _REQUIRED_EXTENSION)
    head_ct, _ = _common._read_layout(dbpath, _MAGIC)
    try:
        purple.decrypt(_common._PURPLE_VERSION, password, head_ct)
    except DecryptionError:
        return False
    return True


def open(password: str, dbpath: str | os.PathLike) -> _CKeysSession:
    """Open a keystore session. Use as a context manager:\n
    ```python
    with crx.keyx.bluekeys.ckeys.open(password, dbpath) as s:
        s.add("alice", mygpubkey, hgpubkey, cprivkey)
    ```
    Raises `WrongPasswordError` on wrong password."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _common._validate_extension(dbpath, _REQUIRED_EXTENSION)
    head_ct, payload_ct = _common._read_layout(dbpath, _MAGIC)
    try:
        purple.decrypt(_common._PURPLE_VERSION, password, head_ct)
    except DecryptionError:
        raise WrongPasswordError("password does not match")
    try:
        payload_str = purple.decrypt(_common._PURPLE_VERSION, password, payload_ct)
    except DecryptionError:
        raise KeystoreError("payload corrupted or tampered")
    entries = _common._parse_payload(payload_str, _FORMAT_TAG, _REQUIRED_FIELDS)
    return _CKeysSession(password, dbpath, entries)