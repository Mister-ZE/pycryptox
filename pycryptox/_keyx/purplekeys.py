"""
Keyx PURPLE keys:
Encrypted store for arbitrary string secrets, sealed
in a `.purple` file with the PURPLE protocol. Each
entry is a (name, key) string pair. The store is
opened as a session via `open()` and operations stay
in memory until session close.
"""


# Imports:
from typing import Any
import os
import json
import secrets
import struct
import tempfile
import builtins
from pathlib import Path
from .._exceptions._exceptions import *
from .._colorx import purple
from rapidfuzz import process


# Functions:
_MAGIC = b"CRXKX_PURPLE_V1\x00"
_HEAD_RANDOM_SIZE = 64
_REQUIRED_EXTENSION = ".purple"
_FORMAT_TAG = "cryptox-keyx-purple"
_FORMAT_VERSION = 1
_PURPLE_VERSION = "2"
_DEFAULT_LEVEL = "strong"


def _validate_extension(dbpath: Path) -> None:
    if dbpath.suffix != _REQUIRED_EXTENSION:
        raise KeyxError(f"path must end with '{_REQUIRED_EXTENSION}'")


def _atomic_write(dbpath: Path, data: bytes) -> None:
    dbpath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{dbpath.name}.", suffix=".tmp", dir=str(dbpath.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dbpath)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_layout(dbpath: Path) -> tuple[str, str]:
    if not dbpath.exists():
        raise KeyxError(f"database not found at '{dbpath}'")
    with builtins.open(dbpath, "rb") as f:
        data = f.read()
    if len(data) < 20 or data[:16] != _MAGIC:
        raise KeyxError("invalid or corrupted database")
    head_len = struct.unpack(">I", data[16:20])[0]
    if 20 + head_len > len(data):
        raise KeyxError("invalid or corrupted database")
    head_ct = data[20:20 + head_len].decode("ascii")
    payload_ct = data[20 + head_len:].decode("ascii")
    return head_ct, payload_ct


def _write_layout(dbpath: Path, head_ct: str, payload_ct: str) -> None:
    head_bytes = head_ct.encode("ascii")
    payload_bytes = payload_ct.encode("ascii")
    if len(head_bytes) > 0xFFFFFFFF:
        raise KeyxError("head too large")
    data = _MAGIC + struct.pack(">I", len(head_bytes)) + head_bytes + payload_bytes
    _atomic_write(dbpath, data)


def _make_head(password: str, level: str = _DEFAULT_LEVEL) -> str:
    return purple.encrypt(_PURPLE_VERSION, password, secrets.token_urlsafe(_HEAD_RANDOM_SIZE), level=level)


def _make_payload(password: str, entries: dict[str, str], level: str = _DEFAULT_LEVEL) -> str:
    obj = {"format": _FORMAT_TAG, "version": _FORMAT_VERSION, "entries": entries}
    return purple.encrypt(_PURPLE_VERSION, password, json.dumps(obj, ensure_ascii=False, sort_keys=True), level=level)


def _check_keyx_purple_version(head_ct: str) -> None:
    """Verify the embedded PURPLE bundle is at the version this build supports.\n
    Raises `KeyxError` with a clear message if the bundle is from an older
    pycryptox release (hard break in 3.0.0)."""
    try:
        head_version = purple.getversion(head_ct)
    except DecryptionError:
        raise KeyxError("corrupted head bundle")
    if not head_version.startswith(_PURPLE_VERSION + "."):
        raise KeyxError(
            f"unsupported keyx PURPLE version v{head_version}; "
            f"this build expects v{_PURPLE_VERSION}.x (created by pycryptox 3.0.0+)"
        )


def _read_level(head_ct: str) -> str:
    """Read the encryption level from an opened keyx head bundle."""
    return purple.getlevel(head_ct)


def _parse_payload(payload_str: str) -> dict[str, str]:
    try:
        obj = json.loads(payload_str)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise KeyxError("corrupted payload")
    if not isinstance(obj, dict) or obj.get("format") != _FORMAT_TAG:
        raise KeyxError("corrupted payload")
    entries = obj.get("entries")
    if not isinstance(entries, dict):
        raise KeyxError("corrupted payload")
    for k, v in entries.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise KeyxError("corrupted payload")
    return entries


def _fuzzy_score(query: str, candidate: str, **kwargs: Any) -> float:
    q = query.lower()
    c = candidate.lower()
    if not q:
        return 1.0
    positions: list[int] = []
    qi = 0
    for ci, ch in enumerate(c):
        if qi < len(q) and ch == q[qi]:
            positions.append(ci)
            qi += 1
    if qi < len(q):
        return 0.0
    score = 100.0 - len(candidate) * 0.5 - positions[0] * 2
    score += sum(5 for i in range(1, len(positions)) if positions[i] == positions[i - 1] + 1)
    for pos in positions:
        if pos == 0:
            score += 15
        elif candidate[pos - 1] in "_-. /":
            score += 10
        elif pos > 0 and candidate[pos].isupper() and candidate[pos - 1].islower():
            score += 8
    score += sum(1 for i, pos in enumerate(positions) if i < len(query) and candidate[pos] == query[i])
    if c.startswith(q):
        score += 50
    elif q in c:
        score += 25
    return max(score, 0.0)


# Classes:
class _PurpleSession:
    def __init__(self, password: str, dbpath: Path, entries: dict[str, str], level: str) -> None:
        self._password = password
        self._dbpath = dbpath
        self._entries = dict(entries)
        self._level = level
        self._dirty = False
        self._closed = False

    def __enter__(self) -> "_PurpleSession":
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
        results = process.extract(keyword, candidates, scorer=_fuzzy_score, limit=maxlen)
        return [name for name, score, _ in results if score > 0]

    def exists(self, name: str) -> bool:
        """Return True if `name` exists."""
        self._check_open()
        return name in self._entries

    def getkey(self, name: str) -> str:
        """Return the key for `name`."""
        self._check_open()
        if name not in self._entries:
            raise KeyNameError(f"no entry named '{name}'")
        return self._entries[name]

    def getdb(self) -> dict[str, str]:
        """Return a copy of all entries."""
        self._check_open()
        return dict(self._entries)

    def add(self, name: str, key: str) -> None:
        """Add a new entry."""
        self._check_open()
        if not isinstance(name, str):
            raise ArgumentTypeError("name", type(name))
        if not isinstance(key, str):
            raise ArgumentTypeError("key", type(key))
        if name == "":
            raise KeyNameError("name must not be empty")
        if name in self._entries:
            raise KeyNameError(f"entry '{name}' already exists")
        self._entries[name] = key
        self._dirty = True

    def update(self, name: str, new_key: str) -> None:
        """Replace the key for `name`."""
        self._check_open()
        if not isinstance(new_key, str):
            raise ArgumentTypeError("new_key", type(new_key))
        if name not in self._entries:
            raise KeyNameError(f"no entry named '{name}'")
        self._entries[name] = new_key
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

    def changelevel(self, new_level: str) -> None:
        """Change the Argon2id strength level for subsequent saves.\n
        Accepts `"low"`, `"normal"`, `"strong"`, `"extreme"`. Idempotent
        if `new_level` equals the current level."""
        self._check_open()
        if not isinstance(new_level, str):
            raise ArgumentTypeError("new_level", type(new_level))
        if new_level not in purple._LEVELS:
            raise KeyxError(
                f"unknown level '{new_level}', expected one of {sorted(purple._LEVELS)}"
            )
        if new_level != self._level:
            self._level = new_level
            self._dirty = True

    def getlevel(self) -> str:
        """Return the current Argon2id strength level of the session."""
        self._check_open()
        return self._level

    def backup(self, target_path: str | os.PathLike) -> None:
        """Write a copy of the encrypted store to `target_path`."""
        self._check_open()
        target = Path(target_path)
        _validate_extension(target)
        head_ct = _make_head(self._password, level=self._level)
        payload_ct = _make_payload(self._password, self._entries, level=self._level)
        _write_layout(target, head_ct, payload_ct)

    def close(self, commit: bool = True) -> None:
        """Close the session. Flush pending changes if `commit=True`."""
        if self._closed:
            return
        try:
            if commit and self._dirty:
                head_ct = _make_head(self._password, level=self._level)
                payload_ct = _make_payload(self._password, self._entries, level=self._level)
                _write_layout(self._dbpath, head_ct, payload_ct)
                self._dirty = False
        finally:
            self._password = ""
            self._entries.clear()
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise KeyxError("session is closed")


# -- Main functions: --
__all__ = [
    "createdb",
    "destroy",
    "verify",
    "open",
]


def createdb(password: str, dbpath: str | os.PathLike, level: str = "strong") -> None:
    """Create a new empty Keyx at `dbpath`, encrypted with `password` at
    Argon2id strength `level` (`"low" | "normal" | "strong" | "extreme"`)."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    if not isinstance(level, str):
        raise ArgumentTypeError("level", type(level))
    if level not in purple._LEVELS:
        raise KeyxError(
            f"unknown level '{level}', expected one of {sorted(purple._LEVELS)}"
        )
    dbpath = Path(dbpath)
    _validate_extension(dbpath)
    if dbpath.exists():
        raise KeyxError(f"database already exists at '{dbpath}'")
    head_ct = _make_head(password, level=level)
    payload_ct = _make_payload(password, {}, level=level)
    _write_layout(dbpath, head_ct, payload_ct)


def destroy(password: str, dbpath: str | os.PathLike, passwordrequired: bool = True) -> None:
    """Destroy the Keyx at `dbpath`.\n
    By default verifies `password` first. Set `passwordrequired=False`\n
    to delete unconditionally (useful for corrupted stores).\n
    NOTE: on SSDs, overwriting before deletion is best-effort only due\n
    to wear leveling. For absolute deletion, use platform tools."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _validate_extension(dbpath)
    if not dbpath.exists():
        raise KeyxError(f"database not found at '{dbpath}'")
    if passwordrequired:
        head_ct, _ = _read_layout(dbpath)
        _check_keyx_purple_version(head_ct)
        try:
            purple.decrypt(_PURPLE_VERSION, password, head_ct)
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
    """Return True if `password` decrypts the Keyx head."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _validate_extension(dbpath)
    head_ct, _ = _read_layout(dbpath)
    _check_keyx_purple_version(head_ct)
    try:
        purple.decrypt(_PURPLE_VERSION, password, head_ct)
    except DecryptionError:
        return False
    return True


def open(password: str, dbpath: str | os.PathLike) -> _PurpleSession:
    """Open a Keyx session. Use as a context manager:\n
    ```python
    with crx.keyx.purplekeys.open(password, dbpath) as s:
        s.add("name", "key")
    ```
    The session inherits the Argon2id level from the file; use
    `session.changelevel(...)` to migrate to a different level on save.\n
    Raises `WrongPasswordError` on wrong password, `KeyxError` if the
    file is from a pre-3.0.0 release (PURPLE v1.0 keyx not supported)."""
    if not isinstance(password, str):
        raise ArgumentTypeError("password", type(password))
    dbpath = Path(dbpath)
    _validate_extension(dbpath)
    head_ct, payload_ct = _read_layout(dbpath)
    _check_keyx_purple_version(head_ct)
    try:
        purple.decrypt(_PURPLE_VERSION, password, head_ct)
    except DecryptionError:
        raise WrongPasswordError("password does not match")
    try:
        payload_str = purple.decrypt(_PURPLE_VERSION, password, payload_ct)
    except DecryptionError:
        raise KeyxError("payload corrupted or tampered")
    entries = _parse_payload(payload_str)
    level = _read_level(head_ct)
    return _PurpleSession(password, dbpath, entries, level)