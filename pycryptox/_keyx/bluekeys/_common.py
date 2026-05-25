"""
Shared internals for keyx.bluekeys.keys and keyx.bluekeys.ckeys.
Not part of the public API.
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
from ..._exceptions._exceptions import *
from ..._colorx import purple


# Functions:
_HEAD_RANDOM_SIZE = 64
_PURPLE_VERSION = "2"
_DEFAULT_LEVEL = "strong"


def _validate_extension(dbpath: Path, expected_ext: str) -> None:
    if dbpath.suffix != expected_ext:
        raise KeyxError(f"path must end with '{expected_ext}'")


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


def _read_layout(dbpath: Path, expected_magic: bytes) -> tuple[str, str]:
    if not dbpath.exists():
        raise KeyxError(f"database not found at '{dbpath}'")
    with builtins.open(dbpath, "rb") as f:
        data = f.read()
    if len(data) < 20 or data[:16] != expected_magic:
        raise KeyxError("invalid or corrupted database")
    head_len = struct.unpack(">I", data[16:20])[0]
    if 20 + head_len > len(data):
        raise KeyxError("invalid or corrupted database")
    head_ct = data[20:20 + head_len].decode("ascii")
    payload_ct = data[20 + head_len:].decode("ascii")
    return head_ct, payload_ct


def _write_layout(dbpath: Path, magic: bytes, head_ct: str, payload_ct: str) -> None:
    head_bytes = head_ct.encode("ascii")
    payload_bytes = payload_ct.encode("ascii")
    if len(head_bytes) > 0xFFFFFFFF:
        raise KeyxError("head too large")
    data = magic + struct.pack(">I", len(head_bytes)) + head_bytes + payload_bytes
    _atomic_write(dbpath, data)


def _make_head(password: str, level: str = _DEFAULT_LEVEL) -> str:
    return purple.encrypt(_PURPLE_VERSION, password, secrets.token_urlsafe(_HEAD_RANDOM_SIZE), level=level)


def _make_payload(
    password: str,
    entries: dict[str, dict[str, str]],
    format_tag: str,
    format_version: int,
    level: str = _DEFAULT_LEVEL,
) -> str:
    obj = {"format": format_tag, "version": format_version, "entries": entries}
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
    """Read the encryption level from an opened keyx head bundle.\n
    The head_ct is expected to be a PURPLE v2.0+ bundle; call
    `_check_keyx_purple_version` first."""
    return purple.getlevel(head_ct)


def _parse_payload(
    payload_str: str,
    format_tag: str,
    required_fields: frozenset[str],
) -> dict[str, dict[str, str]]:
    try:
        obj = json.loads(payload_str)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise KeyxError("corrupted payload")
    if not isinstance(obj, dict) or obj.get("format") != format_tag:
        raise KeyxError("corrupted payload")
    entries = obj.get("entries")
    if not isinstance(entries, dict):
        raise KeyxError("corrupted payload")
    for k, v in entries.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            raise KeyxError("corrupted payload")
        if set(v.keys()) != required_fields:
            raise KeyxError("corrupted payload")
        if not all(isinstance(x, str) for x in v.values()):
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