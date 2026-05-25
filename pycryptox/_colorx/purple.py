"""
Colorx PURPLE:
The PURPLE protocol provides password-based encryption.
Use it when you want a brain-only secret -- one that survives
total device loss, that you can recover by retyping a passphrase.
The Argon2id KDF makes brute-force attacks computationally
expensive.

Versions:
- v1.0 -- fixed Argon2id parameters (t=2, m=64 MiB, p=2). FROZEN, byte-exact
  reproduction of the 2.0.2 release. Kept for backwards-compatible decryption
  of legacy bundles. Not recommended for new encryption: below the RFC 9106
  floor, and uses broad `except Exception` clauses.
- v1.1 -- identical wire format and crypto strength as v1.0, with tightened
  exception handling (specific catches instead of a broad `except Exception`).
  Prefer this over v1.0 for new encryption at v1-equivalent strength.
- v2.0 -- adjustable Argon2id strength via `level` parameter, embedded
  in the bundle so decryption is parameter-less. Levels: "low",
  "normal", "strong", "extreme".
"""


# Imports:
from typing import Any
import os
import re
import base64
import binascii
import secrets
from .._exceptions._exceptions import *
from . import _versioning as _ver
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type


# Functions:
def _load_wordlist() -> list[str]:
    import pathlib
    words_file = pathlib.Path(__file__).parent.parent / "_assets" / "words.txt"
    with open(words_file, "r") as f:
        return [line.split("\t")[1].strip() for line in f if line.strip()]

def _derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def _derive_key_strength(password: str, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
    """Argon2id KDF with explicit strength parameters. Used by v1.1 and v2.0+.
    v1.0 must keep using `_derive_key` (frozen)."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID
    )


# -- Versions: --
# -- v0.0: --
def _encryptv0_0() -> str:
    return "I encrypt nothing now..."

def _decryptv0_0() -> str:
    return "I decrypt nothing now..."

def _genkeysv0_0() -> str:
    return "I don't want to. I can't be bothered to make a new key."

# -- v1.0 (FROZEN -- byte-exact reproduction of the 2.0.2 release): --
def _encryptv1_0(key: str, msg: str) -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    salt = os.urandom(16)
    derived_key = _derive_key(key, salt)
    
    chacha = ChaCha20Poly1305(derived_key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, msg.encode(), None)
    
    return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode()

def _decryptv1_0(key: str, msg: str) -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    try:
        raw = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")
    
    if len(raw) < 16 + 12 + 16:
        raise DecryptionError("message too short")

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    derived_key = _derive_key(key, salt)
    chacha = ChaCha20Poly1305(derived_key)

    try:
        return chacha.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        raise DecryptionError("invalid key or corrupted message")

def _genkeysv1_0() -> str:
    words = _load_wordlist()
    passphrase = " ".join(secrets.choice(words) for _ in range(6))
    return passphrase

# -- v1.1: identical wire format and crypto strength as v1.0, with
#           tightened exception handling (specific catches instead of a
#           broad `except Exception`). Prefer v1.1 over v1.0 for new
#           encryption at v1-equivalent strength. --
def _encryptv1_1(key: str, msg: str) -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    salt = os.urandom(16)
    derived_key = _derive_key_strength(key, salt, **_LEVELS["low"])

    chacha = ChaCha20Poly1305(derived_key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, msg.encode(), None)

    return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode()

def _decryptv1_1(key: str, msg: str) -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    try:
        raw = base64.urlsafe_b64decode(msg)
    except (binascii.Error, ValueError):
        raise DecryptionError("message is not valid base64")

    if len(raw) < 16 + 12 + 16:
        raise DecryptionError("message too short")

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    derived_key = _derive_key_strength(key, salt, **_LEVELS["low"])
    chacha = ChaCha20Poly1305(derived_key)

    try:
        return chacha.decrypt(nonce, ciphertext, None).decode()
    except (InvalidTag, UnicodeDecodeError):
        raise DecryptionError("invalid key or corrupted message")

def _genkeysv1_1() -> str:
    # Same passphrase generation as v1.0: 6 EFF words.
    words = _load_wordlist()
    passphrase = " ".join(secrets.choice(words) for _ in range(6))
    return passphrase

# -- v2.0: --
def _encryptv2_0(key: str, msg: str, level: str = "strong") -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    elif not isinstance(level, str):
        raise ArgumentTypeError("level", type(level))
    if level not in _LEVELS:
        raise EncryptionError(
            f"unknown level '{level}', expected one of {sorted(_LEVELS)}"
        )

    salt = os.urandom(16)
    derived_key = _derive_key_strength(key, salt, **_LEVELS[level])

    chacha = ChaCha20Poly1305(derived_key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, msg.encode(), None)

    level_byte = bytes([_LEVEL_TO_BYTE[level]])
    return base64.urlsafe_b64encode(level_byte + salt + nonce + ciphertext).decode()

def _decryptv2_0(key: str, msg: str) -> str:
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    try:
        raw = base64.urlsafe_b64decode(msg)
    except (binascii.Error, ValueError):
        raise DecryptionError("message is not valid base64")

    # Layout: 1B level | 16B salt | 12B nonce | ciphertext+tag (>=16B)
    if len(raw) < 1 + 16 + 12 + 16:
        raise DecryptionError("message too short")

    level_byte = raw[0]
    if level_byte not in _BYTE_TO_LEVEL:
        raise DecryptionError(f"invalid level byte: {level_byte}")
    level = _BYTE_TO_LEVEL[level_byte]

    salt = raw[1:17]
    nonce = raw[17:29]
    ciphertext = raw[29:]

    derived_key = _derive_key_strength(key, salt, **_LEVELS[level])
    chacha = ChaCha20Poly1305(derived_key)

    try:
        return chacha.decrypt(nonce, ciphertext, None).decode()
    except (InvalidTag, UnicodeDecodeError):
        raise DecryptionError("invalid key or corrupted message")

_GENKEYS_WORDS_BY_LEVEL = {
    "low":     6,   # ~77.5 bits  (legacy default)
    "normal":  7,   # ~90.4 bits
    "strong":  8,   # ~103.3 bits (default for v2.0+)
    "extreme": 10,  # ~129.1 bits
}


def _genkeysv2_0(level: str = "strong") -> str:
    """Generates an EFF-wordlist passphrase. The number of words scales
    with `level`: low=6, normal=7, strong=8 (default), extreme=10.\n
    Each word contributes ~12.92 bits of entropy (`log2(7776)`)."""
    if not isinstance(level, str):
        raise ArgumentTypeError("level", type(level))
    if level not in _GENKEYS_WORDS_BY_LEVEL:
        valid = ", ".join(repr(k) for k in _GENKEYS_WORDS_BY_LEVEL)
        raise EncryptionError(
            f"unknown level {level!r}; must be one of {valid}"
        )
    n_words = _GENKEYS_WORDS_BY_LEVEL[level]
    words = _load_wordlist()
    passphrase = " ".join(secrets.choice(words) for _ in range(n_words))
    return passphrase


# -- Main functions: --
__all__ = [
    "encrypt",
    "decrypt",
    "genkeys",
    "getversion",
    "getlevel",
    "update_bundle",
]

def encrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v2.0):**
    ```python
        def encrypt(
            version: str,
            key: str,
            msg: str,
            level: str = "strong"
        ) -> str
    ```
    `version` may be an exact version (e.g. `"2.0"`) or a major-only\n
    specifier (e.g. `"2"`) which resolves to the latest minor available.\n
    `level` (v2.0+) selects the Argon2id strength: `"low"`, `"normal"`,\n
    `"strong"` (default), or `"extreme"`. The level is embedded in the\n
    bundle and read automatically at decryption time.\n
    See docs for older versions."""
    actual_version = _ver._resolve_version(version, _ENCRYPT_VERSIONS)
    handler = _ENCRYPT_VERSIONS[actual_version]
    inner_b64 = handler(*args, **kwargs)
    return _ver._wrap_version_bytes(actual_version, inner_b64)


def decrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v2.0):**
    ```python
        def decrypt(
            version: str,
            key: str,
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"2.0"`) or a major-only\n
    specifier (e.g. `"2"`) which accepts any minor of that major.\n
    See docs for older versions."""
    if "msg" in kwargs:
        msg = kwargs.pop("msg")
    elif args:
        msg = args[-1]
        args = args[:-1]
    else:
        raise DecryptionError("missing 'msg' argument")

    bundle_version, inner_b64 = _ver._unwrap_version_bytes(msg, version)
    handler = _DECRYPT_VERSIONS.get(bundle_version)
    if handler is None:
        raise VersionNotFoundError(bundle_version)
    return handler(*args, msg=inner_b64, **kwargs)


def genkeys(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v2.0):**
    ```python
        def genkeys(
            version: str,
            level: str = "strong"
        ) -> str
    ```
    Returns an EFF-wordlist passphrase whose length scales with `level`:\n
    \n
    | Level | Words | Approximate entropy |\n
    |---|---|---|\n
    | `"low"` | 6 | ~77.5 bits (legacy default of v1.x) |\n
    | `"normal"` | 7 | ~90.4 bits |\n
    | `"strong"` | 8 | ~103.3 bits (**default** in v2.0+) |\n
    | `"extreme"` | 10 | ~129.1 bits |\n
    \n
    The default level in v2.0+ is `"strong"`, matching `encrypt`'s default\n
    `level` argument. For v1.0 and v1.1, the function ignores `level` and\n
    always returns a 6-word passphrase.\n
    \n
    `version` may be an exact version (e.g. `"2.0"`) or a major-only\n
    specifier (e.g. `"2"`) which resolves to the latest minor available.\n
    See docs for older versions."""
    actual_version = _ver._resolve_version(version, _GEN_KEYS_VERSIONS)
    handler = _GEN_KEYS_VERSIONS[actual_version]
    return handler(*args, **kwargs)


def getversion(msg: str) -> str:
    """Extract the protocol version from a bundle without decrypting it.\n
    Useful for routing or migration logic.\n
    Raises `DecryptionError` if the bundle is malformed."""
    return _ver._extract_version(msg)


def getlevel(msg: str) -> str:
    """Extract the encryption level from a PURPLE v2.0+ bundle without
    decrypting it.\n
    Returns one of `"low"`, `"normal"`, `"strong"`, `"extreme"`.\n
    Raises `ArgumentTypeError` if `msg` is not a `str`, or `DecryptionError`
    if the bundle is malformed, has a bad level byte, or is below v2.0
    (where the level concept does not apply)."""
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    try:
        raw = base64.urlsafe_b64decode(msg)
    except (binascii.Error, ValueError):
        raise DecryptionError("message is not valid base64")
    if len(raw) < 3:
        raise DecryptionError("message too short to contain a version and level header")
    major, minor = raw[0], raw[1]
    if major < 2:
        raise DecryptionError(
            f"bundle is v{major}.{minor}; level concept exists only for v2.0+"
        )
    level_byte = raw[2]
    if level_byte not in _BYTE_TO_LEVEL:
        raise DecryptionError(f"invalid level byte: {level_byte}")
    return _BYTE_TO_LEVEL[level_byte]


def update_bundle(
    old_to_new: str,
    key: str,
    old_msg: str,
    level: str = "strong",
    downgrade: bool = False,
) -> str:
    """Re-encrypt a PURPLE bundle from one protocol version to another.\n
    `old_to_new` is a string of the form `"A.a to B.b"` where each side is
    either an exact version (e.g. `"1.0"`) or a major-only specifier (e.g.
    `"1"`) which resolves to the latest minor available. Examples:
    `"1.0 to 2"`, `"1 to 2.0"`, `"1 to 2"`.\n
    Resolution: after both sides are resolved to canonical `"M.m"` strings,
    if they are equal the bundle is returned unchanged (no decryption or
    re-encryption is performed).\n
    With `downgrade=False` (default), a downgrade (resolved old > resolved
    new) raises `DowngradeError`. With `downgrade=True`, downgrades proceed
    silently.\n
    For v2.0+ targets, `level` selects the Argon2id strength of the new
    bundle. It is ignored when the target is below v2.0.\n
    Raises `ArgumentTypeError` on bad argument types,
    `VersionNotFoundError` if the spec is malformed or if either version
    is unknown, `DecryptionError` if the bundle does not decrypt under
    `key`, and `EncryptionError` if `level` is invalid for the target."""
    if not isinstance(old_to_new, str):
        raise ArgumentTypeError("old_to_new", type(old_to_new))
    if not isinstance(key, str):
        raise ArgumentTypeError("key", type(key))
    if not isinstance(old_msg, str):
        raise ArgumentTypeError("old_msg", type(old_msg))
    if not isinstance(level, str):
        raise ArgumentTypeError("level", type(level))
    if not isinstance(downgrade, bool):
        raise ArgumentTypeError("downgrade", type(downgrade))

    m = _OLD_TO_NEW_RE.match(old_to_new)
    if not m:
        raise VersionNotFoundError(old_to_new)

    old_spec, new_spec = m.group(1), m.group(2)

    # Resolve to canonical "M.m" strings. Each side must exist in the
    # corresponding dispatch dict, otherwise _resolve_version raises
    # VersionNotFoundError.
    old_resolved = _ver._resolve_version(old_spec, _DECRYPT_VERSIONS)
    new_resolved = _ver._resolve_version(new_spec, _ENCRYPT_VERSIONS)

    # Compare as (major, minor) tuples.
    old_t = tuple(int(x) for x in old_resolved.split("."))
    new_t = tuple(int(x) for x in new_resolved.split("."))

    # Equal -> no-op (skip decrypt/encrypt entirely).
    if old_t == new_t:
        return old_msg

    # Downgrade check.
    if old_t > new_t and not downgrade:
        raise DowngradeError(old_resolved, new_resolved)

    # Re-encrypt: decrypt with old spec, then encrypt with new spec.
    plaintext = decrypt(old_spec, key, old_msg)
    if new_t[0] >= 2:
        return encrypt(new_spec, key, plaintext, level=level)
    return encrypt(new_spec, key, plaintext)


# Constants:
_ENCRYPT_VERSIONS = {
    "0.0": _encryptv0_0,
    "1.0": _encryptv1_0,
    "1.1": _encryptv1_1,
    "2.0": _encryptv2_0,
}

_DECRYPT_VERSIONS = {
    "0.0": _decryptv0_0,
    "1.0": _decryptv1_0,
    "1.1": _decryptv1_1,
    "2.0": _decryptv2_0,
}

_GEN_KEYS_VERSIONS = {
    "0.0": _genkeysv0_0,
    "1.0": _genkeysv1_0,
    "1.1": _genkeysv1_1,
    "2.0": _genkeysv2_0,
}

# Argon2id parameter presets for PURPLE v2.0+. Keys are the level names
# accepted by encrypt/decrypt/update_bundle.
_LEVELS: dict[str, dict[str, int]] = {
    "low":     {"time_cost": 2, "memory_cost": 65536,   "parallelism": 2},   # v1.0 strength, kept for compat
    "normal":  {"time_cost": 3, "memory_cost": 65536,   "parallelism": 4},   # RFC 9106 memory-constrained floor
    "strong":  {"time_cost": 4, "memory_cost": 524288,  "parallelism": 4},   # mid-tier (512 MiB)
    "extreme": {"time_cost": 2, "memory_cost": 2097152, "parallelism": 4},   # RFC 9106 gold (2 GiB)
}

_LEVEL_TO_BYTE: dict[str, int] = {
    "low":     0,
    "normal":  1,
    "strong":  2,
    "extreme": 3,
}

_BYTE_TO_LEVEL: dict[int, str] = {v: k for k, v in _LEVEL_TO_BYTE.items()}

_OLD_TO_NEW_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+to\s+(\d+(?:\.\d+)?)$")
