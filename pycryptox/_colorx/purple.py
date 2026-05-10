"""
Colorx PURPLE:
The PURPLE protocol provides password-based encryption.
Use it when you want a brain-only secret -- one that survives
total device loss, that you can recover by retyping a passphrase.
The Argon2id KDF makes brute-force attacks computationally
expensive.
"""


# Imports:
from typing import Any
import os
import base64
import secrets
from .._exceptions._exceptions import *
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
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

def _resolve_version(version: str, versions_dict: dict[str, Any]) -> str:
    """Resolve a version specifier to an exact version string present in
    `versions_dict`.\n
    Accepts:\n
    - Exact version like `"1.0"` → returned as-is if present.\n
    - Major-only like `"1"` → returns the latest minor for that major.\n
    Raises `VersionNotFoundError` if no match exists."""
    if not isinstance(version, str):
        raise ArgumentTypeError("version", type(version))

    if version in versions_dict:
        return version

    if "." not in version:
        try:
            target_major = int(version)
        except ValueError:
            raise VersionNotFoundError(version)

        candidates: list[tuple[int, int, str]] = []
        for v in versions_dict.keys():
            try:
                major, minor = (int(x) for x in v.split("."))
                if major == target_major:
                    candidates.append((major, minor, v))
            except ValueError:
                continue

        if not candidates:
            raise VersionNotFoundError(version)

        _, _, best = max(candidates, key=lambda t: (t[0], t[1]))
        return best

    raise VersionNotFoundError(version)


def _matches_specifier(bundle_version: str, specifier: str) -> bool:
    """Return True if `bundle_version` (an exact `"M.m"` string) is acceptable
    under the user's `specifier` (which may be exact or major-only)."""
    if "." in specifier:
        return bundle_version == specifier
    try:
        target_major = int(specifier)
        bundle_major = int(bundle_version.split(".")[0])
    except (ValueError, IndexError):
        return False
    return bundle_major == target_major

# -- Versions: --
# -- v0.0: --
def _encryptv0_0() -> str:
    return "I encrypt nothing now..."

def _decryptv0_0() -> str:
    return "I decrypt nothing now..."

def _genkeysv0_0() -> str:
    return "I don't want to. I can't be bothered to make a new key."

# -- v1.0: --
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


# -- Main functions: --
__all__ = [
    "encrypt",
    "decrypt",
    "genkeys",
    "getversion"
]

def encrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v1.0):**
    ```python
        def encrypt(
            version: str,
            key: str,
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
    specifier (e.g. `"1"`) which resolves to the latest minor available.\n
    See docs for older versions."""
    actual_version = _resolve_version(version, _ENCRYPT_VERSIONS)
    handler = _ENCRYPT_VERSIONS[actual_version]

    try:
        major, minor = (int(x) for x in actual_version.split("."))
        if not (0 <= major <= 255 and 0 <= minor <= 255):
            raise ValueError()
    except ValueError:
        raise EncryptionError(f"invalid version format: {actual_version}")

    inner_b64 = handler(*args, **kwargs)
    inner = base64.urlsafe_b64decode(inner_b64)
    versioned = bytes([major, minor]) + inner
    return base64.urlsafe_b64encode(versioned).decode()


def decrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v1.0):**
    ```python
        def decrypt(
            version: str,
            key: str,
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
    specifier (e.g. `"1"`) which accepts any minor of that major.\n
    See docs for older versions."""
    if "msg" in kwargs:
        msg = kwargs.pop("msg")
    elif args:
        msg = args[-1]
        args = args[:-1]
    else:
        raise DecryptionError("missing 'msg' argument")

    try:
        versioned = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")

    if len(versioned) < 2:
        raise DecryptionError("message too short for version header")

    bundle_version = f"{versioned[0]}.{versioned[1]}"
    if not _matches_specifier(bundle_version, version):
        raise DecryptionError(
            f"version mismatch: bundle is v{bundle_version}, "
            f"caller requested v{version}"
        )

    handler = _DECRYPT_VERSIONS.get(bundle_version)
    if handler is None:
        raise VersionNotFoundError(bundle_version)

    inner_b64 = base64.urlsafe_b64encode(versioned[2:]).decode()
    return handler(*args, msg=inner_b64, **kwargs)


def genkeys(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v1.0):**
    ```python
        def genkeys(
            version: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only
    specifier (e.g. `"1"`) which resolves to the latest minor available.\n
    See docs for older versions."""
    actual_version = _resolve_version(version, _GEN_KEYS_VERSIONS)
    handler = _GEN_KEYS_VERSIONS[actual_version]
    return handler(*args, **kwargs)


def getversion(msg: str) -> str:
    """Extract the protocol version from a bundle without decrypting it.\n
    Useful for routing or migration logic.\n
    Raises `DecryptionError` if the bundle is malformed."""
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    try:
        versioned = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")
    if len(versioned) < 2:
        raise DecryptionError("message too short for version header")
    return f"{versioned[0]}.{versioned[1]}"


# Constants:
_ENCRYPT_VERSIONS = {
    "0.0": _encryptv0_0,
    "1.0": _encryptv1_0,
}

_DECRYPT_VERSIONS = {
    "0.0": _decryptv0_0,
    "1.0": _decryptv1_0,
}

_GEN_KEYS_VERSIONS = {
    "0.0": _genkeysv0_0,
    "1.0": _genkeysv1_0,
}