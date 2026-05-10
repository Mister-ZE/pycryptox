"""
Colorx BLUE:
The goal of the BLUE protocol is to encrypt
data with the strongest available secrecy
while preserving plausible deniability. It is
recommended for encrypting sensitive data when
the user may be coerced to reveal a key.
This is Pycryptox's most powerful encryption protocol.
"""

# !!NOTE!! Applications using BLUE should avoid exposing decryption
# success/failure status to unauthenticated parties. The noise portion of the
# bundle is not authenticated, so an oracle can be used to map chemkey
# positions over many trials.

# TODO: BLUE v2.0 should support messages > 1 MB via chunk-based fragmentation.
# Current byte-level fragmentation has acceptable performance up to 1 MB only.

# Imports:
from typing import Any
from .._exceptions._exceptions import *
from . import _black as bk
import os
import gc
import secrets
import base64


# Functions:
# Padding bucket sizes used by v1.0. Every plaintext is padded to the smallest
# bucket that can hold it. The padded format is:
#   [4 bytes : len(msg)] [msg] [random padding up to bucket size]
_BUCKETS = [
    4 * 1024,           # 4 KB
    16 * 1024,          # 16 KB
    64 * 1024,          # 64 KB
    256 * 1024,         # 256 KB
    1 * 1024 * 1024,    # 1 MB
]
_LEN_PREFIX_SIZE = 4
_NOISE_SIZE_MIN = 100
_NOISE_SIZE_MAX = 9000
_KYBER512_PUBKEY_SIZE = 800   # raw ML-KEM-512 public key length in bytes (same size as Kyber512)

def _choose_bucket(msg_size: int) -> int:
    needed = msg_size + _LEN_PREFIX_SIZE
    for b in _BUCKETS:
        if needed <= b:
            return b
    raise EncryptionError(
        f"msg too large ({msg_size} bytes), max bucket is {_BUCKETS[-1]} bytes"
    )

def _pad_msg(msg_bytes: bytes, bucket_size: int) -> bytes:
    msg_len = len(msg_bytes)
    if msg_len + _LEN_PREFIX_SIZE > bucket_size:
        raise EncryptionError(f"msg ({msg_len}) too large for bucket ({bucket_size})")
    padding_size = bucket_size - msg_len - _LEN_PREFIX_SIZE
    return (
        msg_len.to_bytes(_LEN_PREFIX_SIZE, 'big')
        + msg_bytes
        + os.urandom(padding_size)
    )

def _unpad_msg(padded: bytes) -> bytes:
    if len(padded) < _LEN_PREFIX_SIZE:
        raise DecryptionError("padded msg too short")
    msg_len = int.from_bytes(padded[:_LEN_PREFIX_SIZE], 'big')
    if msg_len + _LEN_PREFIX_SIZE > len(padded):
        raise DecryptionError("invalid padding length")
    return padded[_LEN_PREFIX_SIZE : _LEN_PREFIX_SIZE + msg_len]

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
def _encryptv1_0(gpubkey: str, xmsg: str | None = None, ymsg: str | None = None) -> str:
    if not isinstance(gpubkey, str):
        raise ArgumentTypeError("gpubkey", type(gpubkey))
    elif xmsg is not None and not isinstance(xmsg, str):
        raise ArgumentTypeError("xmsg", type(xmsg))
    elif ymsg is not None and not isinstance(ymsg, str):
        raise ArgumentTypeError("ymsg", type(ymsg))
    elif xmsg is None and ymsg is None:
        raise EncryptionError("at least one of xmsg or ymsg must be provided")

    try:
        gpubkey_bytes = base64.urlsafe_b64decode(gpubkey)
    except Exception:
        raise EncryptionError("gpubkey is not valid base64")
    if len(gpubkey_bytes) != 2 * _KYBER512_PUBKEY_SIZE:
        raise EncryptionError(
            f"gpubkey must be {2 * _KYBER512_PUBKEY_SIZE} bytes, got {len(gpubkey_bytes)}"
        )
    xpubkey = base64.urlsafe_b64encode(gpubkey_bytes[:_KYBER512_PUBKEY_SIZE]).decode()
    ypubkey = base64.urlsafe_b64encode(gpubkey_bytes[_KYBER512_PUBKEY_SIZE:]).decode()

    xmsg_bytes = xmsg.encode('utf-8') if xmsg is not None else None
    ymsg_bytes = ymsg.encode('utf-8') if ymsg is not None else None

    if xmsg_bytes is not None and ymsg_bytes is not None:
        bucket_x = _choose_bucket(len(xmsg_bytes))
        bucket_y = _choose_bucket(len(ymsg_bytes))
        if bucket_x != bucket_y:
            raise EncryptionError(
                f"xmsg and ymsg fit in different buckets ({bucket_x} vs {bucket_y})"
            )
        bucket = bucket_x
    elif xmsg_bytes is not None:
        bucket = _choose_bucket(len(xmsg_bytes))
    else:
        bucket = _choose_bucket(len(ymsg_bytes))

    if xmsg_bytes is not None:
        actual_pubkey_x = xpubkey
        actual_msg_x = xmsg_bytes
    else:
        eph_pub, eph_priv = bk._mlkem_keygen()
        actual_pubkey_x = base64.urlsafe_b64encode(eph_pub).decode()
        assert ymsg_bytes is not None  # guaranteed by the "at-least-one" check above
        actual_msg_x = os.urandom(len(ymsg_bytes))
        # NOTE: in pure Python, true zeroization of the original bytes object is not
        # achievable -- bytes are immutable, so rebinding the name does not overwrite
        # the original memory allocation. The original data may persist in memory
        # until garbage collection. This rebind/del/gc sequence is symbolic; for a
        # cryptographic destruction guarantee, a hardware module with attested
        # memory wipe is required.
        eph_priv = b'\x00' * len(eph_priv)
        del eph_priv
        gc.collect()

    if ymsg_bytes is not None:
        actual_pubkey_y = ypubkey
        actual_msg_y = ymsg_bytes
    else:
        eph_pub, eph_priv = bk._mlkem_keygen()
        actual_pubkey_y = base64.urlsafe_b64encode(eph_pub).decode()
        assert xmsg_bytes is not None  # guaranteed by the "at-least-one" check above
        actual_msg_y = os.urandom(len(xmsg_bytes))
        # NOTE: in pure Python, true zeroization of the original bytes object is not
        # achievable -- bytes are immutable, so rebinding the name does not overwrite
        # the original memory allocation. The original data may persist in memory
        # until garbage collection. This rebind/del/gc sequence is symbolic; for a
        # cryptographic destruction guarantee, a hardware module with attested
        # memory wipe is required.
        eph_priv = b'\x00' * len(eph_priv)
        del eph_priv
        gc.collect()

    padded_x = _pad_msg(actual_msg_x, bucket)
    padded_y = _pad_msg(actual_msg_y, bucket)
    enc_xmsg_b64 = bk._encryptv1_0(actual_pubkey_x, base64.urlsafe_b64encode(padded_x).decode())
    enc_ymsg_b64 = bk._encryptv1_0(actual_pubkey_y, base64.urlsafe_b64encode(padded_y).decode())
    enc_xmsg = base64.urlsafe_b64decode(enc_xmsg_b64)
    enc_ymsg = base64.urlsafe_b64decode(enc_ymsg_b64)

    noise_size = secrets.randbelow(_NOISE_SIZE_MAX - _NOISE_SIZE_MIN + 1) + _NOISE_SIZE_MIN
    noise = os.urandom(noise_size)

    total_size = len(enc_xmsg) + len(enc_ymsg) + noise_size
    sysrand = secrets.SystemRandom()
    all_pos = sysrand.sample(range(total_size), len(enc_xmsg) + len(enc_ymsg))
    xchemkey = all_pos[:len(enc_xmsg)]
    ychemkey = all_pos[len(enc_xmsg):]
    all_pos_set = set(all_pos)
    noise_pos = [p for p in range(total_size) if p not in all_pos_set]

    mixmsg = bytearray(total_size)
    for i, p in enumerate(xchemkey):
        mixmsg[p] = enc_xmsg[i]
    for i, p in enumerate(ychemkey):
        mixmsg[p] = enc_ymsg[i]
    for i, p in enumerate(noise_pos):
        mixmsg[p] = noise[i]

    xchem_bytes = b''.join(p.to_bytes(4, 'big') for p in xchemkey)
    ychem_bytes = b''.join(p.to_bytes(4, 'big') for p in ychemkey)
    enc_xchemkey_b64 = bk._encryptv1_0(actual_pubkey_x, base64.urlsafe_b64encode(xchem_bytes).decode())
    enc_ychemkey_b64 = bk._encryptv1_0(actual_pubkey_y, base64.urlsafe_b64encode(ychem_bytes).decode())
    enc_xchemkey = base64.urlsafe_b64decode(enc_xchemkey_b64)
    enc_ychemkey = base64.urlsafe_b64decode(enc_ychemkey_b64)

    bundle = (
        len(enc_xchemkey).to_bytes(4, 'big')
        + len(enc_ychemkey).to_bytes(4, 'big')
        + enc_xchemkey
        + enc_ychemkey
        + bytes(mixmsg)
    )
    return base64.urlsafe_b64encode(bundle).decode()

def _decryptv1_0(privkey: str, msg: str) -> str:
    if not isinstance(privkey, str):
        raise ArgumentTypeError("privkey", type(privkey))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    try:
        bundle = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")

    if len(bundle) < 8:
        raise DecryptionError("message too short")

    len_xchem = int.from_bytes(bundle[0:4], 'big')
    len_ychem = int.from_bytes(bundle[4:8], 'big')

    if len(bundle) < 8 + len_xchem + len_ychem:
        raise DecryptionError("message too short for declared lengths")

    enc_xchem = bundle[8 : 8 + len_xchem]
    enc_ychem = bundle[8 + len_xchem : 8 + len_xchem + len_ychem]
    mixmsg = bundle[8 + len_xchem + len_ychem:]

    enc_xchem_b64 = base64.urlsafe_b64encode(enc_xchem).decode()
    enc_ychem_b64 = base64.urlsafe_b64encode(enc_ychem).decode()

    for enc_chem_b64 in (enc_xchem_b64, enc_ychem_b64):
        try:
            chem_b64 = bk._decryptv1_0(privkey, enc_chem_b64)
            chem_bytes = base64.urlsafe_b64decode(chem_b64)
            if len(chem_bytes) % 4 != 0:
                raise DecryptionError("invalid chemkey length")
            positions = [
                int.from_bytes(chem_bytes[i:i+4], 'big')
                for i in range(0, len(chem_bytes), 4)
            ]
            if any(p >= len(mixmsg) for p in positions):
                raise DecryptionError("invalid chemkey positions")
            enc_data = bytes(mixmsg[p] for p in positions)
            enc_data_b64 = base64.urlsafe_b64encode(enc_data).decode()
            padded_b64 = bk._decryptv1_0(privkey, enc_data_b64)
            padded = base64.urlsafe_b64decode(padded_b64)
            unpadded = _unpad_msg(padded)
            return unpadded.decode('utf-8')
        except (DecryptionError, UnicodeDecodeError):
            continue

    raise DecryptionError("invalid key for this bundle")

def _genkeysv1_0() -> dict[str, str]:
    x_pub, x_priv = bk._mlkem_keygen()
    y_pub, y_priv = bk._mlkem_keygen()
    gpubkey_bytes = x_pub + y_pub
    return {
        "gpubkey": base64.urlsafe_b64encode(gpubkey_bytes).decode(),
        "xprivkey": base64.urlsafe_b64encode(x_priv).decode(),
        "yprivkey": base64.urlsafe_b64encode(y_priv).decode()
    }


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
            gpubkey: str,
            xmsg: str | None = None,
            ymsg: str | None = None
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
    specifier (e.g. `"1"`) which resolves to the latest minor available.\n
    At least one of `xmsg` or `ymsg` must be provided.\n
    When both are provided, they must fit in the same padding bucket.\n
    Buckets in v1.0: `4KB`, `16KB`, `64KB`, `256KB`, `1MB`.\n
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
            privkey: str,
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
    specifier (e.g. `"1"`) which accepts any minor of that major.\n
    `privkey` may be either the `xprivkey` or the `yprivkey` of the\n
    recipient. The protocol returns the matching message side.\n
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


def genkeys(version: str, *args: Any, **kwargs: Any) -> dict[str, str]:
    """**Latest version (v1.0):**
    ```python
        def genkeys(
            version: str
        ) -> dict
    ```
    Returns: `{"gpubkey", "xprivkey", "yprivkey"}`.\n
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