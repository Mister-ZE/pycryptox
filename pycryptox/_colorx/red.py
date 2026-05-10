"""
Colorx RED:
The RED protocol encrypts a file using multiple keys (threshold cryptography).
The file cannot be decrypted without the approval of at least `t` out of `n`
people. Use it to encrypt a shared document, a recovery secret, or anything
that no single party should be able to access alone.
"""

# NOTE:
# LIMITATION (v1.0): This is a "trusted dealer" implementation. Whoever calls
# genkeys() and encrypt() must be trusted to destroy their copies of the
# intermediate Kyber private key and the plaintext after distributing shares.
# For a cryptographically enforced destruction guarantee, a future Cryptbox
# hardware module will provide RED v2.0 with attestation.
# Algorithm: Shamir's Secret Sharing in GF(256), byte-by-byte over the ML-KEM-512
# private key. The bundle on the wire is identical to a BLACK ciphertext --
# the threshold property is enforced entirely through the share format and the
# reconstruction step at decryption time.
# TODO: RED v2.0 -- Cryptbox hardware-backed mode. The hardware enters
# "0-trust max", generates the Kyber pair and shares internally, signs the
# bundle with a device key as attestation, and shreds intermediates before
# returning. Software clients verify the attestation against the manufacturer
# public key.

# Imports:
from typing import Any
from .._exceptions._exceptions import *
from . import _black as bk
import gc
import secrets
import base64


# GF(256) parameters:
_KYBER512_PRIVKEY_SIZE = 1632
_GF_REDUCE = 0x1B        # _GF_PRIM_POLY & 0xFF


# Functions:
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

# GF(256) tables -- precomputed at module import.
def _build_gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 510
    log = [0] * 256
    val = 1
    for i in range(255):
        exp[i] = val
        log[val] = i
        # val_next = val * 3 = (val * x) + val   (in GF(256))
        val_times_x = (val << 1) & 0xFF
        if val & 0x80:
            val_times_x ^= _GF_REDUCE
        val = val_times_x ^ val
    # Extend to avoid modular indexing in mul
    for i in range(255, 510):
        exp[i] = exp[i - 255]
    return exp, log

_GF_EXP, _GF_LOG = _build_gf_tables()


# GF(256) helpers
def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]

def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return _GF_EXP[255 - _GF_LOG[a]]

def _gf_polyeval(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial a_0 + a_1*x + ... + a_{n-1}*x^{n-1} at x in GF(256).
    Uses Horner's method."""
    result = 0
    for c in reversed(coeffs):
        result = _gf_mul(result, x) ^ c
    return result

def _gf_lagrange_at_zero(points: list[tuple[int, int]]) -> int:
    """Given points = [(x_i, y_i), ...] in GF(256), compute P(0) where P
    is the unique polynomial of degree < len(points) interpolating them.

    L_i(0) = product_{j != i} x_j / (x_i + x_j)   (XOR is +/- in GF(256))
    P(0)  = sum_i y_i * L_i(0)
    """
    secret = 0
    n = len(points)
    for i in range(n):
        x_i, y_i = points[i]
        num = 1
        den = 1
        for j in range(n):
            if i == j:
                continue
            x_j, _ = points[j]
            num = _gf_mul(num, x_j)
            den = _gf_mul(den, x_i ^ x_j)
        L_i_0 = _gf_mul(num, _gf_inv(den))
        secret ^= _gf_mul(y_i, L_i_0)
    return secret


# Shamir helpers
def _shamir_split(secret_bytes: bytes, t: int, n: int) -> list[tuple[int, bytes]]:
    """Split secret_bytes into n shares with threshold t.
    Returns list of (idx, ydata) tuples where idx is the share number (1..n)
    and ydata is bytes of the same length as secret_bytes."""
    shares = [(i, bytearray(len(secret_bytes))) for i in range(1, n + 1)]
    for byte_idx in range(len(secret_bytes)):
        secret_byte = secret_bytes[byte_idx]
        # P(x) = secret_byte + c_1*x + c_2*x^2 + ... + c_{t-1}*x^{t-1}
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(t - 1)]
        for share_idx in range(n):
            x = share_idx + 1
            shares[share_idx][1][byte_idx] = _gf_polyeval(coeffs, x)
    return [(idx, bytes(data)) for idx, data in shares]

def _shamir_reconstruct(shares: list[tuple[int, bytes]]) -> bytes:
    """Given list of (idx, ydata), reconstruct the secret bytes via Lagrange
    interpolation at x=0. Raises DecryptionError on structural problems with
    the share set (does NOT raise on insufficient shares -- those produce a
    wrong secret which fails downstream auth)."""
    if not shares:
        raise DecryptionError("no shares provided")
    secret_len = len(shares[0][1])
    if any(len(y) != secret_len for _, y in shares):
        raise DecryptionError("shares have inconsistent length")
    indices = [idx for idx, _ in shares]
    if len(set(indices)) != len(indices):
        raise DecryptionError("duplicate share indices")
    if any(idx == 0 for idx in indices):
        raise DecryptionError("invalid share index (0 is reserved)")

    secret = bytearray(secret_len)
    for byte_idx in range(secret_len):
        points = [(idx, y[byte_idx]) for idx, y in shares]
        secret[byte_idx] = _gf_lagrange_at_zero(points)
    return bytes(secret)


# -- Versions: --
# -- v0.0: --
def _encryptv0_0() -> str:
    return "I encrypt nothing now..."

def _decryptv0_0() -> str:
    return "I decrypt nothing now..."

def _genkeysv0_0() -> str:
    return "I don't want to. I can't be bothered to make a new key."


# -- v1.0: --
def _encryptv1_0(gpubkey: str, msg: str) -> str:
    """RED encryption is identical to BLACK encryption with the gpubkey.
    The threshold property is enforced at decryption time via the shares."""
    if not isinstance(gpubkey, str):
        raise ArgumentTypeError("gpubkey", type(gpubkey))
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    return bk._encryptv1_0(gpubkey, msg)


def _decryptv1_0(privkeys: list[str], msg: str) -> str:
    """Reconstruct the Kyber privkey from the provided shares via Lagrange
    interpolation, then decrypt the bundle with BLACK.
    `privkeys` is a list of base64 share strings.
    Provide at least t shares; fewer (or wrong) shares will produce a
    DecryptionError when BLACK fails its authentication tag."""
    if not isinstance(privkeys, list):
        raise ArgumentTypeError("privkeys", type(privkeys))
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    if len(privkeys) < 1:
        raise DecryptionError("at least one share is required")

    # Parse shares
    parsed = []
    for i, pk in enumerate(privkeys):
        if not isinstance(pk, str):
            raise ArgumentTypeError(f"privkeys[{i}]", type(pk))
        try:
            pk_bytes = base64.urlsafe_b64decode(pk)
        except Exception:
            raise DecryptionError(f"share {i} is not valid base64")
        if len(pk_bytes) != 1 + _KYBER512_PRIVKEY_SIZE:
            raise DecryptionError(
                f"share {i} has wrong size: got {len(pk_bytes)}, "
                f"expected {1 + _KYBER512_PRIVKEY_SIZE}"
            )
        parsed.append((pk_bytes[0], pk_bytes[1:]))

    # Reconstruct kyber privkey
    kyber_priv = _shamir_reconstruct(parsed)
    kyber_priv_b64 = base64.urlsafe_b64encode(kyber_priv).decode()

    # Decrypt with BLACK; cleanup intermediate state in finally
    try:
        return bk._decryptv1_0(kyber_priv_b64, msg)
    finally:
        # NOTE: in pure Python, true zeroization of the original bytes object is not
        # achievable -- bytes are immutable, so rebinding the name does not overwrite
        # the original memory allocation. The original data may persist in memory
        # until garbage collection. This rebind/del/gc sequence is symbolic; for a
        # cryptographic destruction guarantee, a hardware module with attested
        # memory wipe is required.
        kyber_priv = b'\x00' * len(kyber_priv)
        del kyber_priv
        del kyber_priv_b64
        gc.collect()


def _genkeysv1_0(t: int, n: int) -> dict[str, str | list[str]]:
    if not isinstance(t, int) or isinstance(t, bool):
        raise ArgumentTypeError("t", type(t))
    if not isinstance(n, int) or isinstance(n, bool):
        raise ArgumentTypeError("n", type(n))
    if not (1 <= t <= n <= 255):
        raise EncryptionError(
            f"invalid threshold parameters: must satisfy 1 <= t <= n <= 255 "
            f"(got t={t}, n={n})"
        )

    kyber_pub, kyber_priv = bk._mlkem_keygen()
    if len(kyber_priv) != _KYBER512_PRIVKEY_SIZE:
        raise EncryptionError(
            f"unexpected ML-KEM-512 privkey size: {len(kyber_priv)}"
        )

    shares = _shamir_split(kyber_priv, t, n)

    # NOTE: in pure Python, true zeroization of the original bytes object is not
    # achievable -- bytes are immutable, so rebinding the name does not overwrite
    # the original memory allocation. The original data may persist in memory
    # until garbage collection. This rebind/del/gc sequence is symbolic; for a
    # cryptographic destruction guarantee, a hardware module with attested
    # memory wipe is required.
    kyber_priv = b'\x00' * len(kyber_priv)
    del kyber_priv
    gc.collect()

    privkeys = [
        base64.urlsafe_b64encode(bytes([idx]) + ydata).decode()
        for idx, ydata in shares
    ]

    return {
        "gpubkey": base64.urlsafe_b64encode(kyber_pub).decode(),
        "privkeys": privkeys
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
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only
    specifier (e.g. `"1"`) which resolves to the latest minor available.\n
    On the wire, RED bundles are indistinguishable from BLACK bundles.
    The threshold property is enforced at decryption time via the shares.\n
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
            privkeys: list[str],
            msg: str
        ) -> str
    ```
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
    specifier (e.g. `"1"`) which accepts any minor of that major.\n
    Provide at least `t` shares in `privkeys` (where `t` was set at\n
    genkeys time). Any subset of `t` valid shares from the original `n`\n
    will succeed. Insufficient or invalid shares produce a\n
    `DecryptionError`, indistinguishably.\n
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


def genkeys(version: str, *args: Any, **kwargs: Any) -> dict[str, str | list[str]]:
    """**Latest version (v1.0):**
    ```python
        def genkeys(
            version: str,
            t: int,
            n: int
        ) -> dict
    ```
    Returns: `{"gpubkey", "privkeys": [share_1, ..., share_n]}`.\n
    Constraints: `1 <= t <= n <= 255`.\n
    `version` may be an exact version (e.g. `"1.0"`) or a major-only\n
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