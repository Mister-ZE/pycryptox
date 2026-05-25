"""
Colorx BLUE:
The goal of the BLUE protocol is to encrypt
data with the strongest available secrecy
while preserving plausible deniability. It is
recommended for encrypting sensitive data when
the user may be coerced to reveal a key.
This is Pycryptox's most powerful encryption protocol.
"""

# !!NOTE!! Applications using BLUE v1.0 should avoid exposing decryption
# success/failure status to unauthenticated parties. The noise portion of the
# v1.0 bundle is not authenticated, so an oracle can be used to map chemkey
# positions over many trials.
# BLUE v2.0 does not have this concern: there is no unauthenticated noise,
# and the order_flag is in the clear by design.

# Imports:
from typing import Any, Callable
from .._exceptions._exceptions import *
from . import _black as bk
from . import _versioning as _ver
import os
import gc
import re
import time
import secrets
import base64
import binascii
import threading


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

# -- v2.0: --
# Wire format (inside the version wrap):
#   [1 byte : order_flag (0 = enc_x first, 1 = enc_y first)]
#   [4 bytes : len(enc_first) big-endian]
#   [enc_first bytes]
#   [enc_second bytes]
#
# The order_flag is randomized at encryption time (secrets.randbits(1)). A
# recipient holding xprivkey or yprivkey reads the flag, identifies the slot
# matching their key, and decrypts ONLY that slot — exactly one ML-KEM decap
# and one AEAD verify per call. This gives constant per-decryption time and,
# statistically across many bundles, no timing oracle on which side the
# recipient is.
#
# v2.0 buckets are expanded relative to v1.0 since the chemical mixing
# bottleneck no longer applies. Max plaintext size per slot is 1 GiB.
_BUCKETS_V2 = [
    4 * 1024,                     # 4 KB
    16 * 1024,                    # 16 KB
    64 * 1024,                    # 64 KB
    256 * 1024,                   # 256 KB
    1 * 1024 * 1024,              # 1 MB
    16 * 1024 * 1024,             # 16 MB
    256 * 1024 * 1024,            # 256 MB
    1 * 1024 * 1024 * 1024,       # 1 GiB
]
_MAX_MSG_SIZE_V2 = 1 * 1024 * 1024 * 1024   # 1 GiB hard cap per slot


def _choose_bucket_v2(msg_size: int) -> int:
    needed = msg_size + _LEN_PREFIX_SIZE
    for b in _BUCKETS_V2:
        if needed <= b:
            return b
    raise EncryptionError(
        f"msg too large ({msg_size} bytes), max bucket is {_BUCKETS_V2[-1]} bytes"
    )


def _encryptv2_0(
    gpubkey: str,
    xmsg: str | None = None,
    ymsg: str | None = None,
    *,
    _progress: "Callable[[float], None] | None" = None,
) -> str:
    """Encrypt under BLUE v2.0.\n
    Uses only the public `_black` API (`bk.encrypt`, `bk.genkeys`). No private
    machinery. Padding is applied per-slot to a common bucket; the inner
    ML-KEM + AEAD encryption is atomic per slot.\n
    `_progress(value)` is an optional callback used by the async layer to
    stamp the current palier into the job registry. Caller-side smoothing
    is the responsibility of the application layer."""
    # --- Type validation ---
    if not isinstance(gpubkey, str):
        raise ArgumentTypeError("gpubkey", type(gpubkey))
    if xmsg is not None and not isinstance(xmsg, str):
        raise ArgumentTypeError("xmsg", type(xmsg))
    if ymsg is not None and not isinstance(ymsg, str):
        raise ArgumentTypeError("ymsg", type(ymsg))
    if xmsg is None and ymsg is None:
        raise EncryptionError("at least one of xmsg or ymsg must be provided")

    # --- Split gpubkey into x and y public keys ---
    try:
        gpubkey_bytes = base64.urlsafe_b64decode(gpubkey)
    except (binascii.Error, ValueError):
        raise EncryptionError("gpubkey is not valid base64")
    if len(gpubkey_bytes) != 2 * _KYBER512_PUBKEY_SIZE:
        raise EncryptionError(
            f"gpubkey must be {2 * _KYBER512_PUBKEY_SIZE} bytes, got {len(gpubkey_bytes)}"
        )
    xpubkey = base64.urlsafe_b64encode(gpubkey_bytes[:_KYBER512_PUBKEY_SIZE]).decode()
    ypubkey = base64.urlsafe_b64encode(gpubkey_bytes[_KYBER512_PUBKEY_SIZE:]).decode()

    # --- Encode messages and check size cap ---
    xmsg_bytes = xmsg.encode("utf-8") if xmsg is not None else None
    ymsg_bytes = ymsg.encode("utf-8") if ymsg is not None else None
    for label, blob in (("xmsg", xmsg_bytes), ("ymsg", ymsg_bytes)):
        if blob is not None and len(blob) > _MAX_MSG_SIZE_V2:
            raise EncryptionError(
                f"{label} exceeds maximum size of {_MAX_MSG_SIZE_V2} bytes (1 GiB)"
            )

    if _progress is not None:
        _progress(0.05)

    # --- Choose a common bucket ---
    if xmsg_bytes is not None and ymsg_bytes is not None:
        bucket_x = _choose_bucket_v2(len(xmsg_bytes))
        bucket_y = _choose_bucket_v2(len(ymsg_bytes))
        if bucket_x != bucket_y:
            raise EncryptionError(
                f"xmsg and ymsg fit in different buckets ({bucket_x} vs {bucket_y})"
            )
        bucket = bucket_x
    elif xmsg_bytes is not None:
        bucket = _choose_bucket_v2(len(xmsg_bytes))
    else:
        bucket = _choose_bucket_v2(len(ymsg_bytes))   # type: ignore[arg-type]

    # --- Resolve slot pubkeys and payloads (mono-mode generates an ephemeral decoy) ---
    if xmsg_bytes is not None:
        actual_xpubkey = xpubkey
        actual_xmsg = xmsg_bytes
    else:
        assert ymsg_bytes is not None
        eph = bk.genkeys("1.0")
        actual_xpubkey = eph["pubkey"]
        actual_xmsg = os.urandom(len(ymsg_bytes))
        del eph
        gc.collect()

    if ymsg_bytes is not None:
        actual_ypubkey = ypubkey
        actual_ymsg = ymsg_bytes
    else:
        assert xmsg_bytes is not None
        eph = bk.genkeys("1.0")
        actual_ypubkey = eph["pubkey"]
        actual_ymsg = os.urandom(len(xmsg_bytes))
        del eph
        gc.collect()

    # --- Pad both to the common bucket ---
    padded_x = _pad_msg(actual_xmsg, bucket)
    padded_y = _pad_msg(actual_ymsg, bucket)

    if _progress is not None:
        _progress(0.10)

    # --- Encrypt x slot ---
    padded_x_b64 = base64.urlsafe_b64encode(padded_x).decode()
    enc_x_b64 = bk.encrypt("1.0", actual_xpubkey, padded_x_b64)
    enc_x = base64.urlsafe_b64decode(enc_x_b64)
    if _progress is not None:
        _progress(0.50)

    # --- Encrypt y slot ---
    padded_y_b64 = base64.urlsafe_b64encode(padded_y).decode()
    enc_y_b64 = bk.encrypt("1.0", actual_ypubkey, padded_y_b64)
    enc_y = base64.urlsafe_b64decode(enc_y_b64)
    if _progress is not None:
        _progress(0.85)

    # --- Random order, assemble bundle ---
    order_flag = secrets.randbits(1)
    if order_flag == 0:
        enc_first = enc_x
        enc_second = enc_y
    else:
        enc_first = enc_y
        enc_second = enc_x

    bundle = (
        bytes([order_flag])
        + len(enc_first).to_bytes(4, "big")
        + enc_first
        + enc_second
    )

    result = base64.urlsafe_b64encode(bundle).decode()
    if _progress is not None:
        _progress(1.0)
    return result


def _decryptv2_0(
    privkey: str,
    msg: str,
    *,
    slot: str,
    _progress: "Callable[[float], None] | None" = None,
) -> str:
    """Decrypt under BLUE v2.0.\n
    `slot` is required and must be `"x"` or `"y"`. It tells the decrypter
    which slot of the bundle the privkey corresponds to. The order_flag in
    the bundle locates that slot's ciphertext; only that slot is decrypted.\n
    `_progress(value)` is an optional callback for stamping paliers into
    the async job registry."""
    if not isinstance(privkey, str):
        raise ArgumentTypeError("privkey", type(privkey))
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    if not isinstance(slot, str):
        raise ArgumentTypeError("slot", type(slot))
    if slot not in ("x", "y"):
        raise DecryptionError(f"slot must be 'x' or 'y', got {slot!r}")

    try:
        bundle = base64.urlsafe_b64decode(msg)
    except (binascii.Error, ValueError):
        raise DecryptionError("message is not valid base64")

    if len(bundle) < 5:
        raise DecryptionError("message too short")

    order_flag = bundle[0]
    if order_flag not in (0, 1):
        raise DecryptionError(f"invalid order flag: {order_flag}")

    len_first = int.from_bytes(bundle[1:5], "big")
    if 5 + len_first > len(bundle):
        raise DecryptionError("message too short for declared first-slot length")
    enc_first = bundle[5:5 + len_first]
    enc_second = bundle[5 + len_first:]

    if order_flag == 0:
        enc_x = enc_first
        enc_y = enc_second
    else:
        enc_x = enc_second
        enc_y = enc_first

    target_enc = enc_x if slot == "x" else enc_y

    if _progress is not None:
        _progress(0.10)

    target_b64 = base64.urlsafe_b64encode(target_enc).decode()
    try:
        padded_b64 = bk.decrypt("1.0", privkey, target_b64)
    except DecryptionError:
        raise DecryptionError("privkey does not match the requested slot")

    if _progress is not None:
        _progress(0.90)

    try:
        padded = base64.urlsafe_b64decode(padded_b64)
    except (binascii.Error, ValueError):
        raise DecryptionError("decrypted payload is not valid base64")

    unpadded = _unpad_msg(padded)
    try:
        result = unpadded.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("decrypted message is not valid UTF-8")

    if _progress is not None:
        _progress(1.0)
    return result


def _genkeysv2_0() -> dict[str, str]:
    # Same key shape as v1.0: gpubkey = xpubkey || ypubkey concatenated.
    # Uses only the public _black.genkeys API.
    xk = bk.genkeys("1.0")
    yk = bk.genkeys("1.0")
    xpub_bytes = base64.urlsafe_b64decode(xk["pubkey"])
    ypub_bytes = base64.urlsafe_b64decode(yk["pubkey"])
    gpubkey_bytes = xpub_bytes + ypub_bytes
    return {
        "gpubkey": base64.urlsafe_b64encode(gpubkey_bytes).decode(),
        "xprivkey": xk["privkey"],
        "yprivkey": yk["privkey"],
    }


# -- Async machinery (v2.0+ only) --
#
# Caller pattern:
#   crx.blue.encrypt("2", gpubkey, xmsg="...", id=42)   # returns None, starts bg job
#   while crx.blue.show_encryption_progress(id=42) < 1.0:
#       update_ui()
#   bundle = crx.blue.get_encryption_result(id=42)      # blocks if not yet done
#
# get_*_result auto-cleans the job from the registry on retrieval.
#
# Progress is reported as discrete paliers (stepped values, e.g. 0.05, 0.10,
# 0.50, 0.85, 1.0 for encrypt). The library reports the truth: the current
# palier reached. Caller-side smoothing or interpolation between paliers is
# the responsibility of the application layer (e.g. Rich, tqdm, Qt, web UIs
# all have their own animation primitives and can ease between two values
# better than this library could from inside).


# Job registry. Keyed by user-provided id (any hashable). Each entry tracks
# current progress, the final result (or raised exception), and a done event.
_jobs: dict[Any, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _create_job(job_id: Any, kind: str) -> None:
    """Register a new job. `kind` is 'encrypt' or 'decrypt' for show/get
    disambiguation. Raises EncryptionError if the id is already in use."""
    with _jobs_lock:
        if job_id in _jobs:
            raise EncryptionError(f"job id {job_id!r} already in use")
        _jobs[job_id] = {
            "kind": kind,
            "progress": 0.0,
            "result": None,
            "error": None,
            "done": threading.Event(),
            "start_time": time.monotonic(),
        }


def _stamp(job_id: Any, value: float) -> None:
    """Update the visible progress of a job."""
    if job_id is None:
        return
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["progress"] = value


def _finish_job(job_id: Any, result: Any = None, error: "BaseException | None" = None) -> None:
    """Mark a job as completed (success or failure). The done event is set."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["result"] = result
        job["error"] = error
        if error is None:
            job["progress"] = 1.0
        job["done"].set()


def _consume_job(job_id: Any, expected_kind: str) -> Any:
    """Block until the job finishes, then pop from registry and return result
    (or re-raise the captured exception)."""
    err_cls = EncryptionError if expected_kind == "encrypt" else DecryptionError
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise err_cls(f"no {expected_kind} job with id {job_id!r}")
        if job["kind"] != expected_kind:
            raise err_cls(f"job id {job_id!r} is a {job['kind']} job, not {expected_kind}")
        done_event = job["done"]
    done_event.wait()
    with _jobs_lock:
        job = _jobs.pop(job_id, None)
    if job is None:
        raise err_cls(f"job id {job_id!r} disappeared from registry")
    if job["error"] is not None:
        raise job["error"]
    return job["result"]


def _peek_progress(job_id: Any, expected_kind: str) -> float:
    err_cls = EncryptionError if expected_kind == "encrypt" else DecryptionError
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise err_cls(f"no {expected_kind} job with id {job_id!r}")
        if job["kind"] != expected_kind:
            raise err_cls(f"job id {job_id!r} is a {job['kind']} job, not {expected_kind}")
        return job["progress"]


def _peek_eta(job_id: Any, expected_kind: str) -> "float | None":
    """Estimate remaining seconds based on elapsed time and current progress.
    Returns None when progress is too low to project (below 1 %), 0.0 when
    the job is complete."""
    err_cls = EncryptionError if expected_kind == "encrypt" else DecryptionError
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise err_cls(f"no {expected_kind} job with id {job_id!r}")
        if job["kind"] != expected_kind:
            raise err_cls(f"job id {job_id!r} is a {job['kind']} job, not {expected_kind}")
        progress = job["progress"]
        start = job["start_time"]
    if progress >= 1.0:
        return 0.0
    if progress < 0.01:
        return None
    elapsed = time.monotonic() - start
    total_estimate = elapsed / progress
    remaining = total_estimate - elapsed
    return max(remaining, 0.0)


# Regex for update_bundle spec, identical to PURPLE's.
_OLD_TO_NEW_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+to\s+(\d+(?:\.\d+)?)$")


# -- Main functions: --
__all__ = [
    "encrypt",
    "decrypt",
    "genkeys",
    "getversion",
    "update_bundle",
    "show_encryption_progress",
    "show_decryption_progress",
    "show_encryption_eta",
    "show_decryption_eta",
    "get_encryption_result",
    "get_decryption_result",
]


def encrypt(version: str, *args: Any, id: Any = None, **kwargs: Any) -> "str | None":
    """**Latest version (v2.0):**
    ```python
        def encrypt(
            version: str,
            gpubkey: str,
            xmsg: str | None = None,
            ymsg: str | None = None,
            *,
            id: Any = None
        ) -> str | None
    ```
    `version` may be an exact version (e.g. `"2.0"`) or a major-only\n
    specifier (e.g. `"2"`) which resolves to the latest minor available.\n
    At least one of `xmsg` or `ymsg` must be provided.\n
    When both are provided, they must fit in the same padding bucket.\n
    Buckets in v2.0: `4 KB`, `16 KB`, `64 KB`, `256 KB`, `1 MB`, `16 MB`, `256 MB`, `1 GiB` (hard cap).\n
    \n
    If `id` is provided (any hashable), encryption runs in a background\n
    thread and returns `None` immediately. The caller can poll progress\n
    via `show_encryption_progress(id)` and retrieve the bundle via\n
    `get_encryption_result(id)` (which blocks until done and auto-cleans\n
    the registry). Async mode is only supported for v2.0+.\n
    See docs for older versions."""
    actual_version = _ver._resolve_version(version, _ENCRYPT_VERSIONS)
    handler = _ENCRYPT_VERSIONS[actual_version]

    if id is None:
        inner_b64 = handler(*args, **kwargs)
        return _ver._wrap_version_bytes(actual_version, inner_b64)

    if actual_version not in _ASYNC_CAPABLE_ENCRYPT_VERSIONS:
        raise EncryptionError(
            f"async mode (id) is not supported for BLUE v{actual_version}, only v2.0+"
        )
    if "_progress" in kwargs:
        raise EncryptionError("'_progress' is internal and cannot be passed from the caller")

    _create_job(id, "encrypt")

    def _worker(
        _job_id: Any = id,
        _ver_str: str = actual_version,
        _handler: Any = handler,
        _args: tuple = args,
        _kwargs: dict = kwargs,
    ) -> None:
        try:
            _kwargs["_progress"] = lambda v: _stamp(_job_id, v)
            inner_b64 = _handler(*_args, **_kwargs)
            bundle = _ver._wrap_version_bytes(_ver_str, inner_b64)
        except BaseException as exc:
            _finish_job(_job_id, error=exc)
            return
        _stamp(_job_id, 1.0)
        _finish_job(_job_id, result=bundle)

    threading.Thread(target=_worker, daemon=True).start()
    return None


def decrypt(version: str, *args: Any, id: Any = None, **kwargs: Any) -> "str | None":
    """**Latest version (v2.0):**
    ```python
        def decrypt(
            version: str,
            privkey: str,
            msg: str,
            *,
            slot: str,
            id: Any = None
        ) -> str | None
    ```
    `version` may be an exact version (e.g. `"2.0"`) or a major-only\n
    specifier (e.g. `"2"`) which accepts any minor of that major.\n
    `privkey` is one of `xprivkey` or `yprivkey` from the keypair.\n
    `slot` (v2.0+, keyword-only) is `"x"` or `"y"` and identifies which\n
    slot of the bundle the `privkey` decrypts. v1.0 bundles do not take\n
    a `slot` argument: they try both slots internally.\n
    \n
    If `id` is provided (any hashable), decryption runs in a background\n
    thread and returns `None` immediately. The caller can poll progress\n
    via `show_decryption_progress(id)` and retrieve the plaintext via\n
    `get_decryption_result(id)` (which blocks until done and auto-cleans\n
    the registry). Async mode is only supported for v2.0+.\n
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

    if id is None:
        return handler(*args, msg=inner_b64, **kwargs)

    if bundle_version not in _ASYNC_CAPABLE_DECRYPT_VERSIONS:
        raise DecryptionError(
            f"async mode (id) is not supported for BLUE v{bundle_version}, only v2.0+"
        )
    if "_progress" in kwargs:
        raise DecryptionError("'_progress' is internal and cannot be passed from the caller")

    _create_job(id, "decrypt")

    def _worker(
        _job_id: Any = id,
        _handler: Any = handler,
        _args: tuple = args,
        _kwargs: dict = kwargs,
        _inner: str = inner_b64,
    ) -> None:
        try:
            _kwargs["_progress"] = lambda v: _stamp(_job_id, v)
            plaintext = _handler(*_args, msg=_inner, **_kwargs)
        except BaseException as exc:
            _finish_job(_job_id, error=exc)
            return
        _stamp(_job_id, 1.0)
        _finish_job(_job_id, result=plaintext)

    threading.Thread(target=_worker, daemon=True).start()
    return None


def genkeys(version: str, *args: Any, **kwargs: Any) -> dict[str, str]:
    """**Latest version (v2.0):**
    ```python
        def genkeys(
            version: str
        ) -> dict
    ```
    Returns: `{"gpubkey", "xprivkey", "yprivkey"}`.\n
    `version` may be an exact version (e.g. `"2.0"`) or a major-only
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


def update_bundle(
    old_to_new: str,
    gpubkey: str,
    old_msg: str,
    xprivkey: "str | None" = None,
    yprivkey: "str | None" = None,
    downgrade: bool = False,
) -> str:
    """Re-encrypt a BLUE bundle from one protocol version to another.\n
    `old_to_new` follows `"A.a to B.b"` (e.g. `"1.0 to 2"`, `"1 to 2.0"`,
    `"1 to 2"`). Major-only sides resolve to the latest minor available.\n
    At least one of `xprivkey` or `yprivkey` must be provided. If only
    one is given when the source bundle was dual-mode, the slot for the
    missing privkey is replaced by a random decoy in the new bundle —
    that information is LOST and not recoverable. This is a deliberate
    "lossy" migration; the caller is responsible for accepting the loss
    or providing both keys.\n
    If the resolved old and new versions are equal, `old_msg` is returned
    unchanged.\n
    With `downgrade=False` (default), migrating to an older version raises
    `DowngradeError`. With `downgrade=True`, it is permitted.\n
    Raises `ArgumentTypeError`, `VersionNotFoundError`, `DowngradeError`,
    `DecryptionError`, `EncryptionError` as appropriate."""
    if not isinstance(old_to_new, str):
        raise ArgumentTypeError("old_to_new", type(old_to_new))
    if not isinstance(gpubkey, str):
        raise ArgumentTypeError("gpubkey", type(gpubkey))
    if not isinstance(old_msg, str):
        raise ArgumentTypeError("old_msg", type(old_msg))
    if xprivkey is not None and not isinstance(xprivkey, str):
        raise ArgumentTypeError("xprivkey", type(xprivkey))
    if yprivkey is not None and not isinstance(yprivkey, str):
        raise ArgumentTypeError("yprivkey", type(yprivkey))
    if not isinstance(downgrade, bool):
        raise ArgumentTypeError("downgrade", type(downgrade))
    if xprivkey is None and yprivkey is None:
        raise EncryptionError("at least one of xprivkey or yprivkey must be provided")

    m = _OLD_TO_NEW_RE.match(old_to_new)
    if not m:
        raise VersionNotFoundError(old_to_new)
    old_spec, new_spec = m.group(1), m.group(2)
    old_resolved = _ver._resolve_version(old_spec, _DECRYPT_VERSIONS)
    new_resolved = _ver._resolve_version(new_spec, _ENCRYPT_VERSIONS)

    old_t = tuple(int(x) for x in old_resolved.split("."))
    new_t = tuple(int(x) for x in new_resolved.split("."))

    if old_t == new_t:
        return old_msg
    if old_t > new_t and not downgrade:
        raise DowngradeError(old_resolved, new_resolved)

    # --- Decrypt with whatever privkeys we have ---
    xmsg: "str | None" = None
    ymsg: "str | None" = None

    if old_resolved == "1.0":
        # v1.0 decrypt tries both slots internally; whichever the key matches succeeds.
        if xprivkey is not None:
            try:
                xmsg = decrypt(old_spec, xprivkey, old_msg)
            except DecryptionError:
                pass
        if yprivkey is not None:
            try:
                ymsg = decrypt(old_spec, yprivkey, old_msg)
            except DecryptionError:
                pass
    elif old_resolved == "2.0":
        if xprivkey is not None:
            try:
                xmsg = decrypt(old_spec, xprivkey, old_msg, slot="x")
            except DecryptionError:
                pass
        if yprivkey is not None:
            try:
                ymsg = decrypt(old_spec, yprivkey, old_msg, slot="y")
            except DecryptionError:
                pass
    else:
        raise VersionNotFoundError(old_resolved)

    if xmsg is None and ymsg is None:
        raise DecryptionError("neither xprivkey nor yprivkey decrypts the bundle")

    return encrypt(new_spec, gpubkey, xmsg=xmsg, ymsg=ymsg)


def show_encryption_progress(id: Any) -> float:
    """Return the current progress (0.0 to 1.0) of a background encrypt job.\n
    Raises `EncryptionError` if no job with this id exists or it is a
    decrypt job."""
    return _peek_progress(id, "encrypt")


def show_decryption_progress(id: Any) -> float:
    """Return the current progress (0.0 to 1.0) of a background decrypt job.\n
    Raises `DecryptionError` if no job with this id exists or it is an
    encrypt job."""
    return _peek_progress(id, "decrypt")


def show_encryption_eta(id: Any) -> "float | None":
    """Estimate the number of seconds remaining for the background encrypt
    job with the given `id`. Returns `None` when progress is too low to
    project (below 1 %) and `0.0` when the job has completed.\n
    The estimate is derived from elapsed wall-clock time divided by the
    current palier value, projected to the remaining fraction. Accuracy
    improves as more paliers are reached.\n
    Raises `EncryptionError` if no encrypt job with this id exists."""
    return _peek_eta(id, "encrypt")


def show_decryption_eta(id: Any) -> "float | None":
    """Estimate the number of seconds remaining for the background decrypt
    job with the given `id`. Same semantics as `show_encryption_eta`.\n
    Raises `DecryptionError` if no decrypt job with this id exists."""
    return _peek_eta(id, "decrypt")


def get_encryption_result(id: Any) -> str:
    """Block until the encryption job with `id` finishes, return the bundle,
    and remove the job from the registry. Re-raises any exception that
    occurred during the background work.\n
    Raises `EncryptionError` if no encrypt job with this id exists."""
    return _consume_job(id, "encrypt")


def get_decryption_result(id: Any) -> str:
    """Block until the decryption job with `id` finishes, return the plaintext,
    and remove the job from the registry. Re-raises any exception that
    occurred during the background work.\n
    Raises `DecryptionError` if no decrypt job with this id exists."""
    return _consume_job(id, "decrypt")


# Constants:
_ENCRYPT_VERSIONS = {
    "0.0": _encryptv0_0,
    "1.0": _encryptv1_0,
    "2.0": _encryptv2_0,
}

_DECRYPT_VERSIONS = {
    "0.0": _decryptv0_0,
    "1.0": _decryptv1_0,
    "2.0": _decryptv2_0,
}

_GEN_KEYS_VERSIONS = {
    "0.0": _genkeysv0_0,
    "1.0": _genkeysv1_0,
    "2.0": _genkeysv2_0,
}

# Only v2.0+ supports the async mode (because it requires _progress hooks
# integrated into the implementation). v1.0's `_progress` hook does not exist.
_ASYNC_CAPABLE_ENCRYPT_VERSIONS = {"2.0"}
_ASYNC_CAPABLE_DECRYPT_VERSIONS = {"2.0"}
