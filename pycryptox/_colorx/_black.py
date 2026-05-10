"""
Colorx BLACK:
The goal of the BLACK protocol is to encrypt
data as securely as possible. It is
recommended for encrypting sensitive data.
"""


# Imports:
from typing import Any
from .._exceptions._exceptions import *
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import base64


# Functions:
_KEM_ALG = "ML-KEM-512"
_KEM_CIPHERTEXT_SIZE = 768
_AEAD_NONCE_SIZE = 12
_AEAD_TAG_SIZE = 16


def _mlkem_keygen() -> tuple[bytes, bytes]:
    """Generate a fresh ML-KEM-512 keypair. Returns (public_key, secret_key) as bytes.
    Internal helper, used by BLACK, BLUE and RED."""
    from oqs import KeyEncapsulation
    with KeyEncapsulation(_KEM_ALG) as kem:
        pub = kem.generate_keypair()
        priv = kem.export_secret_key()
    return bytes(pub), bytes(priv)


# -- Versions: --
# -- v0.0: --
def _encryptv0_0() -> str:
    return "I encrypt nothing now..."

def _decryptv0_0() -> str:
    return "I decrypt nothing now..."

def _genkeysv0_0() -> str:
    return "I don't want to. I can't be bothered to make a new key."

# -- v1.0: --
def _encryptv1_0(pubkey: str, msg: str) -> str:
    if not isinstance(pubkey, str):
        raise ArgumentTypeError("pubkey", type(pubkey))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    from oqs import KeyEncapsulation
    try:
        pubkey_bytes = base64.urlsafe_b64decode(pubkey)
        with KeyEncapsulation(_KEM_ALG) as kem:
            ciphertext_kem, shared_key = kem.encap_secret(pubkey_bytes)
    except Exception:
        raise EncryptionError("invalid public key")

    nonce = os.urandom(_AEAD_NONCE_SIZE)
    chacha = ChaCha20Poly1305(shared_key)
    ciphertext_msg = chacha.encrypt(nonce, msg.encode(), None)
    payload = ciphertext_kem + nonce + ciphertext_msg
    return base64.urlsafe_b64encode(payload).decode()

def _decryptv1_0(privkey: str, msg: str) -> str:
    if not isinstance(privkey, str):
        raise ArgumentTypeError("privkey", type(privkey))
    elif not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))

    from oqs import KeyEncapsulation
    try:
        raw = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")

    if len(raw) < _KEM_CIPHERTEXT_SIZE + _AEAD_NONCE_SIZE + _AEAD_TAG_SIZE:
        raise DecryptionError("message too short")

    ciphertext_kem = raw[:_KEM_CIPHERTEXT_SIZE]
    nonce = raw[_KEM_CIPHERTEXT_SIZE:_KEM_CIPHERTEXT_SIZE + _AEAD_NONCE_SIZE]
    ciphertext_msg = raw[_KEM_CIPHERTEXT_SIZE + _AEAD_NONCE_SIZE:]

    try:
        privkey_bytes = base64.urlsafe_b64decode(privkey)
        with KeyEncapsulation(_KEM_ALG, secret_key=privkey_bytes) as kem:
            shared_key = kem.decap_secret(ciphertext_kem)
    except Exception:
        raise DecryptionError("invalid private key")

    chacha = ChaCha20Poly1305(shared_key)
    try:
        return chacha.decrypt(nonce, ciphertext_msg, None).decode()
    except Exception:
        raise DecryptionError("invalid key or corrupted message")

def _genkeysv1_0() -> dict[str, str]:
    pub, priv = _mlkem_keygen()
    return {
        "pubkey": base64.urlsafe_b64encode(pub).decode(),
        "privkey": base64.urlsafe_b64encode(priv).decode()
    }

# -- Main functions: --
__all__ = [
    "encrypt",
    "decrypt",
    "genkeys"
]

def encrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v1.0):**
    ```python
    def encrypt(
        version: str,
        pubkey: str,
        msg: str
    ) -> str
    ```
    """
    handler = _ENCRYPT_VERSIONS.get(version)

    if not handler:
        raise VersionNotFoundError(version)

    return handler(*args, **kwargs)

def decrypt(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v1.0):**
    ```python
    def decrypt(
        version: str,
        privkey: str,
        msg: str
    ) -> str
    ```
    """
    handler = _DECRYPT_VERSIONS.get(version)

    if not handler:
        raise VersionNotFoundError(version)

    return handler(*args, **kwargs)

def genkeys(version: str, *args: Any, **kwargs: Any) -> dict[str, str]:
    """**Latest version (v1.0):**
    ```python
    def genkeys(
        version: str
    ) -> dict
    ```
    Returns: `{"pubkey", "privkey"}`.\n
    """
    handler = _GEN_KEYS_VERSIONS.get(version)

    if not handler:
        raise VersionNotFoundError(version)

    return handler(*args, **kwargs)


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