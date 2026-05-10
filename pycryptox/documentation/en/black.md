# BLACK protocol (internal)

BLACK is the base asymmetric encryption protocol of Pycryptox. It is not exposed in the public API. It is used internally by BLUE and RED.

This document is provided for understanding the architecture. The user never needs to call BLACK directly.


## Why BLACK is internal

BLACK is not exposed in order to preserve the **plausible deniability** of the BLUE protocol.

If BLACK were a public protocol, two populations of users would coexist: those who encrypt with BLACK (without deniability) and those who encrypt with BLUE (with deniability). An adversary who identified a bundle as a BLUE bundle would immediately know that the sender uses deniability — and therefore that they potentially have something to hide. Merely using BLUE would become a signal.

By making BLACK internal and forcing all asymmetric encryption to go through BLUE, all users produce bundles with the same structure. Those who do not need deniability (mono mode) and those who do (dual mode) are indistinguishable. The uniformity of the protocol protects everyone.


## Cryptographic primitives

| Component | Algorithm | Detail |
|---|---|---|
| Key encapsulation (KEM) | ML-KEM-512 (FIPS 203) | Via liboqs (C implementation, constant-time) |
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | Key = ML-KEM shared secret (256 bits) |


## Operation

1. **Encryption**: ML-KEM-512 encapsulation with the recipient's public key → KEM ciphertext (768 bytes) + shared secret (32 bytes). The message is encrypted with ChaCha20-Poly1305 using the shared secret as the key.

2. **Decryption**: ML-KEM-512 decapsulation with the private key → shared secret. ChaCha20-Poly1305 decryption.

3. **Key generation**: call to `oqs.KeyEncapsulation("ML-KEM-512").generate_keypair()`. Returns `{"pubkey": str, "privkey": str}` in base64url.


## BLACK ciphertext format

```
[768 bytes: ML-KEM-512 ciphertext] [12 bytes: nonce] [N bytes: ChaCha20-Poly1305 ciphertext + tag]
```

This format is identical for RED bundles (which are BLACK bundles whose private key has been split into Shamir shares).


## `_mlkem_keygen` helper

BLACK exposes an internal `_mlkem_keygen() -> tuple[bytes, bytes]` function that generates a raw ML-KEM-512 keypair (bytes). This function is used by BLUE (for ephemeral keys and genkeys) and by RED (for the trusted dealer's keypair). It centralizes the interaction with liboqs so that a backend change is always a single-file modification.


## Version history

### Version 1.0 (stable)

Current version, documented above. Uses ML-KEM-512 via liboqs and ChaCha20-Poly1305.

BLACK does not participate in the bundle versioning system (no 2-byte header in the ciphertext). Versioning is handled by the calling protocol (BLUE or RED), which prepends its own version header before delegating to BLACK.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
