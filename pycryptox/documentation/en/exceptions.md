# Exceptions

All Pycryptox exceptions inherit from `PycryptoxError`, which itself inherits from `Exception`. They are exposed directly at the root module level: `crx.DecryptionError`, `crx.KeyxError`, etc.


## Hierarchy

```
Exception
└── PycryptoxError               Base Pycryptox exception.
    ├── ProtocolNotFoundError    Unknown protocol.
    ├── VersionNotFoundError     Unknown protocol version.
    ├── ArgumentTypeError        Invalid argument type.
    ├── DecryptionError          Decryption failure.
    ├── EncryptionError          Encryption failure.
    ├── StegaError               Steganography failure (YELLOW, future).
    ├── UnstegaError             Unsteganography failure (YELLOW, future).
    ├── KeyxError            Keyx error (file, format, state).
    ├── KeyNameError             Error related to the name of an entry in a Keyx.
    └── WrongPasswordError       Incorrect password for a Keyx.
```


## Detailed descriptions

### `PycryptoxError`

Base exception. Must not be raised directly. Allows catching all Pycryptox errors with a single `except crx.PycryptoxError`.


### `VersionNotFoundError`

Raised when the `version` parameter does not match any version implemented in the protocol.

Message: `"The version '<version>' being sought could not be found"`.

Trigger examples:
- `crx.purple.encrypt("99", ...)` — version 99 does not exist.
- `crx.blue.decrypt("1", ...)` on a bundle whose extracted version is `"2.0"` and `"2.0"` is not implemented.


### `ArgumentTypeError`

Raised when an argument has an incorrect Python type. Each protocol and each keyx method validates the types of its arguments before proceeding.

Message: `"The variable type '<type>' used for the value of the argument '<name>' is invalid"`.

Trigger examples:
- `crx.purple.encrypt("1", 123, "msg")` — `key` is an `int`, not a `str`.
- `crx.red.genkeys("1", 2.0, 3)` — `t` is a `float`, not an `int`.
- `crx.red.genkeys("1", True, 3)` — booleans are rejected (even though `bool` is a subtype of `int` in Python, RED explicitly refuses them).


### `DecryptionError`

Raised when decryption fails, whatever the cause.

Message: `"Error during decryption because '<reason>'"`.

Possible causes (non-exhaustive):
- Incorrect password or private key.
- Corrupted or truncated message.
- Bundle version incompatible with the requested version.
- Invalid base64 bundle.
- Insufficient or invalid RED shares.
- Invalid BLUE chemical key.

By design, a wrong password and a corrupted message produce the same exception with the same message type. The caller cannot distinguish these cases, which is a security choice.


### `EncryptionError`

Raised when encryption fails.

Message: `"Error during encryption because '<reason>'"`.

Possible causes:
- Invalid public key (incorrect size, malformed base64).
- Invalid RED threshold parameters.
- BLUE messages in different buckets.
- BLUE message too large (> 1 MB).


### `StegaError`

Reserved for YELLOW v1.0. Not used in the current version.

Message: `"Error during steganography because '<reason>'"`.


### `UnstegaError`

Reserved for YELLOW v1.0. Not used in the current version.

Message: `"Error during unsteganography because '<reason>'"`.


### `KeyxError`

Raised for any error related to the state or format of a Keyx.

Message: `"Keyx error because '<reason>'"`.

Possible causes:
- Incorrect file extension.
- Incompatible file magic (wrong Keyx type).
- Corrupted file.
- File not found.
- Operation on a closed session.
- Empty field in a bluekeys entry.


### `KeyNameError`

Raised for errors related to entry names in a Keyx.

Message: `"Key name error because '<reason>'"`.

Possible causes:
- Entry not found (in `getkey`, `get`, `update`, `rename`, `delete`).
- Duplicate name (in `add`).
- Empty name (in `add`, `rename`).
- Name collision (in `rename`).


### `WrongPasswordError`

Raised when the password provided to a Keyx is incorrect.

Message: `"Wrong password"`.

Raised by `open()`, `destroy()` (if `passwordrequired=True`), and `changepwd()` (if the old password is wrong).


## Catching usage

```python
import pycryptox as crx

# Catch all Pycryptox errors
try:
    crx.purple.decrypt("1", "wrong-pwd", bundle)
except crx.DecryptionError:
    print("Decryption failed")
except crx.PycryptoxError:
    print("Other Pycryptox error")

# Specifically catch Keyx errors
try:
    with crx.keyx.purplekeys.open("pwd", "store.purple") as s:
        s.getkey("unknown")
except crx.WrongPasswordError:
    print("Incorrect password")
except crx.KeyNameError:
    print("Entry not found")
except crx.KeyxError:
    print("Keyx problem")
```
