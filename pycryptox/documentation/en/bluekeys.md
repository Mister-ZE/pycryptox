# keyx.bluekeys

`bluekeys` is an encrypted key manager for storing BLUE communication channels. It consists of two sub-modules:

- **`crx.keyx.bluekeys.keys`** — stores standard BLUE channels (`.keys` extension).
- **`crx.keyx.bluekeys.ckeys`** — stores critical/deniable BLUE channels (`.ckeys` extension).

Both sub-modules have the same API except for three details: the file extension, the file magic, and the name of the private-key field (`privkey` vs `cprivkey`).


## Why two separate sub-modules

The separation between `keys` and `ckeys` serves the **plausible deniability** of the BLUE protocol.

In a deniability scenario, the user holds two private keys for each channel: a decoy key and a real key. The decoy key is stored in the `keys` keystore, accessible on the user's machine. Why store the decoy in the main keystore? Because that is the keystore the adversary will force the user to open under coercion. The adversary will find the decoy key there, decrypt the decoy message, and obtain a credible result — without knowing that another key exists elsewhere.

The real key is stored in the `ckeys` keystore, on a physically separate medium (USB drive, external disk, etc.) that is not present at the moment of coercion. The adversary cannot force the opening of a file whose existence they ignore and which is physically absent.

The library provides both stores. Management of the physical medium (USB, file separation) is the responsibility of the user or the CLI software.


## Entry schema

Each entry in a bluekeys keystore represents a **correspondence channel** (not a person). The user freely chooses the name of each channel.

### `keys` — fields per entry

| Field | Type | Description |
|---|---|---|
| `mygpubkey` | `str` | My BLUE composite public key for this channel. |
| `hgpubkey` | `str` | The BLUE composite public key of my correspondent. |
| `privkey` | `str` | My private key for this channel. |

### `ckeys` — fields per entry

| Field | Type | Description |
|---|---|---|
| `mygpubkey` | `str` | My BLUE composite public key for this channel. |
| `hgpubkey` | `str` | The BLUE composite public key of my correspondent. |
| `cprivkey` | `str` | My critical private key for this channel. |

The only schema difference is the name of the third field: `privkey` in `keys`, `cprivkey` in `ckeys`. All fields are `str` (base64url), non-empty, mandatory.


## File format

Both sub-modules use the same layout as purplekeys:

```
[16 bytes: magic]  [4 bytes: head_len (BE32)]  [head_ct]  [payload_ct]
```

| Sub-module | Magic | Extension |
|---|---|---|
| `keys` | `CRXKX_BLUEKEYS_1` | `.keys` |
| `ckeys` | `CRXKX_BLUECKEY_1` | `.ckeys` |

The files are encrypted with PURPLE. Integrity is guaranteed by the Poly1305 tag. Writes are atomic.

Magic-based discrimination prevents opening a `.ckeys` file with the `keys` module (and vice versa), even if the extension is manually renamed. This is double protection: extension + magic.


## API

The API is identical between `keys` and `ckeys`. The examples below use `keys`; for `ckeys`, replace `keys` with `ckeys`, `.keys` with `.ckeys`, and `privkey` with `cprivkey`.


### Module functions

#### `createdb(password, dbpath) -> None`

Creates a new empty keystore.

```python
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")
crx.keyx.bluekeys.ckeys.createdb("master-pwd", "/usb/critical.ckeys")
```

**Exceptions**:
- `KeystoreError` — if the file already exists or if the extension is incorrect.
- `ArgumentTypeError` — if `password` is not a `str`.

#### `open(password, dbpath) -> _KeysSession / _CKeysSession`

Opens an existing keystore. Returns a session (context manager).

```python
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    ...
```

**Exceptions**:
- `WrongPasswordError` — incorrect password.
- `KeystoreError` — file not found, corrupted, invalid magic, or incorrect extension.

#### `verify(password, dbpath) -> bool`

Verifies the password without opening the keystore. `True` = correct, `False` = incorrect. Raises `KeystoreError` if the file is not a valid keystore of the right type.

#### `destroy(password, dbpath, passwordrequired=True) -> None`

Deletes the keystore. Raises `WrongPasswordError` if the password is wrong (unless `passwordrequired=False`).


### Session methods

All methods raise `KeystoreError` if the session is closed.

#### `session.add(name, mygpubkey, hgpubkey, privkey) -> None`

For `ckeys`: `session.add(name, mygpubkey, hgpubkey, cprivkey)`.

Adds a channel. All fields are `str`, non-empty, mandatory.

**Exceptions**:
- `KeyNameError` — if `name` already exists or is empty.
- `KeystoreError` — if a value is empty.
- `ArgumentTypeError` — if an argument is not a `str`.

#### `session.get(name) -> dict[str, str]`

Returns a dictionary with the three fields of the entry. The returned dictionary is independent of the session: modifying it does not change the keystore.

```python
entry = s.get("alice")
# keys:  {"mygpubkey": ..., "hgpubkey": ..., "privkey": ...}
# ckeys: {"mygpubkey": ..., "hgpubkey": ..., "cprivkey": ...}
```

Raises `KeyNameError` if `name` does not exist.

#### `session.update(name, mygpubkey=None, hgpubkey=None, privkey=None) -> None`

For `ckeys`: use `cprivkey=` instead of `privkey=`.

Partial update: only the fields provided (non-`None`) are modified. Fields not provided remain unchanged. Calling `update(name)` with no fields is a silent no-op.

**Exceptions**:
- `KeyNameError` — if `name` does not exist.
- `KeystoreError` — if a provided value is empty.

#### `session.exists(name) -> bool`

#### `session.__contains__(name) -> bool`

Allows `"alice" in session`.

#### `session.__len__() -> int`

#### `session.listallnames() -> list[str]`

Returns the sorted list of all channel names.

#### `session.search(keyword, maxlen=20) -> list[str]`

Fuzzy search by channel name. Same algorithm as purplekeys.

#### `session.getdb() -> dict[str, dict[str, str]]`

Returns an independent copy of all entries. The returned dictionary and its sub-dictionaries can be modified without affecting the session.

#### `session.rename(old_name, new_name) -> None`

Renames a channel. Same rules as purplekeys.

#### `session.delete(name) -> None`

Deletes a channel. Raises `KeyNameError` if `name` does not exist.

#### `session.changepwd(old_password, new_password) -> None`

Changes the master password. Raises `WrongPasswordError` if the old password is wrong.

#### `session.backup(target_path) -> None`

Creates a copy of the keystore. The extension of `target_path` must match the keystore type (`.keys` for keys, `.ckeys` for ckeys).

#### `session.close(commit=True) -> None`

Closes the session. `commit=True` = writes modifications. `commit=False` = abandons them. Idempotent.


## Cross-module discrimination

A `.keys` file cannot be opened by `ckeys.open()` and vice versa. The check is performed at two levels:

1. **Extension**: `keys` refuses anything that is not `.keys`, `ckeys` refuses anything that is not `.ckeys`.
2. **Magic**: even if the extension is manually renamed, the 16-byte magic in the file header identifies the actual type. An incompatible magic raises `KeystoreError`.

Likewise, neither `keys` nor `ckeys` can open a `purplekeys` file (extension `.purple`, magic `CRXKX_PURPLE_V1\x00`), and conversely.
