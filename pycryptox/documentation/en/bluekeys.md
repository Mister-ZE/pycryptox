# keyx.bluekeys

`bluekeys` is an encrypted key manager for storing BLUE communication channels. It consists of two sub-modules:

- **`crx.keyx.bluekeys.keys`** — stores standard BLUE channels (`.keys` extension).
- **`crx.keyx.bluekeys.ckeys`** — stores critical/deniable BLUE channels (`.ckeys` extension).

Both sub-modules have the same API except for three details: the file extension, the file magic, and the name of the private-key field (`privkey` vs `cprivkey`).


## Why two separate sub-modules

The separation between `keys` and `ckeys` serves the **plausible deniability** of the BLUE protocol.

In a deniability scenario, the user holds two private keys for each channel: a decoy key and a real key. The decoy key is stored in the `keys` Keyx, accessible on the user's machine. Why store the decoy in the main Keyx? Because that is the Keyx the adversary will force the user to open under coercion. The adversary will find the decoy key there, decrypt the decoy message, and obtain a credible result — without knowing that another key exists elsewhere.

The real key is stored in the `ckeys` Keyx, on a physically separate medium (USB drive, external disk, etc.) that is not present at the moment of coercion. The adversary cannot force the opening of a file whose existence they ignore and which is physically absent.

The library provides both stores. Management of the physical medium (USB, file separation) is the responsibility of the user or the CLI software.


## Entry schema

Each entry in a bluekeys Keyx represents a **correspondence channel** (not a person). The user freely chooses the name of each channel.

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

#### `createdb(password, dbpath, level="strong") -> None`

Creates a new empty Keyx.

```python
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")                     # default level = "strong"
crx.keyx.bluekeys.ckeys.createdb("master-pwd", "/usb/critical.ckeys", level="extreme")
```

| Parameter | Type | Description |
|---|---|---|
| `password` | `str` | Master password. |
| `dbpath` | `str \| Path` | File path. Must end with `.keys` (for `keys`) or `.ckeys` (for `ckeys`). |
| `level` | `str` | Argon2id strength level. One of `"low"`, `"normal"`, `"strong"`, `"extreme"`. Default `"strong"`. |

The level is embedded in the file and read automatically at `open()`.

**Exceptions**:
- `KeyxError` — if the file already exists, the extension is incorrect, or `level` is unknown.
- `ArgumentTypeError` — if `password` or `level` is not a `str`.

#### `open(password, dbpath) -> _KeysSession / _CKeysSession`

Opens an existing Keyx. Returns a session (context manager).

```python
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    ...
```

The session inherits the Argon2id level from the file. Use `session.getlevel()` to inspect it and `session.changelevel(new_level)` to migrate to a different level on next save.

**Exceptions**:
- `WrongPasswordError` — incorrect password.
- `KeyxError` — file not found, corrupted, invalid magic, incorrect extension, or created by pycryptox < 3.0.0 (PURPLE v1.0 keyx files are not supported in 3.0.0+; see *Migrating from 2.x* below).

#### `verify(password, dbpath) -> bool`

Verifies the password without opening the Keyx. `True` = correct, `False` = incorrect. Raises `KeyxError` if the file is not a valid Keyx of the right type or was created by pycryptox < 3.0.0.

#### `destroy(password, dbpath, passwordrequired=True) -> None`

Deletes the Keyx. Raises `WrongPasswordError` if the password is wrong (unless `passwordrequired=False`). Raises `KeyxError` if the file was created by pycryptox < 3.0.0 and `passwordrequired=True`.


### Session methods

All methods raise `KeyxError` if the session is closed.

#### `session.add(name, mygpubkey, hgpubkey, privkey) -> None`

For `ckeys`: `session.add(name, mygpubkey, hgpubkey, cprivkey)`.

Adds a channel. All fields are `str`, non-empty, mandatory.

**Exceptions**:
- `KeyNameError` — if `name` already exists or is empty.
- `KeyxError` — if a value is empty.
- `ArgumentTypeError` — if an argument is not a `str`.

#### `session.get(name) -> dict[str, str]`

Returns a dictionary with the three fields of the entry. The returned dictionary is independent of the session: modifying it does not change the Keyx.

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
- `KeyxError` — if a provided value is empty.

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

#### `session.changelevel(new_level) -> None` *(new in v3.0.0)*

Changes the Argon2id strength level for subsequent saves. `new_level` must be one of `"low"`, `"normal"`, `"strong"`, `"extreme"`.

The change applies to the next commit. Calling with the same level as the current one is a no-op.

**Exceptions**:
- `ArgumentTypeError` — if `new_level` is not a `str`.
- `KeyxError` — if `new_level` is not a recognised level name.

#### `session.getlevel() -> str` *(new in v3.0.0)*

Returns the current Argon2id strength level of the session.

#### `session.backup(target_path) -> None`

Creates a copy of the Keyx at the current session level. The extension of `target_path` must match the Keyx type (`.keys` for keys, `.ckeys` for ckeys).

#### `session.close(commit=True) -> None`

Closes the session. `commit=True` = writes modifications. `commit=False` = abandons them. Idempotent.


## Migrating from 2.x

Pycryptox 3.0.0 hard-breaks compatibility with `.keys` and `.ckeys` files created by 2.x releases (which embedded PURPLE v1.0 bundles). Opening such a file in 3.0.0+ raises a clear error:

```
KeyxError: Error with Keyx because 'unsupported keyx PURPLE version v1.0;
this build expects v2.x (created by pycryptox 3.0.0+)'
```

There is no in-place migration tool. Use a 2.x venv to dump entries, then recreate the Keyx in 3.0.0+ with the level of your choice.


## Cross-module discrimination

A `.keys` file cannot be opened by `ckeys.open()` and vice versa. The check is performed at two levels:

1. **Extension**: `keys` refuses anything that is not `.keys`, `ckeys` refuses anything that is not `.ckeys`.
2. **Magic**: even if the extension is manually renamed, the 16-byte magic in the file header identifies the actual type. An incompatible magic raises `KeyxError`.

Likewise, neither `keys` nor `ckeys` can open a `purplekeys` file (extension `.purple`, magic `CRXKX_PURPLE_V1\x00`), and conversely.
