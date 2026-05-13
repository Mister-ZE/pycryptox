# Examples

This page gathers code examples covering all features of Pycryptox. Each example is self-contained and can be copy-pasted directly.

```python
import pycryptox as crx
```


## PURPLE — Password-based encryption

### Encrypt and decrypt a message

```python
ct = crx.purple.encrypt("1", "my-password", "Confidential message")
pt = crx.purple.decrypt("1", "my-password", ct)
print(pt)  # → "Confidential message"
```

### Generate a secure passphrase

```python
passphrase = crx.purple.genkeys("1")
print(passphrase)  # → "abandon ability able about above absent" (example)

ct = crx.purple.encrypt("1", passphrase, "Protected by an EFF passphrase")
pt = crx.purple.decrypt("1", passphrase, ct)
```

### Extract the version of a bundle

```python
ct = crx.purple.encrypt("1", "pwd", "hello")
version = crx.purple.getversion(ct)
print(version)  # → "1.0"
```

### Handle a wrong password

```python
ct = crx.purple.encrypt("1", "good-password", "secret")

try:
    crx.purple.decrypt("1", "wrong-password", ct)
except crx.DecryptionError:
    print("Incorrect password or corrupted message")
```

### Encrypting the same message multiple times produces different bundles

```python
ct1 = crx.purple.encrypt("1", "pwd", "same message")
ct2 = crx.purple.encrypt("1", "pwd", "same message")
print(ct1 == ct2)  # → False (random salt and nonce)
```


## BLUE — Deniable asymmetric encryption

### Generate a keyring

```python
keys = crx.blue.genkeys("1")
print(keys.keys())  # → dict_keys(['gpubkey', 'xprivkey', 'yprivkey'])
```

### Dual encryption (real message + decoy)

```python
keys = crx.blue.genkeys("1")

bundle = crx.blue.encrypt("1", keys["gpubkey"],
                          xmsg="Meet at 2pm at the bridge",
                          ymsg="I'll send you the cake recipe tomorrow")

# With xprivkey → real message
real = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(real)  # → "Meet at 2pm at the bridge"

# With yprivkey → decoy
decoy = crx.blue.decrypt("1", keys["yprivkey"], bundle)
print(decoy)  # → "I'll send you the cake recipe tomorrow"
```

### Mono encryption (without deniability)

```python
keys = crx.blue.genkeys("1")

# Only the x channel is used
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="Simple message")
pt = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(pt)  # → "Simple message"

# The y channel contains undecryptable noise
try:
    crx.blue.decrypt("1", keys["yprivkey"], bundle)
except crx.DecryptionError:
    print("The y channel is undecryptable (ephemeral key destroyed)")
```

### Wrong private key

```python
keys_alice = crx.blue.genkeys("1")
keys_bob = crx.blue.genkeys("1")

bundle = crx.blue.encrypt("1", keys_alice["gpubkey"], xmsg="For Alice")

try:
    crx.blue.decrypt("1", keys_bob["xprivkey"], bundle)
except crx.DecryptionError:
    print("Bob's key does not decrypt Alice's bundle")
```

### Messages in different buckets → error

```python
keys = crx.blue.genkeys("1")

try:
    crx.blue.encrypt("1", keys["gpubkey"],
                     xmsg="Short",
                     ymsg="x" * 5000)  # 5 KB → bucket different from "Short" (< 4 KB)
except crx.EncryptionError as e:
    print(f"Error: {e}")
```


## RED — Threshold encryption

### 2-of-3 encryption

```python
keys = crx.red.genkeys("1", t=2, n=3)

bundle = crx.red.encrypt("1", keys["gpubkey"], "Vault code: 7491")

# 2 shares are enough
pt = crx.red.decrypt("1", keys["privkeys"][:2], bundle)
print(pt)  # → "Vault code: 7491"

# Any combination of 2
pt = crx.red.decrypt("1", [keys["privkeys"][0], keys["privkeys"][2]], bundle)
print(pt)  # → "Vault code: 7491"
```

### A single share is not enough

```python
keys = crx.red.genkeys("1", t=2, n=3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "secret")

try:
    crx.red.decrypt("1", [keys["privkeys"][0]], bundle)
except crx.DecryptionError:
    print("Impossible with a single share (threshold = 2)")
```

### 1-of-N threshold (redundancy)

```python
keys = crx.red.genkeys("1", t=1, n=5)
bundle = crx.red.encrypt("1", keys["gpubkey"], "Each share is enough on its own")

# Any single share is enough
for i in range(5):
    pt = crx.red.decrypt("1", [keys["privkeys"][i]], bundle)
    assert pt == "Each share is enough on its own"
print("All 5 shares decrypt individually")
```

### Duplicated shares → error

```python
keys = crx.red.genkeys("1", t=2, n=3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "test")

try:
    crx.red.decrypt("1", [keys["privkeys"][0], keys["privkeys"][0]], bundle)
except crx.DecryptionError:
    print("Duplicated shares rejected")
```


## keyx.purplekeys — Key storage

### Create, add, read, modify, delete

```python
crx.keyx.purplekeys.createdb("master", "secrets.purple")

with crx.keyx.purplekeys.open("master", "secrets.purple") as s:
    # Add
    s.add("gmail", "G00gleP@ss!")
    s.add("github", "gh-token-abc")
    s.add("aws", "AKIA1234567890")

    # Read
    print(s.getkey("gmail"))       # → "G00gleP@ss!"
    print(len(s))                  # → 3
    print(s.listallnames())        # → ["aws", "gmail", "github"]

    # Search
    print(s.search("gi"))          # → ["github"]

    # Check existence
    print("gmail" in s)            # → True
    print("slack" in s)            # → False

    # Modify
    s.update("gmail", "NewP@ss2025!")

    # Rename
    s.rename("aws", "aws-prod")

    # Delete
    s.delete("github")

    print(s.listallnames())        # → ["aws-prod", "gmail"]
```

### Verify a password without opening

```python
print(crx.keyx.purplekeys.verify("master", "secrets.purple"))  # → True
print(crx.keyx.purplekeys.verify("wrong", "secrets.purple"))   # → False
```

### Change the password

```python
with crx.keyx.purplekeys.open("master", "secrets.purple") as s:
    s.changepwd("master", "new-master")

# The old password no longer works
try:
    crx.keyx.purplekeys.open("master", "secrets.purple")
except crx.WrongPasswordError:
    print("Old password rejected")
```

### Backup

```python
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    s.backup("secrets.backup.purple")

# The backup is a valid Keyx
with crx.keyx.purplekeys.open("new-master", "secrets.backup.purple") as s:
    print(s.listallnames())
```

### Automatic rollback on error

```python
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    print(len(s))  # → 2
    s.add("temporary", "xyz")
    # len(s) is now 3 in memory

try:
    with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
        s.add("poison", "data")
        raise RuntimeError("simulated crash")
except RuntimeError:
    pass

# "poison" was NOT committed
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    print("poison" in s)  # → False
```

### Destroy a Keyx

```python
crx.keyx.purplekeys.destroy("new-master", "secrets.purple")

# Force destroy (without verifying the password)
crx.keyx.purplekeys.createdb("pwd", "temp.purple")
crx.keyx.purplekeys.destroy("anything", "temp.purple", passwordrequired=False)
```


## keyx.bluekeys — BLUE channel storage

### Store and retrieve a channel

```python
my_keys = crx.blue.genkeys("1")
alice_gpubkey = "..."  # received from Alice through another channel

crx.keyx.bluekeys.keys.createdb("master", "channels.keys")

with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    s.add("alice", my_keys["gpubkey"], alice_gpubkey, my_keys["xprivkey"])

    entry = s.get("alice")
    print(entry.keys())  # → dict_keys(['mygpubkey', 'hgpubkey', 'privkey'])
```

### Partial update of a channel

```python
new_keys = crx.blue.genkeys("1")

with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    # Update only the private key, without touching the public keys
    s.update("alice", privkey=new_keys["xprivkey"])

    entry = s.get("alice")
    print(entry["privkey"] == new_keys["xprivkey"])  # → True
    # mygpubkey and hgpubkey are unchanged
```

### Use a stored channel to encrypt/decrypt

```python
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    entry = s.get("alice")

    # Encrypt a message for Alice
    bundle = crx.blue.encrypt("1", entry["hgpubkey"],
                              xmsg="Message for Alice",
                              ymsg="Nothing special")

    # Decrypt a message received from Alice
    received_bundle = "..."  # received from Alice
    pt = crx.blue.decrypt("1", entry["privkey"], received_bundle)
```


## Complete scenario: deniability with keyx

```python
# Bob generates his BLUE keys
bob_keys = crx.blue.genkeys("1")
alice_gpubkey = "..."  # received from Alice

# Bob creates two Keyx: standard (machine) and critical (USB)
crx.keyx.bluekeys.keys.createdb("master", "channels.keys")
crx.keyx.bluekeys.ckeys.createdb("master", "/usb/critical.ckeys")

# yprivkey (decoy) → standard Keyx
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    s.add("alice", bob_keys["gpubkey"], alice_gpubkey, bob_keys["yprivkey"])

# xprivkey (real) → critical Keyx on USB
with crx.keyx.bluekeys.ckeys.open("master", "/usb/critical.ckeys") as s:
    s.add("alice", bob_keys["gpubkey"], alice_gpubkey, bob_keys["xprivkey"])

# Alice encrypts a dual message for Bob
bundle = crx.blue.encrypt("1", bob_keys["gpubkey"],
                          xmsg="Coordinates: 48.8566, 2.3522",
                          ymsg="Hi, see you tomorrow?")

# Normal situation: Bob decrypts with the real key (from USB)
with crx.keyx.bluekeys.ckeys.open("master", "/usb/critical.ckeys") as s:
    entry = s.get("alice")
    real = crx.blue.decrypt("1", entry["cprivkey"], bundle)
    print(real)  # → "Coordinates: 48.8566, 2.3522"

# Under coercion: Bob opens the standard Keyx (on his machine)
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    entry = s.get("alice")
    decoy = crx.blue.decrypt("1", entry["privkey"], bundle)
    print(decoy)  # → "Hi, see you tomorrow?"
    # The adversary obtains a credible message. They cannot prove
    # that the x channel exists.
```


## Error handling

### Catch all Pycryptox errors

```python
try:
    crx.purple.decrypt("1", "pwd", "invalid-bundle")
except crx.DecryptionError:
    print("Specific decryption error")
except crx.PycryptoxError:
    print("Other Pycryptox error")
```

### Type errors

```python
try:
    crx.purple.encrypt("1", 123, "msg")  # 123 is not a str
except crx.ArgumentTypeError:
    print("Invalid argument type")
```

### Keyx errors

```python
try:
    crx.keyx.purplekeys.open("pwd", "nonexistent.purple")
except crx.KeyxError:
    print("File not found or corrupted")

try:
    crx.keyx.purplekeys.createdb("pwd", "file.txt")  # wrong extension
except crx.KeyxError:
    print("The extension must be .purple")
```

### Version error

```python
try:
    crx.purple.encrypt("99", "pwd", "msg")
except crx.VersionNotFoundError:
    print("Version 99 unknown")
```


## keyx file discrimination

```python
crx.keyx.purplekeys.createdb("pwd", "p.purple")
crx.keyx.bluekeys.keys.createdb("pwd", "k.keys")
crx.keyx.bluekeys.ckeys.createdb("pwd", "c.ckeys")

# Each module refuses files of the others
try:
    crx.keyx.purplekeys.open("pwd", "k.keys")  # extension .keys ≠ .purple
except crx.KeyxError:
    print("purplekeys refuses a .keys file")

try:
    crx.keyx.bluekeys.keys.open("pwd", "c.ckeys")  # extension .ckeys ≠ .keys
except crx.KeyxError:
    print("bluekeys.keys refuses a .ckeys file")

# Even with a renamed extension, the magic bytes reject
import shutil
shutil.copy("k.keys", "spoofed.purple")
try:
    crx.keyx.purplekeys.open("pwd", "spoofed.purple")
except crx.KeyxError:
    print("Incompatible magic bytes — double protection")
```
