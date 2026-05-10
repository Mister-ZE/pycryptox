# YELLOW protocol (placeholder)

YELLOW is the steganography protocol of Pycryptox. Its goal is to conceal encrypted data inside innocuous-looking documents (images, texts, audio files) so that an observer cannot detect even the presence of an encrypted message.

**YELLOW is not implemented in this version of Pycryptox.** The module exists as a placeholder and its functions produce no useful result.


## Current API

### `crx.yellow.stega(version) -> str`

Returns a placeholder string. No actual processing.

### `crx.yellow.unstega(version) -> str`

Returns a placeholder string. No actual processing.

Both functions accept the `version` parameter to respect the common convention of Pycryptox protocols, but do nothing.


## Future goal

YELLOW v1.0 will add:

- `stega(version, msg, cover)` — conceals `msg` (an already-encrypted PURPLE, BLUE, or RED bundle) in a cover file `cover`.
- `unstega(version, stego)` — extracts the hidden bundle from a steganographed file.

The protocol will be designed so that the steganographed file is statistically indistinguishable from the original to an observer who does not know the key.


## Why YELLOW is separate from the other protocols

YELLOW is not an encryption protocol. It operates on the result of an already-performed encryption. Its role is concealment, not confidentiality. The typical combination is: encrypt with BLUE, then conceal with YELLOW before transmission over a monitored network.


## Version history

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any processing.

- `stega("0.0")` → `"Actually... there's nothing I can return."`
- `unstega("0.0")` → `"Actually... there's nothing I can return."`
