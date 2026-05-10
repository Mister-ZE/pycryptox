# Pycryptox

Post-quantum cryptography library for Python.

Four protocols, one goal: protect your data against today's threats and tomorrow's quantum computers.

| Protocol   | What it does                                         |
| ---------- | ---------------------------------------------------- |
| **PURPLE** | Encrypt with a password                              |
| **BLUE**   | Encrypt with asymmetric keys + plausible deniability |
| **RED**    | Encrypt with a threshold (t-of-n)                    |
| **YELLOW** | Steganography *(coming soon)*                        |

```python
import pycryptox as crx

keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real", ymsg="decoy")
crx.blue.decrypt("1", keys["xprivkey"], bundle)  # → "real"
crx.blue.decrypt("1", keys["yprivkey"], bundle)  # → "decoy"
```

## Documentation

📖 [English](documentation/en/INDEX.md) · [Français](documentation/fr/INDEX.md)

## Tests

🧪 [Test suite](tests/run_all.py) — 162 tests covering all protocols and keystores.

```bash
cd pycryptox/tests
python run_all.py
```

## Credits

©️See [CREDITS.md](CREDITS.md)
