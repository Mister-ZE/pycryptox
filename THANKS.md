# Thanks to

Pycryptox is the work of one author, but it stands on the shoulders of many people, organisations, and projects whose work made it possible. This page acknowledges them.


## Cryptographic primitives and libraries

**[Open Quantum Safe (OQS) project](https://openquantumsafe.org/)** — for `liboqs` and `liboqs-python`, the ML-KEM-512 implementation that Pycryptox's BLUE and RED protocols rely on. Without their long-term effort to make post-quantum primitives accessible from a high-level language, this library would not exist in its current form.

**[PyCA — Python Cryptographic Authority](https://github.com/pyca/cryptography)** — for the `cryptography` package providing battle-tested ChaCha20-Poly1305 (and many other primitives Pycryptox uses internally). The PyCA team's work on secure-by-default API design is a constant source of inspiration.

**[Argon2-cffi maintainers](https://github.com/hynek/argon2-cffi)** (Hynek Schlawack and contributors) — for the Python bindings to Argon2 that PURPLE depends on for its KDF. Memory-hard password hashing in Python remains accessible thanks to this work.

**[RapidFuzz maintainers](https://github.com/rapidfuzz/RapidFuzz)** — for the high-performance fuzzy-matching library used by Keyx's passphrase recovery hints.


## Standards and research

**The NIST PQC team and submitters of Kyber/ML-KEM** — for the standardisation effort that produced FIPS 203 (August 2024). ML-KEM-512 is the foundation on which BLUE and RED are built.

**The Argon2 team** (Alex Biryukov, Daniel Dinu, Dmitry Khovratovich) — for designing the password-hashing function used by PURPLE, and for the parameter recommendations later codified in RFC 9106.

**Adi Shamir** — whose 1979 paper *How to Share a Secret* underlies RED's threshold scheme.

**Daniel J. Bernstein** — for ChaCha20 and the surrounding family of primitives that make modern symmetric encryption fast, simple, and safe.


## Wordlist

**[Electronic Frontier Foundation](https://www.eff.org/dice)** — for releasing the EFF Large Wordlist for Passphrases (7776 carefully curated English words) under a permissive licence. PURPLE's passphrase generator uses it directly.


## Inspiration

**The Snowden disclosures, work by Ross Anderson, Bruce Schneier, Matthew Green, and many others** — for decades of public-facing security writing that shaped this project's commitment to honest threat modelling. The **Me vs Opponent** documentation sections in particular reflect their insistence that cryptographic engineering is meaningful only when paired with a clear adversary model.

**[Signal Protocol](https://signal.org/docs/) and its designers** — for showing that production-grade, deniable, post-compromise-secure protocols are achievable in practice.

**[age](https://age-encryption.org/) by Filippo Valsorda and Ben Cartwright-Cox** — for demonstrating what a minimal, well-thought-out modern encryption tool looks like. Pycryptox aims to follow the same principle of "small, opinionated, explicit" at the protocol level.


## Reviewers, testers, and conversations

**u/Cryptizard on [r/crypto](https://www.reddit.com/r/crypto/)** — for a careful public review of an early BLUE design, confirming that simple concatenation of two ciphertexts with equal-size padding provides the same security guarantee as the more complex (and ultimately removed) chemical-mixing approach, as long as the underlying primitives are IND$-CPA secure. This review validated the direction taken by the BLUE v2.0 simplified wire format `[order_flag][len][enc_x][enc_y]`. Cryptizard also pointed to a richer multi-slot model of plausible deniability, referencing Erik-Oliver Blass, Travis Mayberry, Guevara Noubir and Kaan Onarlioglu: *"Toward Robust Hidden Volumes Using Write-Only Oblivious RAM"* (CCS 2014, pp. 203–214) — an avenue the project may explore in future versions.

Any further name added here will be done with explicit consent. If you have provided substantive feedback, cryptanalysis, or critique privately, contact me at [z.e.pro@outlook.fr](mailto:z.e.pro@outlook.fr) and I will add an acknowledgement.


## Open issues, open arms

Pycryptox is far from finished. If you spot an error in this acknowledgement page (a missing dependency, an incorrect attribution, a maintainer name spelled wrong), please flag it. Credit where credit is due is a non-negotiable principle of this project.
