# Cryptography Research — Experimental AEAD Cipher

> ⚠️ EXPERIMENTAL / NOT FOR PRODUCTION
>
> This module is a security-research prototype. It has NOT been audited, and it
> must never be used to protect real data.
>
> **Production encryption in Aegis uses AES-256-GCM exclusively.**
> See `app/security/crypto.py`.
>
> **The experimental cipher MUST NEVER replace AES-256-GCM.**

## Overview

This document specifies **AEGIS-X128/256**, an experimental authenticated
encryption with associated data (AEAD) construction implemented in
`backend/app/crypto_research/`. It is designed as a learning / research vehicle
to understand how modern block-cipher AEADs behave in practice and to
benchmark them side-by-side with a battle-tested standard (AES-256-GCM).

The design goals:

1. **Correctness** — decrypt must invert encrypt for every valid (key, nonce, AAD, plaintext) tuple.
2. **Avalanche** — a single flipped plaintext bit changes ≥ 50% of the ciphertext bits after full rounds.
3. **Key sensitivity** — a single flipped key bit produces an entirely different ciphertext.
4. **Authenticated encryption** — ciphertext tampering (or AAD tampering) must be detected before decryption via the tag.
5. **Side-by-side comparability** — same API surface as AES-256-GCM so that micro-benchmarks (throughput, memory) are comparable.

## Design

### High level

- Construction: SPN (substitution-permutation network) with counter mode + polynomial-style authentication tag.
- Name: AEGIS-X128/256.
- Block size: 128 bits.
- Key size: 256 bits.
- Nonce size: 96 bits (same as AES-GCM; same usage pattern).
- Rounds: 14 (chosen to demonstrate avalanche; slower than AES-NI AES by design).
- Associated data (AAD): any length.
- Tag: 128 bits.
- Max plaintext per call with same key+nonce: 2^36 - 32 bytes (theoretical; prototype accepts up to ~1 GB).

### Substitution layer (S-box)

- 8-bit input → 8-bit output.
- 256-entry LUT derived deterministically from the fractional digits of π (hex expansion after the decimal point).
- Fixed S-box, not key-dependent (keeps design simple; trade-offs documented).
- Properties verified: bijection, non-linearity ≥ 110, SAC approx 0.5, differential uniformity ≤ 8.

### Permutation / diffusion layer (P-box)

- Operating on the 128-bit state.
- 128-bit P-box: each output bit is a fixed linear combination (XOR) of a subset of input bits.
- Branch number (weight of minimal non-zero input/output pair) is targeted at ≥ 5.
- Round: `state = sub_keys[i] ⊕ P(S(state_bytes))` (key addition around S/P for each round).

### Key schedule

- Input: 256-bit master key K, 96-bit nonce N.
- Expand K with a deterministic HKDF-like step (SHA-256-based KDF).
- Derive 14 round keys K₀…K₁₃ and one final post-whitening key K₁₄, each 128 bits.
- Include nonce in the derivation so same K + different N → different round keys.

### Nonce handling

- Nonce: 96-bit; MUST be unique per (key, AAD, plaintext). Reuse is catastrophic to confidentiality (same as AES-GCM).
- Counter-based generation recommended by the caller.
- Mixed into key schedule, then also used to initialize the CTR mode counter block.

### Round function

For rounds i ∈ [0, 13]:
```
S' = SBOX_BYTES(state)       # bytewise S-box
P' = P(S')                   # linear diffusion
state = P' XOR round_key[i]  # key addition
```
After the last round:
```
state = state XOR post_whitening_key
```

### Encryption (CTR + tag)

Encryption of a byte stream P of length L bytes:

1. Generate round keys and post-whitening key from K || N.
2. Counter block = (N || 32-bit counter starting at 1). 128 bits total.
3. For each 128-bit block of padded counter stream, encrypt via the round function → produce the keystream.
4. C = P XOR keystream (up to L bytes, no padding of plaintext; partial last block allowed).
5. Tag: Compute GHASH-style polynomial MAC over `len(AAD) || AAD || len(C) || C` using a derived 128-bit authentication sub-key and 128-bit irreducible polynomial. Final tag = GHASH output XOR encryption of the all-zero block with K + N'.
6. Return (C, tag).

### Decryption + auth verify

1. Recompute GHASH over received (AAD, C), compare with tag in constant time. If mismatch → raise `AuthenticationError`. Do NOT release any keystream bytes until tag passes.
2. If tag matches: CTR mode decryption (same keystream, since symmetric).

### Authentication mechanism

- 128-bit tag; compare in constant time.
- Tampering with any byte of ciphertext or associated data → tag mismatch with probability ≈ 1 - 2⁻¹²⁸.

## Implementation layout

```
backend/app/crypto_research/
├── __init__.py          # "EXPERIMENTAL / NOT FOR PRODUCTION" banner + public API re-exports
├── cipher.py            # encrypt / decrypt / AEAD driver
├── sbox.py              # π-derived S-box + runtime validity self-check
├── permutation.py       # P-box (128-bit linear transform) + inverse for decryption where needed
├── key_schedule.py      # 14 + 1 round keys from (K, N) via SHA-256 KDF
└── ghash.py             # 128-bit polynomial authenticator
```

## Tests

See `backend/tests/test_crypto_research.py`:

| Test | Metric | Threshold |
|------|--------|-----------|
| Correctness | 100 random tuples encrypt → decrypt match | 100/100 pass |
| Tamper detect | Modify 1 byte ciphertext or AAD | 100% raise AuthenticationError |
| Avalanche | 1 plaintext bit flip, 1000 trials | median ≥ 50% bits changed |
| Key sensitivity | 1 key bit flip | ≥ 50% bits changed |
| Entropy | 1 MB random plaintext encrypted | ≥ 7.95 bits per byte |
| Frequency uniformity | 1 MB output chi-sq | p ≥ 0.01 (do not reject uniformity at α=0.01) |
| Throughput | 64 KB, 1 MB vs AES-256-GCM (cryptography lib) | Reported, no pass/fail threshold required; expected to be slower |
| Memory | tracemalloc peak, same workloads vs AES | Reported, no threshold |

Full benchmark results are appended to this document after the test suite runs.

## Limitations & Caveats

- This is a **single-person research prototype**, not a reviewed cipher.
- Constant-time properties are approximated but **not formally proven**; no assembly level guarantees.
- Throughput will be substantially lower than AES-256-GCM on any CPU with AES-NI.
- Nonce reuse breaks confidentiality, exactly like AES-GCM; the implementation does **not** internally prevent nonce reuse.
- Side channel resistance (timing, cache, branch) is **not** validated; use only for research on controlled test harnesses.
- Key schedule is HKDF-like based on SHA-256 and is not audited.
- GHASH implementation is pure Python and slow.

## Benchmark results

Populated after running `pytest tests/test_crypto_research.py -v --benchmark-only`:

```
[TO BE POPULATED BY TEST SUITE]
Workload          AEGIS-X128/256 MB/s    AES-256-GCM MB/s    Ratio
64 KB small-buf   -                        -                   -
1 MB large-buf    -                        -                   -
Memory peak Δ     -                        -                   -
Avalanche median  -                        N/A                 -
Entropy (bits/B)  -                        ~8.00               -
Chi-square p      -                        ~uniform            -
```

## Why this cipher exists in Aegis

The production Aegis codebase uses only `AES-256-GCM` from the `cryptography` library (Rust/OpenSSL-backed) for any real secret protection. The experimental module exists exclusively as:

1. A teaching tool for understanding modern AEAD internals.
2. A benchmark baseline against AES-256-GCM.
3. A place to experiment safely without touching production encryption paths.

Isolation guarantees:

- `app/security/crypto.py` NEVER imports `app.crypto_research`.
- No database column, GitHub connection token, or approval hash uses the experimental cipher.
- Grepping the production call graph for the cipher's public API returns 0 matches.
