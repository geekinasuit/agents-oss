# Test-vector provenance

Both files are upstream specification vectors, checked in verbatim. Nothing here was
transcribed, reformatted, or trimmed — a probe asserting against numbers typed from memory
would only prove that two of the same mistakes agree.

| File | Source | Retrieved | SHA-256 |
|---|---|---|---|
| `bip340-test-vectors.csv` | `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv` | 2026-08-12 | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` |
| `nip44.vectors.json` | `https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json` | 2026-08-12 | `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040` |

The CSV digest was computed at check-in (upstream publishes none), so it pins what "verbatim"
meant on the retrieval date. The JSON digest is stronger than a local pin: it is the checksum
the NIP-44 specification itself publishes for this file, so the copy here can be verified
against the spec directly, without trusting either this repository or the hosting one.

## License

- `bip340-test-vectors.csv` — BIP-340's preamble offers its reference code and test vectors
  under `BSD-2-Clause OR MIT OR CC0-1.0` (the BIP document itself is BSD-2-Clause).
- `nip44.vectors.json` — the hosting repository declares no license for the vectors file
  (its README licenses each language implementation separately, and none of those licenses
  names this file). It is normatively incorporated into the NIP-44 specification by the
  SHA-256 above.

## Why these are checked in rather than fetched

A test that reaches the network is not hermetic, is not reproducible offline, and turns an
upstream repository rename into a red build for reasons unrelated to this code. The cost is
that the vectors can go stale relative to upstream; the mitigation is that both specs are
finalized — BIP-340 vectors last grew in December 2022, and NIP-44 v2 is a versioned payload
format, so a change would arrive as v3 alongside v2 rather than as an edit to v2's vectors.

## Which vectors the probes use, and which they do not

`Bip340VectorTest` uses only the vectors whose message is 32 bytes. That is not a
convenience: nostr signs a 32-byte event id, so a fixed-32 signing path is the whole
requirement, and libsecp256k1's `schnorrsig_sign32` is the matching primitive. The four
variable-length-message vectors added in 2022-12 (indices 15–18) are therefore skipped, and
the test asserts the surviving count so the filter cannot silently empty out.

`Nip44VectorTest` uses `get_conversation_key`, `get_message_keys`, `calc_padded_len`, and
`encrypt_decrypt` from `v2.valid`, plus the `v2.invalid.get_conversation_key` and
`v2.invalid.decrypt` negative sets. It does not use `encrypt_decrypt_long_msg` (the payloads
are given as hashes rather than literals) or `invalid.encrypt_msg_lengths` (four plaintext
lengths that exercise `encrypt`'s one-line input-bounds `require` — input policy rather than
cryptography; the probe's negative claims are about decryption and key derivation, and
nothing derived from these four integers reaches a cryptographic operation).
