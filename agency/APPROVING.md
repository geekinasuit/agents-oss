# Writing an approver

This is the contract for approving a gate from any language. The `approval` tool in `agency/wiring` is one implementation of it, and [RUNNING.md](RUNNING.md) shows it in use. The tests in `agency/wiring` hold `SpecApprover`, which builds the preimage, signature and content from this document with no code shared with the real signer. A real lead accepts its approvals. The test wraps them with the real NIP-59 code, so the wrap and step 1 are the parts no independent code has checked.

An approval is a BIP-340 signature over a canonical JSON array, carried to the lead in a NIP-59 gift wrap. You need what this document does not define: [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures, [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) encryption, [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) gift wraps, and [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) authentication for a relay that requires it. Authenticate as your approver key, the one the relay admits and the notices are wrapped to.

## 1. Read the gate-open notice

Subscribe on the relay to kind 1059 events with a `#p` filter of your public key, and unwrap them with NIP-59. A notice is a rumor with these properties. Ignore anything else:

- Its kind is 14.
- Its author is the lead's public key. NIP-59 is what authenticates that: the seal's signature must verify, and the rumor's `pubkey` must equal the seal's signer. A library that skips either check lets anyone write a notice as the lead.
- It has exactly one each of the tags `agency-gate-id`, `agency-payload-digest` and `agency-nonce`, each with one value.
- Its content is the artifact, and the lowercase hex SHA-256 of the content's UTF-8 bytes equals the digest tag. Refuse a notice where it does not.

The artifact is the thing you are approving, and it comes from the lead, so show it safely: it may hold control characters. A lead may send the same notice again, so deduplicate on the nonce.

A notice does not say whether it is still open, and a relay keeps spent ones. Approving a spent nonce changes nothing, and tells you nothing either, so ask the lead's operator which gate is open.

Copy the gate id, digest and nonce exactly as they arrived. They are opaque strings, and the gate id is free text.

## 2. Build the preimage

The preimage is a JSON array of exactly five strings, in this order:

```
["agency/gate-approval/v1",PUBLIC_KEY,GATE_ID,PAYLOAD_DIGEST,NONCE]
```

`PUBLIC_KEY` is your x-only public key as 64 lowercase hex digits.

**The bytes must be exact.** The lead refuses anything that is not the one canonical spelling of these fields, so a signature over a different spelling of the same values never counts. There is no whitespace anywhere: no space after a comma, and no newline at the end. Write each string like this, in UTF-8:

| Character | Written as |
|---|---|
| `"` | `\"` |
| `\` | `\\` |
| Backspace, form feed, newline, carriage return, tab | `\b`, `\f`, `\n`, `\r`, `\t` |
| Any other character below U+0020 | `\u00xx`, with lowercase hex digits |
| Everything else, including `/`, U+007F and all non-ASCII characters | Itself, unescaped |

Characters above U+FFFF are written as themselves, in UTF-8, not as surrogate escapes. A string holding an unpaired surrogate has no UTF-8 form, so it cannot be approved. No field may be blank, meaning empty or only whitespace.

Most JSON libraries need telling. In Python the expected form is `json.dumps(fields, ensure_ascii=False, separators=(",", ":"))`, because the defaults add spaces and escape non-ASCII characters. Go's `json.Marshal` escapes `<`, `>`, `&` and U+2028 by default, so it passes a vector without them and fails on a gate id with them. If your library cannot be set to this table exactly, write the strings yourself: the table is short. Check the result against the vectors below, because an approval signed over any other spelling is rejected.

## 3. Sign

Take the SHA-256 of the preimage's UTF-8 bytes, and sign those 32 bytes with BIP-340 using your secret key and 32 fresh bytes of auxiliary data from a cryptographically secure random source. Do not hash again: the BIP-340 message is the digest. The signature is 128 lowercase hex digits.

## 4. Send it to the lead

Build a rumor and gift-wrap it to the lead with NIP-59. Date the wrap and the rumor now, and backdate only the seal: NIP-59 allows backdating the wrap too, but a relay can refuse a wrap dated in the past.

- The rumor's kind is 4901, and its author is your public key.
- The rumor has the tag `["p", LEAD_PUBLIC_KEY]`.
- The rumor's content is this JSON object, at most 16,384 characters, with no nesting beyond what is shown:

```json
{"gateId": GATE_ID,
 "nonce": NONCE,
 "payloadDigest": PAYLOAD_DIGEST,
 "evidence": {"schemeId": "bip340",
              "publicKey": PUBLIC_KEY,
              "signature": SIGNATURE,
              "gateId": GATE_ID,
              "payloadDigest": PAYLOAD_DIGEST,
              "nonce": NONCE,
              "signedPreimage": PREIMAGE}}
```

Unlike the preimage, this object has no canonical form: key order and whitespace do not matter. `signedPreimage` is the preimage from step 2 as a JSON string, so its bytes survive inside the escaping.

Leave out `carrierArtifactId`. The lead sets that field to the rumor's id and ignores anything you write there, and the signature does not cover it.

Publish the wrap to the relay. A relay's acceptance says nothing about the lead's verdict.

## What the lead checks

The preimage is the authority. The flat fields are only there to find the record, but they must agree with it. The lead accepts an approval when all of these hold:

1. The rumor has the shape in step 4: its kind, size, and string fields. Otherwise the lead drops it with no trace.
2. Its nonce is the one currently open for its gate. If not, the lead drops it with no reason recorded: a spent or mistyped nonce ends here.
3. Its digest is that gate's, and its record fits in 4,096 characters, which only an unusually long gate id would exceed. If not, the lead drops it. `lead_status` counts these under `attempts dropped on a nonce`, but only once the nonce has closed.
4. `evidence` parses, and `signedPreimage` is present and is the canonical encoding of its own fields, with the domain tag first.
5. The key and signature are lowercase hex of the right lengths, and the key is a point on the curve.
6. `schemeId` is exactly `bip340`, and the signature verifies over the SHA-256 of `signedPreimage`, under the key the preimage names. Any other scheme reads as a bad signature.
7. That key is in the lead's signed spec.
8. The `publicKey`, `gateId`, `payloadDigest` and `nonce` in `evidence` equal the preimage's, and the top-level `gateId`, `nonce` and `payloadDigest` do too.

The principal is not something you claim: the lead resolves it from your key. Approvals that fail checks 4 to 8 are recorded with a reason, and `lead_status` shows them under `approvals rejected on arrival`. The journal holds one such row per listed key on each nonce, and one more for all unlisted keys together. A second approval by the same principal on the same nonce adds nothing.

An approval counts toward one gate, once. Whether it releases the gate depends on the quorum in the spec.

## Test vectors

[wiring/testdata/approval-vectors.json](wiring/testdata/approval-vectors.json) holds worked examples, with throwaway keys and fixed auxiliary data so that the signature is reproducible. Use fixed auxiliary data only to check a vector, never to sign. The test holds them against the real signer and verifier.

| Field | Meaning |
|---|---|
| `secretKey`, `auxRand` | Your inputs to signing |
| `gateId`, `payloadDigest`, `nonce` | The notice's fields |
| `publicKey` | Your x-only public key |
| `preimage` | Step 2's bytes |
| `preimageSha256` | The 32 bytes step 3 signs |
| `signature` | Step 3's result |
| `rumorContent` | One valid content for step 4 |

The vector file is JSON, so its strings are themselves escaped. Parse it, then compare your bytes to the parsed strings. Between them, the vectors' gate ids use every row of the table in step 2, and a test holds that true.
