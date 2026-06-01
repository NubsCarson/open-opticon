# Integrations — portable "proof of restraint" for any local-first app

open-opticon's reusable invention isn't the audio detector — it's the **envelope**:
a signed, deterministic, hash-chained, transparency-logged, on-chain-anchorable
record of a sensor's *restraint*. That envelope is independent of the sensor and
of the hardware root, so any local-first app can adopt it to turn a privacy
*claim* into a *checkable* one.

This doc specifies that bridge and the first external adopter, **VoxTerm**.

## VoxTerm (the first non-audio, non-Arm adopter)

[VoxTerm](https://github.com/dmarzzz/VoxTerm) is a local-first voice-transcription
terminal: audio is transcribed **on-device** and its claim is, verbatim, *"No
audio is stored… processed in real-time and discarded… Everything runs on your
machine. Nothing is ever sent to a server."* Today that is a **trust** claim.
open-opticon is the layer that can make it a **verifiable** one — without merging
codebases.

**The seam already exists.** VoxTerm's `--hivemind-sink-url` already POSTs
transcript batches to a local sink. Point it at an open-opticon **receipt sink**
and each batch becomes a signed, hash-chained **restraint receipt** — no change to
VoxTerm's transcription architecture.

## Restraint receipts

A restraint receipt is a small, canonical, newline-delimited note (see
`src/verifier/receipt.go`, schema `honest-ear/restraint-receipt/v1`) committing,
per processing batch:

| field | meaning |
|---|---|
| `session` | session id |
| `batch` | monotonic batch index (anti-replay) |
| `input_hash` | SHA-256 of the input window **processed and then discarded** (proves which input existed without storing it) |
| `output_hash` | SHA-256 of the only thing emitted (e.g. the transcript text) |
| `retained` | `0`/`1` — did the app keep the raw input? (the honest claim is `0`) |
| `prev` | SHA-256 of the previous receipt body — an append-only hash chain, so a silently dropped batch is a detectable **gap** |

It is signed with a P-256 key and verified by `he-receipt verify` /
`VerifyReceipt` (reusing the project's single ECDSA path). Because a receipt body
is just canonical bytes, it is also a **transparency-log leaf**: feed receipts to
`he-log` / `he-logd` and a session's stream becomes append-only, witness-cosignable
(`he-witness`), and on-chain-anchorable (`CheckpointAnchor`) with the existing
machinery — no new schema. `make voxterm-e2e` demonstrates a full session:
chained receipts → verify → inclusion under a signed checkpoint → gap detection →
rejection of a receipt that admits retaining audio.

```sh
# what VoxTerm's hivemind sink does per batch, conceptually:
he-receipt emit --session $S --batch $N --audio window.pcm --text out.txt \
    --key <deviceKey> --prev <prevDigest>     # -> a signed receipt; its digest = next --prev
he-receipt verify --file receipt.json --expect-prev <prevDigest> --require-not-retained
```

### Reference adapter + proven cross-language interop

A reference VoxTerm-side emitter exists: a standalone Python `ReceiptEmitter`
(using VoxTerm's existing `cryptography` dependency, P-256) that produces receipts
in this exact wire format. **Interop is proven** — a Python-emitted receipt
verifies with this project's stdlib-only Go `he-receipt`, the chain links across
batches, and a suppressed batch is detected as a gap (cross-checked end to end).
A small, opt-in PR (module + tests + a maintainer wiring recipe) is prepared for
the VoxTerm team's review; it is **not yet merged** (it lives in their repo, not
this one). VoxTerm's "audio is discarded" claim was verified against their code
(`audio/buffer.py` clears the PCM buffer; audio is never persisted), so the
receipt's `retained=0` is truthful.

## Heterogeneous hardware roots (the "outside the box" part)

The receipt's signature can come from **whatever hardware root the platform
offers** — the verifier is root-agnostic (it checks a P-256 signature):

| platform | hardware root | gives |
|---|---|---|
| Arm (RPi / i.MX) | OP-TEE / TrustZone, CAAM black key | firmware **measurement** (attests *which code*) + non-extractable key |
| Apple (Mac / iOS) | **Secure Enclave** (P-256) | a non-extractable device key (anti-clone); no app firmware measurement |
| PC | TPM 2.0 | a hardware-bound key (+ measured boot, with work) |

This is exactly open-opticon's heterogeneous-quorum vision, now cross-platform:
different roots, the **same** envelope and transparency layer. VoxTerm on a Mac
would sign receipts with a Secure-Enclave-resident P-256 key — `VerifyReceipt`
checks it unchanged.

## Honest scope (the whole point)

A restraint receipt proves a **tamper-evident, gap-free, signed binding of
input→output per batch, under a hardware-backed key** — verifiably stronger than a
bare promise, and publicly auditable. It does **not**, by itself, prove:

- **which code ran** — that needs firmware measurement (a TEE) or, on platforms
  without it, reproducible builds + open source (VoxTerm is open source);
- **that no covert exfiltration path exists** — only a measured/attested execution
  environment can rule that out. On Apple/PC the Secure-Enclave/TPM key binds the
  *signer*, not the *code*.

So on VoxTerm's current platform this is an **accountability/transparency**
guarantee, not a hardware confidentiality proof — and we say so rather than imply
otherwise. The strongest deployment (Arm + OP-TEE, where the firmware hash is
attested *and* reproducible) is the only one that closes the "which code" gap;
everything else is an honest step up from "trust me."
