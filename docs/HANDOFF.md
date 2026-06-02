# Track 3 software — handoff

open-opticon is the **software side of Track 3** (minimal open attestable sensor)
in the credible-sensors program. This is the one-page "what's here, what's proven,
what's next" for the collaborators. Full positioning is in [`T3.md`](T3.md).

Role split: **nubs = T3 software (this repo); Noah = T3 hardware** (sensor, ST
secure-element root, Pi target, enclosure).

## What works today (Tier 1 — proven on QEMU / any Linux box)

A layperson scans a QR and, in under a minute, *verifies* (not trusts) the
program's five questions, each backed by a real artifact:

- **Walk-up verifier** — `he-challenge` serves `/v`; on a PASS it answers what's
  captured / where it goes / who can access / how long kept / how used, each with
  a "show me the proof" panel and an honest tier label. Proven end-to-end (mint →
  sign → verify).
- **Portable proof explorer** — [`docs/verify.html`](verify.html) runs the *same*
  verifier in-browser (WASM); paste any bundle to walk the gates + see the 5
  answers. No server, no install.
- **The verifier** (`he-verify`, stdlib Go): 5 gates — endorsement pin, ECDSA-P256
  signature, nonce freshness, monotonic anti-replay, streaming hash-chain. Root-
  agnostic (pins a P-256 key; any silicon's key enrolls unchanged).
- **Heterogeneous roots, demonstrated** — `make tpm-e2e`: a key born inside a TPM
  (private half never exported) signs an artifact the unmodified verifier accepts.
  `--co-attest` binds an audio **and** a vision verdict to one challenge nonce.
- **Track 6 mechanisms** — `he-consent`: k-of-n threshold reveal + consent-gated
  single-window disclosure (`make consent-e2e`).
- **Accountability bridge** — `he-receipt` restraint receipts (the VoxTerm hook):
  signed, hash-chained {input processed-then-discarded, output, retained:0}
  (`make voxterm-demo`). See [`INTEGRATIONS.md`](INTEGRATIONS.md).
- **Transparency + on-chain** — RFC 6962/9162 log with witness cosigning; a ZK
  proof of the detector and a dual-root quorum **live on Ethereum Sepolia**
  (addresses in [`../onchain/README.md`](../onchain/README.md)).

Everything above is gated by CI (host tests, reproducible build, on-chain verify,
C↔Rust port equivalence, fuzz, TPM root). `make test` runs the host suite.

## What needs hardware (speced, not built — honest scope)

Read these as designed, not proven: device identity / anti-clone (a non-extractable
key — i.MX CAAM, or an **ST secure element** on the Pi), rollback-proof anti-replay
(hardware monotonic counter), physical tamper response, and secure capture (audio
into secure-world I2S/PDM). Full scope + adversary table in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## What Noah needs first

[`PI_ST_ELEMENT.md`](PI_ST_ELEMENT.md) — an honest design for running opticon on a
Raspberry Pi with an STSAFE-A110 as the signing root. Because the verifier is
root-agnostic, an ST key enrolls with **no verifier change** (Option A, runnable
today). It flags the two real gaps to weigh on the hardware side: there is no
secure boot on a stock Pi (the SE proves *who signed*, not *what code ran*), and
the secure-world TA must own the I2C path to the SE or the binding breaks.

## Run it

```sh
make test          # the full host suite (no hardware, no network)
make voxterm-demo  # the restraint-receipt bridge, narrated
make consent-e2e   # Track-6 threshold reveal + consent-gated disclosure
make tpm-e2e       # heterogeneous TPM root (needs swtpm + tpm2-tools)
# then: he-challenge  -> open /v on a phone, or click "simulate a device"
```
