# Why a TEE? (and not ZK / FHE / MPC / C2PA)

The obvious question is *"why a trusted enclave instead of ZK proofs or FHE —
isn't a TEE a single root of trust with a manufacturer backdoor?"* This is the
honest answer.

## TL;DR

For **real-time edge audio in 2026, TEE remote attestation is the only family
that runs the detector at native latency while proving integrity, provenance,
and freshness.** The right framing — and the one that survives the single-root
critique — is: **make the TEE the root of *capture*, not the root of *trust*.**

## The alternatives, and why they don't (yet) replace it

| Approach | What it proves | Real-time audio in 2026? | Key weakness here |
|---|---|---|---|
| **TEE remote attestation** (this) | code identity + provenance + freshness | ✅ native latency | single root of trust; physical side-channels |
| **zkML** | a model ran on an input | ❌ ~seconds/inference, GPU prover | ~100× too slow for 10–30 ms frames |
| **FHE** | compute on encrypted data | ❌ seconds–minutes | architecturally backwards (below) |
| **MPC / threshold** | joint compute, no single party sees input | ❌ needs ≥2 online non-colluding parties + rounds | wrong shape for an autonomous mic |
| **C2PA / signed sensors** | content was signed at capture | ✅ | sensor-injection: a soft key signs *injected* frames |

- **zkML** is seconds per inference and needs a GPU prover, not a microphone —
  roughly 100× too slow for streaming frames.
- **FHE is backwards for this:** it ships *encrypted raw audio off-device* to
  protect a confidentiality we already solved by **discarding the audio**. We
  don't want to compute on the audio elsewhere; we want it gone.
- **MPC** needs multiple online, non-colluding parties and network rounds — the
  wrong shape for an autonomous sensor.
- **C2PA / signed sensors** die to sensor-injection (a production camera was
  induced to sign an AI-generated image in 2025). A soft signing key wielded by
  malware over injected frames is not provenance.

## So the TEE is the right *substrate* — here's how it survives the critique

The single-root critique is real: a manufacturer backdoor, a leaked
hardware-bound key, or a side-channel can break everything at once (DRAM-timing
and fault attacks against production TEEs are demonstrated). Three things blunt
it — and they're design choices, not hand-waving:

1. **Minimization is itself the defense.** The worst-case side-channel leak is
   "`occupancy = 3`", not a transcript. Confidentiality is not resting on the
   TEE — so a TEE break **degrades gracefully** instead of catastrophically.
2. **Close the firmware-identity gap cheaply: reproducible builds.** The
   attestation token says "hash X ran," not "X is the audited source." A
   bit-for-bit reproducible build lets *anyone* re-derive the measurement from
   public source and match the token — converting "trust the vendor's hash" into
   "recompute it yourself." Highest-leverage, lowest-cost upgrade.
3. **Scope the TEE to the one job only it can do.** Nothing else can sit at the
   ADC/sensor and bind a **live analog signal** to attested hardware. ZK and FHE
   cannot ingest a microphone. The TEE owns *capture*; trust can live elsewhere.

## Strongest 2026-shippable architecture

What this repo has (OP-TEE + Veraison) **plus**:

- **Reproducible-build attestation** — independently re-derivable firmware hash.
- **An append-only / on-chain transparency log** of `(nonce, counter, predicate,
  token-hash)` commitments, so the device cannot lie *consistently* without
  public detection of counter-rollback or equivocation.
- **A TEE-signed commitment to the predicate's input** under a SNARK-friendly
  hash, so a future ZK proof can bind to the *same* commitment (tighter than
  today's standalone batch proof) without re-architecting the capture path.

> Already shipped: a **batch/audit ZK proof of the detector** (RISC Zero zkVM,
> the audio as private witness) runs today as a non-load-bearing second prover
> leg, and its receipt is verifiable on an EVM — see [`zk/`](../zk/README.md)
> and [`onchain/`](../onchain/README.md). That is distinct from the still-future
> *sub-second, real-time* zkML and the TEE-signed-commitment binding described
> below.

## Principled endgame — the multi-prover pattern

Map the **2-of-3 multi-prover** pattern (ZK + optimistic + TEE on disjoint trust
assumptions) onto sensing:

- **The TEE keeps the analog/capture boundary forever** (only it can).
- **ZK already absorbs the predicate as a non-TEE prover leg (`zk/`).** Because
  the detector is *tiny by design*, even a CPU STARK proof of it is tractable as
  a batch/audit step (~6 min for a ~0.2 s clip; faster on GPU), and the receipt
  verifies in milliseconds — appropriate for spot-audits and the quorum, not
  per-frame real time. Sub-second real-time zkML remains the future case.
- **Add a second heterogeneous root** (a measured-boot TPM event log alongside
  the CAAM key) as a near-free poor-man's multi-root.

FHE is named only to dismiss.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the precise scope and
[`ROADMAP.md`](ROADMAP.md) for the migration path.
