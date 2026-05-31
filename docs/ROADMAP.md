# Roadmap

From this PoC to a defensible product, in order of trust-impact.

## Done in this PoC

- **Multi-prover quorum (verifier side).** `he-verify --quorum k` requires *k* of
  *n* enrolled independent roots to verify and agree
  ([`quorum.go`](../src/verifier/quorum.go)). Wiring up genuinely heterogeneous
  provers (a second-vendor TEE, a TPM quote) is the remaining integration.
- **Endorsement transparency log + witness cosigning.** RFC 6962 append-only
  Merkle log with inclusion + consistency proofs and a signed checkpoint
  (`he-log`, [`transparency.go`](../src/verifier/transparency.go)); the verifier
  can require an endorsement to be logged. Independent **witnesses cosign**
  checkpoints (`he-log cosign`, `CosignCheckpoint`/`VerifyCheckpointWitnesses`,
  C2SP/Sigstore model) and the verifier requires a threshold of cosignatures from
  **enrolled, pinned-key** witnesses (a cosig only counts if its name + key match
  an enrolled witness, like the prover quorum), so a single operator can't mint
  keys to equivocate — the off-chain analogue of the on-chain `CheckpointAnchor`.
  Remaining: wiring the threshold check into a CLI verify path + running real
  gossiping/consistency-checking witnesses.
- **Reproducible host builds.** `make repro` proves the host artifacts are
  byte-identical across independent build trees; the TA-measurement recipe is in
  [`REPRODUCIBLE.md`](REPRODUCIBLE.md). CI gates every push on this and publishes
  the SHA-256 measurement manifest.
- **A zero-knowledge proof of the detector** (a non-TEE prover leg). A RISC Zero
  zkVM runs a faithful Rust port of the published detector over audio as private
  witness data and proves the verdict, committing only the predicate — never the
  audio — with no enclave trusted for the math. Real STARK proof captured +
  verified end-to-end ([`zk/`](../zk/README.md)). Batch/audit speed (minutes per
  clip), wired conceptually as a second quorum leg; on-chain verification of that
  receipt is done (see the on-chain bullet below) — locally and live on Sepolia.
- **On-chain (permissionless) verification of the zk receipt.** A Foundry project
  ([`onchain/`](../onchain/README.md)) whose `onchain/src/HonestEarVerifier.sol`
  wraps RISC Zero's verifier and checks the Groth16 receipt for the pinned guest
  `imageId` on a stateless EVM; a real proof fixture verifies on a local EVM
  (`forge test`, no funds/network) **and is deployed live on Ethereum Sepolia**
  (addresses + Etherscan links in onchain/README) where a real `eth_call` to the
  quorum returns the agreed verdict.
- **A heterogeneous dual-root check, on-chain (a both-required 2-of-2).**
  `HonestEarQuorum.sol` returns a verdict only if a ZK proof of the detector
  (Groth16) *and* the device's hardware-bound secp256r1 signature over its
  bound-output payload (OpenZeppelin P256) both verify and agree on the predicate
  (event, presence, voice_active, frames) — where, unlike the stdlib-only Go
  verifier, the EVM can verify both proof systems. `recordVerdict` enforces
  on-chain anti-replay via the device counter. Proven on a local EVM with a real
  receipt + a real device bundle, and **deployed live on Ethereum Sepolia** (full
  stack via `DeployLocal.s.sol`; addresses in onchain/README). The two roots are
  **cryptographically bound to the same observation** — the same verifier nonce
  AND the same audio: the guest commits sha256(nonce) and sha256(audio), and the
  contract requires both to equal the device payload's nonce hash and its
  input_hash, so a proof and a signature from a different session OR different
  audio can't be combined, even against a misbehaving device. One realisable leg
  of the broader 2-of-3 vision. The transparency-log checkpoints also have an on-chain
  anchor (`onchain/src/CheckpointAnchor.sol`): it verifies an RFC 9162 consistency
  proof on-chain (SHA-256 precompile) so a fork/rewrite is rejected — proven by a
  real `he-log consistency` proof in `forge test`; only the live deploy is deferred.
- **The primitive generalizes beyond audio.** A vision occupancy detector
  (`he_vision`, integer-only, same discipline as the acoustic one) emits only
  `empty`/`occupied` + a region count, never the frame, and rides the *same*
  bound-output envelope verified by the *same* `he-verify` (`make vision-e2e`).
  Proves the attestation/binding/verification machinery is sensor-agnostic.

## Cryptographic / protocol
- **Promote the bound-output envelope to COSE_Sign1** (RFC 9052/9053). The
  signing primitive is identical (`sign_ecdsa_sha256`); wrap the canonical
  payload in a tagged COSE_Sign1 with `alg=ES256` in the protected header so the
  algorithm is bound and any RATS/EAT tooling consumes it. Deferred here only
  because it changes the in-enclave wire format already proven on QEMU — it is a
  TA-side change requiring a re-measure + re-attest, not a host-only edit.
- **Fold the bound output into the EAT itself** as a custom claim, so there is a
  single attestation token rather than two signatures. (Two signatures is fine
  for the PoC and keeps Veraison freshness untouched.)
- **Heterogeneous provers for the quorum.** Done on-chain: `HonestEarQuorum.sol`
  requires a ZK proof *and* the device's P-256 signature to agree (see "Done"
  above). Remaining for the *off-chain* Go verifier: enrol more non-TEE legs
  (a measured-boot TPM quote, a second-vendor TEE) as roots in `he-verify
  --quorum`. The ZK leg can't be auto-wired into the stdlib-only Go verifier
  (it can't verify a STARK) — which is exactly why that leg's quorum is on-chain.
- **Witness cosigning for the transparency log.** ✅ Done (see "Done in this
  PoC"): `he-log cosign` + `VerifyCheckpointWitnesses` let independent witnesses
  countersign checkpoints (C2SP/Sigstore model). Remaining operational work is
  running real, independent witnesses that gossip + consistency-check before
  cosigning, not just the protocol.
- **Sign endorsements as CoRIM.** Provision Veraison with a COSE-signed CoRIM and
  log the signed CoRIM as the transparency-log entry, so endorser authenticity
  is covered end-to-end.

## Hardware identity & tamper
The full board bring-up, bill of materials, wiring, and device picture are in
[`HARDWARE.md`](HARDWARE.md) (incl. why a phone is the wrong place for the sensor
but the right place for the verifier).
- **i.MX 8M Plus CAAM** non-extractable black key as the default signing key;
  per-device endorsement enrolled to a **public manufacturer root** (the
  StrongBox/EKCert analogue we currently self-provision).
- **Hardware tamper response**: route the tamper line into a secure element
  (ATECC608) or CAAM so the *private key* is zeroized in hardware, with a backup
  battery so detection works while powered off. Fine anti-tamper mesh + potting
  behind the transparent window (PCI-PTS / IBM-4758 model).
- **Hardware monotonic counter** (RPMB-backed) for rollback-proof anti-replay.

## Secure capture path
- Move PCM capture to a **secure-world I2S/PDM** source so raw audio never
  enters the normal world at all (today the host feeds a file/buffer for the
  PoC). This closes the analog-hole-equivalent gap fully.

## Detector quality
- Replace the threshold detector with a small, **audited** keyword/acoustic-event
  model; publish the model + policy and bind its hash (already wired via
  `config_hash`). Add a constant-time / no-secret-dependent-branch audit pass.

## Confidentiality migration
- Where richer outputs are needed, migrate sensitive computation toward
  **PIR/FHE** so confidentiality no longer rests on TEE side-channel resistance.

## Ecosystem / collaborations
- **VoxTerm** ([dmarzzz/VoxTerm](https://github.com/dmarzzz/VoxTerm)) is a local-first
  voice-transcription app whose privacy pitch is "nothing sent to a server, no
  audio stored." Today that's a *trust* claim. open-opticon is the layer that
  could make it a *provable* one: attest the transcription pipeline's firmware
  and emit only signed, bound outputs, so VoxTerm could prove — not just assert —
  that it didn't exfiltrate or retain audio. Natural collaboration; keep the
  projects separate, bridge at the attestation boundary (don't merge codebases).

## Ops
- **Reproducible builds:** host artifacts are byte-reproducible today
  (`make repro`); finish the **TA** measurement re-derivation so the published
  firmware hash is independently recomputable from source (recipe in
  [`REPRODUCIBLE.md`](REPRODUCIBLE.md)). Highest-leverage remaining honesty item.
- **Transparency log:** the append-only Merkle log + proofs exist (`he-log`);
  remaining work is operating it for real — periodic checkpoints, witness
  cosigning, and logging signed CoRIM endorsements.
