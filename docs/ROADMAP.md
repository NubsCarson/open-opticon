# Roadmap

From this PoC to a defensible product, in order of trust-impact.

## Done in this PoC

- **Multi-prover quorum, with a genuinely heterogeneous root.** `he-verify
  --quorum k` requires *k* of *n* enrolled independent roots to verify and agree
  ([`quorum.go`](../src/verifier/quorum.go)). This is no longer verifier-side
  only: `make quorum-hetero-e2e` stands up a real 2-of-2 where a sim P-256 root
  **and** a **TPM-resident** P-256 key (its private half never leaves the TPM)
  sign the same bound output, and `he-verify --quorum 2` accepts both — concrete
  evidence the quorum path is root-agnostic across a genuinely different keystore
  (its own CI job, `tpm-hetero-root`). HONEST SCOPE: that leg runs against
  **swtpm — a software TPM, not separate hardware**; it is a TPM-resident
  **signing key, not a TPM quote** (no PCR / measured-boot binding); and it did
  **not** observe the audio — so it demonstrates a heterogeneous *root*, not a
  second *witness* of the event (see [`HARDWARE.md`](HARDWARE.md)). Still
  remaining: a second-vendor TEE, a real TPM **quote** bound to a firmware
  measurement, and a prover that independently observes the event.
- **Endorsement transparency log + witness cosigning.** RFC 6962 append-only
  Merkle log with inclusion + consistency proofs and a signed checkpoint
  (`he-log`, [`transparency.go`](../src/verifier/transparency.go)); the verifier
  can require an endorsement to be logged. Independent **witnesses cosign**
  checkpoints (`he-log cosign`, `CosignCheckpoint`/`VerifyCheckpointWitnesses`,
  C2SP/Sigstore model) and the verifier requires a threshold of cosignatures from
  **enrolled, pinned-key** witnesses (a cosig only counts if its name + key match
  an enrolled witness, like the prover quorum), so a single operator can't mint
  keys to equivocate — the off-chain analogue of the on-chain `CheckpointAnchor`.
  A CLI verify path enforces the threshold (`he-log cosign-verify`); remaining
  is running real, independent gossiping/consistency-checking witnesses.
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
  real `he-log consistency` proof in `forge test`, and **deployed live on Sepolia**
  (its `latestSize`/`latestRoot` read live on the transparency dashboard, matching
  the committed checkpoint). Off-chain, **operating witnesses** (`he-logd` +
  `he-witness`) now consistency-check and cosign that same log and refuse forks.
- **The primitive generalizes beyond audio.** A vision occupancy detector
  (`he_vision`, integer-only, same discipline as the acoustic one) emits only
  `empty`/`occupied` + a region count, never the frame, and rides the *same*
  bound-output envelope verified by the *same* `he-verify` (`make vision-e2e`).
  Proves the attestation/binding/verification machinery is sensor-agnostic.
- **Streaming hash-chain (suppression detection).** Each payload carries
  `prev_digest = SHA-256(previous payload)` (key 10), making a device's stream
  append-only. Where the monotonic counter defeats *replay*, the chain defeats
  *suppression*: a verifier that records one window's digest rejects the next
  window unless it chains from exactly that digest, so a silently dropped window
  is a detectable gap. Device-payload-only (Gate 4 in the Go verifier, under the
  P-256 signature), so the ZK leg is unchanged. `make chain-e2e` shows a genuine
  stream verifying and a spliced (window-dropped) stream rejected. The TA stores
  genesis (zeros) until per-window chain-state lands in Trusted Storage alongside
  the counter (the rig TODO).

## Cryptographic / protocol
- **COSE_Sign1 envelope (RFC 9052/9053).** ✅ Implemented host-side: the shared,
  TA-portable encoder (`src/common/he_cose.[ch]`) wraps the SAME canonical payload
  in a tagged COSE_Sign1 with `alg=ES256` in the protected header — same
  ECDSA-P256 primitive, signing the COSE Sig_structure instead of the bare
  payload, so any RATS/EAT tooling can consume it. The host signer emits it
  (`HE_COSE=1`), the stdlib-only Go verifier checks it (`he-verify --cose`,
  `cose.go`), and `make cose-e2e` proves C→Go end-to-end. Remaining: the TA emits
  it on the next rig build (a re-measure + re-attest, since it changes the
  in-enclave wire format already proven on QEMU).
- **Host-side PSA attestation-token (EAT) verifier.** ✅ Implemented: `eat.go` /
  `he-attest-verify` parse a PSA token (COSE_Sign1, profile
  `http://arm.com/psa/2.0.0`) and check the parts that are verifiable offline (a
  subset of Veraison's appraisal) — the ES256 signature under a pinned attestation key, the EAT
  profile, the freshness nonce, and that every software-component measurement is a
  published reference value. Reuses the COSE machinery above; tested against a
  faithfully-minted PSA token. It does NOT replace Veraison's full
  endorsement/trust-anchor provisioning and policy — a real Veraison-issued token
  is the rig step.
- **Fold the bound output into the EAT itself** as a custom claim, so there is a
  single attestation token rather than two signatures. (Two signatures is fine
  for the PoC and keeps Veraison freshness untouched.)
- **Heterogeneous provers for the quorum.** Done on-chain: `HonestEarQuorum.sol`
  requires a ZK proof *and* the device's P-256 signature to agree (see "Done"
  above). Remaining for the *off-chain* Go verifier: enrol more non-TEE legs
  (a measured-boot TPM quote, a second-vendor TEE) as roots in `he-verify
  --quorum`. The ZK leg can't be auto-wired into the stdlib-only Go verifier
  (it can't verify a STARK) — which is exactly why that leg's quorum is on-chain.
- **Witness cosigning for the transparency log.** ✅ Protocol + a runnable
  operational layer done (proven single-host): `he-logd` serves the log's signed checkpoints + RFC 9162
  consistency proofs over HTTP, and `he-witness` is a real witness daemon that
  polls it, verifies each checkpoint is a consistent append-only extension of the
  one it last cosigned, and **refuses to cosign a forked or rewound history**
  (pinning the log key). A 2-of-3 witness quorum verifies and a fork is refused
  end-to-end in `make witness-e2e` (plus deterministic httptest unit tests).
  ✅ Witnesses now also **cross-check each other**, two ways: `he-witness compare`
  (one-shot 1:1) and — wired into the daemon — `he-witness serve --peer
  name,url,x,y …`, which CONTINUOUSLY cross-checks each pinned peer every tick and
  reports per-peer agreement / equivocation in `/health` (going unhealthy + latching
  on a detected equivocation). Both reuse the pure `crossCheck` decision; proven in
  `make witness-e2e` (honest agree path + the 1:1 equivocation case) + `TestCrossCheck`.
  Remaining (genuinely future, not a clean slice now): peer DISCOVERY / a witness
  registry / trust-on-first-use (the guarantee needs pinned independent keys), and a
  true p2p gossip overlay (transitive flooding, peer-of-peer fan-out, NAT traversal).
  ✅ A first piece of that shipped: a TRANSFERABLE equivocation proof — on a same-size
  split the daemon serves `/equivocation-proof` (its own + the divergent peer's
  cosigned checkpoints), and `he-witness verify-equivocation` lets ANYONE confirm the
  log equivocated offline under the two pinned witness keys. A detecting daemon also
  **relays** the proof to its pinned peers (`POST /equivocation-intake`), which
  re-verify it under THEIR own pinned keys (origin-scoped to the log they watch) before
  latching — and re-push on first adoption, so the proof **transitively floods** the
  pinned mesh, terminating via the `d.proof` once-per-node latch (`make witness-e2e`,
  `VerifyEquivocation`, `TestDaemonAdoptsRelayedProof`, `TestDaemonRelayIsTransitiveOncePerNode`).
  Only the robustness layer (anti-entropy, eclipse resistance) + discovery/membership
  stay frontier, scoped in [`DESIGN_WITNESS_GOSSIP.md`](DESIGN_WITNESS_GOSSIP.md).
- **Sign endorsements (endorser authenticity).** ✅ A first slice: an ENDORSER
  signs a canonical endorsement body (`EndorsementBody`/`ParseEndorsement` +
  the shared `SignNote`/`VerifyCheckpointSig`), the SAME signed body is logged,
  and a verifier confirms BOTH the endorser signature (`he-log endorse-verify`
  under the pinned endorser key) AND log inclusion (`he-log verify`) — separating
  WHO vouched from the operator who merely appends. `make endorse-e2e` +
  `TestSignedEndorsement`. ✅ Also available standards-aligned: `endorse --cose`
  wraps the body in a tagged COSE_Sign1 (ES256) via a promoted PRODUCTION COSE
  encoder (`cose_encode.go` `SignCOSESign1`, sharing the one Sig_structure builder
  with verification — removed the prior test-only COSE encoder duplication);
  `endorse-verify --cose` / `VerifyCOSEEndorsement` check it, so standard RATS/COSE
  tooling can consume the endorsement (`TestCOSEEndorsement`). Remaining: the full
  IETF-CoRIM tag structure (CoMID/CoSWID triples, profile) — a large spec, NOT the
  COSE envelope above — and a Veraison-provisioned, manufacturer-rooted endorser
  (the endorser here is self-provisioned P-256; the role separation + COSE wire are
  real, a public trust anchor is future/needs-hardware).

## On-chain hardening
The `onchain/` layer is a PoC public-verification leg (its honest scope is in
[`../onchain/README.md`](../onchain/README.md)). The live Sepolia contracts are an
immutable snapshot, so these apply to any future deploy.
- **Domain separation against cross-chain / cross-instance replay.** Bind
  `chainid` + the contract address into BOTH the device-signed payload and the zk
  journal, so a valid {receipt, signature} bundle for one deployment can't be
  replayed into another deployment/instance. The two roots already bind each
  other's nonce + audio; this adds the deployment as a third bound dimension. Needs
  a TA + zk-guest wire change and a re-prove (batch/audit step), so it is future
  work, not a laptop task.
- **On-chain checkpoint-signature verification.** `CheckpointAnchor` enforces RFC
  9162 consistency on-chain and emits the checkpoint's P-256 signature for
  off-chain authentication against the published log key; verifying that signature
  on-chain (RIP-7212 / OpenZeppelin P256) would authenticate even the seeding call
  to the log key, closing the permissionless-seed gap.
- ✅ **Counter-boundary + deterministic-CBOR hardening (source).** `HonestEarQuorum`
  bounds the device counter below `type(uint64).max` (so the monotonic anti-replay
  check can't be wedged at the integer boundary) and enforces strictly-ascending
  CBOR keys in the payload reader (one canonical encoding — duplicate or
  out-of-order keys are rejected). Done in source with a forge test; the live
  instances are the pre-hardening snapshot.

## Secure-world signing-path hardening
- **Centralized tamper gate.** `he_tamper_tripped()` is checked in
  `he_attest_audio` but must gate EVERY command that uses the attested key — the
  `SIGN_DATA` PTA and the PSA/CBOR-evidence command included — so an opened device
  whose embedded key was not physically destroyed (the QEMU case, where there is no
  normal-world key file to erase) cannot keep signing or attesting. Today only the
  audio path is gated.
- **Restrict the `SIGN_DATA` PTA to the audio TA.** The raw signing primitive must
  be reachable only from the in-TEE audio TA (a caller-UUID restriction in
  optee-ra's PTA registration), never normal-world-invocable; otherwise the public
  canonical payload format (`he_payload.h`) makes it a forging oracle. See
  [`../src/optee/pta/INTEGRATION.md`](../src/optee/pta/INTEGRATION.md) and THREAT_MODEL.

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
- **Probe-band tone detection.** ✅ Done: the detector now scans a small band of
  frequencies around the configured center (default 2900/3100/3300 Hz via
  `tone_bins`/`tone_band_hz`, taking the strongest Goertzel power per frame), so a
  real alarm that sits off the nominal frequency (UL-217 alarms drift across
  ~3000-3400 Hz) is still detected. Integer-only, config-hash-bound, and
  bit-for-bit identical in the C detector and the Rust zk port (`make port-diff`);
  an off-center 3300 Hz alarm is detected in `test_detector`. This is a stronger
  HEURISTIC, not a learned model.
- **Replace the heuristic with a small, _audited_ keyword/acoustic-event model.**
  Still open and the honest hard part: it needs a real labelled dataset, a
  fixed-point model whose weights are published + bound via `config_hash`, a
  constant-time / no-secret-dependent-branch audit pass, AND an independent audit
  (the word "audited" is load-bearing — it is not something the maintainer can
  self-assert). The probe-band detector above and the existing `config_hash`
  binding are the on-ramp; the model + audit are future work, not a laptop task.

## Confidentiality migration
- Where richer outputs are needed, migrate sensitive computation toward
  **PIR/FHE** so confidentiality no longer rests on TEE side-channel resistance.

## Ecosystem / collaborations
- **VoxTerm** ([dmarzzz/VoxTerm](https://github.com/dmarzzz/VoxTerm)) is a local-first
  voice-transcription app whose pitch is "nothing sent to a server, no audio
  stored" — today a *trust* claim. ✅ A portable bridge now exists: **restraint
  receipts** (`src/verifier/receipt.go`, `he-receipt`, `make voxterm-e2e`) let a
  transcription session emit signed, hash-chained, transparency-loggable records
  binding {input_hash processed-then-discarded, output_hash, retained=0} per batch
  — verifiable, gap-detecting, witness-cosignable, anchorable, with no codebase
  merge (VoxTerm's existing `--hivemind-sink-url` is the seam). The signing key is
  whatever hardware root the platform offers (OP-TEE/CAAM on Arm, Secure Enclave on
  Apple, TPM on PC — the verifier is root-agnostic). HONEST SCOPE: this is
  accountability (tamper-evident, gap-free, signed input→output), not a hardware
  confidentiality proof — "which code ran / no covert exfil" still needs firmware
  measurement (a TEE) and/or reproducible builds + open source. See
  [`INTEGRATIONS.md`](INTEGRATIONS.md).
- **Credible-sensors program (Track 3).** open-opticon is positioned as the
  **software side of Track 3** (minimal open attestable sensor) — see
  [`T3.md`](T3.md). ✅ The walk-up verifier (`/v` in `he-challenge`) now answers the
  program's five questions (what is captured / where it goes / who accesses / how
  long kept / how used) in plain language on a PASS, each with a "show me the
  proof" panel that reveals the literal verified artifact and an honest tier label
  (proven-here vs needs-hardware). Hardware side (a Raspberry Pi + an ST secure
  element as the per-device root) is designed in [`PI_ST_ELEMENT.md`](PI_ST_ELEMENT.md)
  — SPECED/FRONTIER, not built; the verifier is already root-agnostic so an ST key
  enrolls with no verifier change. HONEST SCOPE: integrity + provenance, Tier-1
  proven on QEMU; device identity / secure boot / secure capture are hardware work.
- **Track 6 (consent / query / policy) mechanisms.** ✅ `threshold.go` (stdlib):
  **k-of-n threshold reveal** (Shamir over the Mersenne prime 2^521-1 + AES-256-GCM
  seal — a full record is revealable only with group agreement, k-1 holders learn
  nothing) and **consent-gated single-window disclosure** (reveal one window of a
  logged predicate stream with a Merkle inclusion proof, hiding the others).
  HONEST SCOPE: these are mechanisms, not a solution to the joint-data
  conflicting-wishes problem (still open); share custody + key lifecycle are
  operational policy, not enforced in code. Tier-1, host-tested under `-race`.
  Exposed as the `he-consent` CLI (seal/reveal + disclose/verify-disclosure) and
  exercised end-to-end by `make consent-e2e`.
- **Multi-modal co-attestation.** ✅ `VerifyCoAttestation` + `he-verify
  --co-attest k` (`make multimodal-e2e`): an AUDIO verdict and a VISION verdict,
  each a fresh signature bound to the SAME challenge nonce, accepted as a
  k-modality co-attestation. The cross-modal sibling of the quorum — a quorum
  requires k independent roots to AGREE on one event; co-attestation requires k
  distinct modalities (distinct input_hash) bound to one nonce and does NOT
  require agreement. HONEST SCOPE: proves the key signed a fresh verdict per
  modality for one challenge; does NOT prove they observed the same physical
  scene, nor (Tier-1 shared key) a specific device.
- **TPM as a heterogeneous root.** ✅ `make tpm-e2e` (dedicated CI job): a P-256
  key generated INSIDE a software TPM (swtpm; private half never exported) signs
  an artifact the *unmodified* verifier accepts after enrolling only its public
  X/Y — concrete proof the verifier is root-agnostic, and substantiates the "TPM
  on PC" claim with a genuinely different keystore/root than the QEMU test key
  (swtpm here — a SOFTWARE TPM, not separate hardware). HONEST SCOPE: the TPM did
  not observe the audio (no PCR/measured-boot binding) — a signing-root
  demonstration, NOT a second witness; weaker than the OP-TEE Tier-1 attest+bind.
  Also exercised in the quorum (`make quorum-hetero-e2e`). See [`HARDWARE.md`](HARDWARE.md).

## Ops
- **Reproducible builds:** host artifacts are byte-reproducible today
  (`make repro`); finish the **TA** measurement re-derivation so the published
  firmware hash is independently recomputable from source (recipe in
  [`REPRODUCIBLE.md`](REPRODUCIBLE.md)). Highest-leverage remaining honesty item.
- **Transparency log:** the append-only Merkle log + proofs exist (`he-log`);
  remaining work is operating it for real — periodic checkpoints, witness
  cosigning, and logging signed CoRIM endorsements.
