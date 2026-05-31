# zk — a zero-knowledge proof of the detector

A second, **independent** proof of the sensor's restraint: a RISC Zero zkVM runs
the *published* detector over audio supplied as **private** witness data and
proves *"the published detector produced this verdict"* — committing only the
verdict to the public journal, never the audio. This complements the TEE
attestation: the TEE proves *which code ran in an enclave*; the zk proof proves
*the computation itself* with **no enclave trusted for the math**. Together they
are two of the "2-of-3 multi-prover" legs — neither load-bearing alone.

## What's here

```
zk/
  oo-detector/   the detector as a no_std Rust lib — a FAITHFUL port of the
                 published C detector (src/common/he_detector.c). `cargo test -p
                 oo_detector` asserts a 3.1 kHz tone -> alarm_tone and silence ->
                 none (the same classes he-detect emits); a byte-level
                 differential test against he-detect is not yet automated.
  methods/guest/ the zkVM guest: read samples (private) -> oo_detector::detect ->
                 commit ONLY (event, presence, voice_active, frames, active, n).
  host/          he-zk-prove:  prove + verify a STARK receipt, print the verdict.
                 he-zk-export: produce a Groth16 receipt + Ethereum seal fixture
                               for on-chain verification (see ../onchain).
```

## Run it

Needs the RISC Zero toolchain (`curl -L https://risczero.com/install | bash`,
then `rzup install`). Then:

```sh
cd zk
cargo test -p oo_detector              # the port matches the C detector
cargo run --release -- ../path/to.pcm  # prove + verify a verdict in zero knowledge
```

Expected (a real STARK proof captured on a 12-frame alarm clip, ~6 min on a
laptop CPU — the `image_id` is the published guest measurement anyone can
recompute from source):

```
ZK-VERIFIED  detector(audio) proven in zero knowledge
  event        : alarm_tone
  presence     : 1
  voice_active : 0
  frames       : 12  (active 12)
  samples      : 3072  (audio itself never revealed)
  image_id     : 14d9f548bd831dd7c8a040aae7bb9e8c107e8f87e8c8df9159dbd2c7ce1cdef5
```

(`image_id` is the canonical risc0 `Digest` hex — the same bytes `he-zk-export`
writes and the on-chain verifier pins, so the local and EVM measurements match.)

## Honest scope

- **It is a batch/audit proof, not a live path.** A CPU STARK proof of a
  12-frame (~0.2 s) clip took ~6 min on a laptop; a full 1 s window is longer
  still. Appropriate for spot-audits and the multi-prover quorum, not for
  proving every frame in real time. (GPU/accelerated proving cuts this; the
  receipt verifies in milliseconds regardless.)
- **The detector is the same threshold stub** as the rest of the PoC; the zk
  proof attests *that this exact published computation ran*, not that the
  detector is a good model.
- **Faithful-port caveat (rule 2):** the guest is necessarily a Rust
  reimplementation of the C detector (different language/trust domain — C runs
  in the TEE, Rust in the zkVM), so they are two implementations of one
  algorithm by necessity. Equivalence is held by the `oo_detector` test
  asserting the same event classes `he-detect` emits; a byte-level differential
  harness against `he-detect` is not yet automated.
- **Reproducibility:** the toolchain + crate versions are pinned via the
  committed `Cargo.lock`; rebuild when crates.io is reachable.

## Where it plugs in

The receipt's journal carries the agreed event class — the same field
`VerifyQuorum` already agrees on across provers. Verifying the receipt with
`r0vm` and feeding its journal verdict in as one independent prover makes a real
TEE + ZK (+ phone) 2-of-3. On-chain verification of the receipt (Groth16 → an EVM
verifier contract) is **implemented** in [`../onchain`](../onchain/README.md):
`he-zk-export` writes the Ethereum seal and a Foundry test verifies it on a
local EVM. (Anchoring the transparency log to an L2 is the remaining roadmap
item.)
