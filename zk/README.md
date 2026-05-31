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
                 published C detector (src/common/he_detector.c). It is validated
                 against the C reference: `cargo test -p oo_detector` asserts a
                 3.1 kHz tone -> alarm_tone and silence -> none, matching he-detect.
  methods/guest/ the zkVM guest: read samples (private) -> oo_detector::detect ->
                 commit ONLY (event, presence, voice_active, frames, active, n).
  host/          he-zk-prove: read a PCM file, prove, verify the receipt against
                 the published guest image id, print the proven verdict.
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
  image_id     : 48f5d914d71d83bdaa40a0c88c9ebbe7878f7e1091dfc8e8c7d2db59f5de1cce
```

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
  algorithm by necessity. The equivalence is held by the `oo_detector` test +
  the cross-check against `he-detect` on shared fixtures.
- **Reproducibility:** the toolchain + crate versions are pinned via the
  committed `Cargo.lock`; rebuild when crates.io is reachable.

## Where it plugs in

The receipt's journal carries the agreed event class — the same field
`VerifyQuorum` already agrees on across provers. Verifying the receipt with
`r0vm` and feeding its journal verdict in as one independent prover makes a real
TEE + ZK (+ phone) 2-of-3. On-chain verification of the receipt (Groth16 → an EVM
verifier contract) is the optional public-verifiability layer (see the roadmap).
