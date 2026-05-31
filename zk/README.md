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
                 published C detector (src/common/he_detector.c), proven by a
                 differential test: `test/run_port_diff.sh` runs both the C
                 `he-detect` and the Rust port over the same fixtures and asserts
                 byte-identical verdicts (also `make port-diff`).
  oo-detect/     a tiny CLI over oo-detector used by that differential test.
  methods/guest/ the zkVM guest: read samples (private) + a verifier nonce ->
                 oo_detector::detect -> commit ONLY (event, presence,
                 voice_active, frames, active_frames, n_samples) + sha256(nonce)
                 + sha256(audio). The two hashes bind the proof to the same
                 challenge AND the same input as the device signature (the latter
                 equals the device payload's input_hash); the on-chain quorum
                 requires both to match. The audio itself is never committed.
  host/          he-zk-prove:  prove + verify a STARK receipt, print the verdict.
                 he-zk-export: produce a Groth16 receipt + Ethereum seal fixture
                               for on-chain verification (see ../onchain).
```

## Run it

Needs the RISC Zero toolchain (`curl -L https://risczero.com/install | bash`,
then `rzup install`). Then:

```sh
cd zk
cargo test -p oo_detector                       # the port matches the C detector
cargo run --release -- ../path/to.pcm [nonce]   # prove + verify in zero knowledge
```

Expected (a real STARK proof captured on a 12-frame alarm clip, ~6 min on a
laptop CPU — the `image_id` is the published guest measurement anyone can
recompute from source; `nonce_sha256`/`audio_sha256` bind the proof to the
verifier challenge and to the exact input):

```
ZK-VERIFIED  detector(audio) proven in zero knowledge
  event        : alarm_tone
  presence     : 1
  voice_active : 0
  frames       : 12  (active 12)
  samples      : 3072  (audio itself never revealed)
  nonce_sha256 : 8d70d691c822d55638b6e7fd54cd94170c87d19eb1f628b757506ede5688d297
  audio_sha256 : 76fce813fbb5a4c577d78eb957bcb37962a16a89d3c1151b801acdb96b9b0e2a
  image_id     : 7b3b6516a727718282f79230824c557da58b0edc9b4641f44d9aa240424996aa
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
  algorithm by necessity. Equivalence is proven by a differential test
  (`test/run_port_diff.sh` / `make port-diff`, run in CI) that asserts the C
  `he-detect` and the Rust `oo-detect` emit byte-identical verdicts on the
  shared fixtures.
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
