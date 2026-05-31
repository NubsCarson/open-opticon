# Reproducible builds

The whole trust model rests on one claim: *the firmware running in the enclave is
the published source.* Remote attestation proves the device runs firmware with a
particular measurement (hash); reproducible builds are what let **anyone**
recompute that measurement from source and confirm it matches — turning "trust
the maintainer's binary" into "verify it yourself."

## Host artifacts — proven here

```sh
make repro
```

`tools/repro.sh` builds the C simulator/detector and the Go verifier tools
**twice, in two separate trees at different absolute paths**, with deterministic
flags, and compares the SHA-256 of every binary. Identical hashes prove the
output depends only on the source — not the path, the clock, or the machine.

Deterministic flags used:

- **C:** `-g0 -fno-ident -ffile-prefix-map=<tree>=.` and a fixed
  `SOURCE_DATE_EPOCH`, so no build path, identifier string, or timestamp leaks
  into the binary.
- **Go:** `-trimpath -buildvcs=false -ldflags=-buildid=` with `CGO_ENABLED=0`
  and `GOPROXY=off`, which makes Go output bit-for-bit reproducible offline.

Expected result: `REPRODUCIBLE  all host artifacts are byte-identical`.

## The OP-TEE TA measurement — the one that matters

The TA's measurement is what Veraison checks (the `measurement-value` in
[`SAMPLE_ATTESTATION.md`](SAMPLE_ATTESTATION.md)). To make it independently
re-derivable:

1. **Pin the toolchain.** Build the TA only inside the pinned attester container
   (fixed OP-TEE + cross-toolchain versions), never an ambient host toolchain.
2. **Erase build paths and time.** Export `SOURCE_DATE_EPOCH` from the commit
   date and pass `-ffile-prefix-map=$PWD=.` / `-fdebug-prefix-map=$PWD=.` to the
   TA build flags so the signed TA is path- and time-independent.
3. **Build twice, compare.** Build the TA in two clean checkouts at different
   paths; the resulting `*.ta` (and therefore its measurement) must be identical.
4. **Publish the measurement.** That hash is the reference value provisioned to
   Veraison; a third party who repeats steps 1–3 from the same commit gets the
   same value and can confirm the published reference value is honest.

> Status: the host artifacts are reproducible **today** (`make repro`). The TA
> measurement re-derivation requires the optee-ra build (Docker + ~40 GB) and is
> documented above as the recipe; the deterministic flags are the same ones the
> host build already proves. This is the highest-leverage remaining hardening
> item and is tracked in [`ROADMAP.md`](ROADMAP.md).

## Why not just sign the binary?

A signature says "the maintainer vouches for these bytes." A reproducible build +
a published measurement says "these bytes are *this source*, and the device is
running them" — no one has to trust the maintainer, only the math and the source
they can read. That is the entire point of the project.
