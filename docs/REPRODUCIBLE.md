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

`tools/repro.sh` builds the C simulator/detector, the Go verifier tools, and the
in-browser WASM verifier (`docs/verify.wasm`) **twice, in two separate trees at
different absolute paths**, with deterministic flags, and compares the SHA-256 of
every artifact. Identical hashes prove the output depends only on the source —
not the path, the clock, or the machine. The WASM is included because it is a
committed, user-facing trust artifact (the in-browser verifier).

Deterministic flags used:

- **C:** `-g0 -fno-ident -ffile-prefix-map=<tree>=.` and a fixed
  `SOURCE_DATE_EPOCH`, so no build path, identifier string, or timestamp leaks
  into the binary.
- **Go:** `-trimpath -buildvcs=false -ldflags=-buildid=` with `CGO_ENABLED=0`
  and `GOPROXY=off`, which makes Go output bit-for-bit reproducible offline.

Expected result: `REPRODUCIBLE  all host artifacts are byte-identical`.

### The in-browser verifier (`docs/verify.wasm`) — honest caveat

`make repro` also rebuilds `docs/verify.wasm` (the in-browser verifier) twice and
asserts the two are byte-identical, so the build is **deterministic within one Go
toolchain**. But Go's wasm output embeds runtime code that differs across compiler
*versions*, so the committed `docs/verify.wasm` is only byte-reproducible with the
**same Go toolchain** that built it (and `docs/wasm_exec.js` is the matching
runtime from that toolchain — `tools/build_wasm.sh` copies it from the same
`GOROOT`, so the pair always agrees). Rebuild it with `make wasm`. CI rebuilds and
**smoke-tests** the wasm on every push (`tools/build_wasm.sh` + a node harness that
checks the browser path matches the CLI's verdicts), but does not byte-compare the
committed binary to the CI build — a strict byte-match gate would require pinning
an exact Go version, which is deferred. The trust anchor is the source + the smoke
test, not the prebuilt bytes; anyone can rebuild and diff.

### CI publishes + attests the manifest (SLSA provenance)

On every push, the `reproducible-build` CI job runs the same check, writes the
SHA-256 manifest (`<sha256>  <binary>`, one line per artifact) to the run summary,
uploads it as the `repro-manifest` artifact, and attaches a **SLSA build
provenance attestation** to it via
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance).
The attestation is a Sigstore-signed, in-toto statement binding the manifest's
digest to *which workflow, commit, and runner produced it* — so a third party can
confirm a given manifest came from this repo's CI on this source, not from
someone's laptop. Verify it with the GitHub CLI:

```sh
# download the manifest from the CI run (or recompute it with `make repro`), then:
gh attestation verify repro-manifest.txt --repo NubsCarson/open-opticon
# (on a fork, substitute your own owner/repo — the attestation is bound to the
#  repo whose CI produced it; the run summary prints the exact command for you.)
```

A successful verification prints the source repo, the workflow that built it, and
the commit — closing the loop from "these bytes are this source" (the two-tree
rebuild) to "and this measurement was produced by this public CI from that source"
(the provenance). The two compose: recompute the manifest locally, confirm it
matches the attested one.

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

## The zk guest image_id — recomputable from source

The RISC Zero guest's `image_id` is a hash of the *published detector* compiled
for the zkVM — the same recompute-from-source property, in a second trust domain.
Anyone with the pinned toolchain and the committed `Cargo.lock` rebuilds the
guest and gets the same `image_id` (e.g. `0x7b3b6516…`), and the *same* receipt
is checkable on an EVM against that id. So the detector's measurement is
independently re-derivable two ways (TEE firmware hash + zk guest image id). This
is re-derivable from source with a pinned toolchain — not a byte-identical
two-tree rebuild like `make repro`. See [`zk/README.md`](../zk/README.md) and
[`onchain/README.md`](../onchain/README.md).

## Why not just sign the binary?

A signature says "the maintainer vouches for these bytes." A reproducible build +
a published measurement says "these bytes are *this source*, and the device is
running them" — no one has to trust the maintainer, only the math and the source
they can read. That is the entire point of the project.
