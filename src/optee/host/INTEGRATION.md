# Host (CA) integration — `he_host`

`he_host.c` is a normal-world client that drives the `ATTEST_AUDIO` command and
prints the JSON bound-output bundle. It links against OP-TEE's `libteec` and the
TA's `remote_attestation_ta.h`, exactly like the existing optee-ra host
(`attester/remote_attestation/host/main.c`).

## Option A — build as a second binary in the optee-ra host dir (verified)

The optee-ra host is built with CMake (`attester/remote_attestation/CMakeLists.txt`).
After `tools/stage_optee.sh` copies `he_host.c` and `he_testkey.h` into the host
dir, add a second target there (mirrors the existing `optee_remote_attestation`
target, but `he_host` links only `teec` — it needs no Veraison FFI):

```cmake
# Honest Ear: he_host (bound-audio-output CA) — libteec only, no Veraison FFI.
add_executable (he_host host/he_host.c)
target_include_directories (he_host PRIVATE ta/include PRIVATE host)
target_link_libraries (he_host PRIVATE teec)
install (TARGETS he_host DESTINATION ${CMAKE_INSTALL_BINDIR})
# optional: a sample clip so he_host has audio to attest in the guest. Copy one
# into host/ yourself (e.g. cp test/fixtures/alarm_short.pcm .../host/clip.pcm) —
# stage_optee.sh does not stage it, so keep this OPTIONAL or the build fails.
install (FILES host/clip.pcm DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
```

The `ta/include` path carries `remote_attestation_ta.h` (the
`TA_REMOTE_ATTESTATION_CMD_*` ids) and `host` carries `he_testkey.h`. `he_host.c`
is a pure normal-world client: it does NOT include any TA-only header. This is the
exact change that produced the verified in-enclave bundle in
[`../../../docs/SAMPLE_ATTESTATION.md`](../../../docs/SAMPLE_ATTESTATION.md);
`clip.pcm` then installs to `/usr/bin/clip.pcm` in the guest rootfs.

## Option B — Yocto / buildroot recipe

Add `he_host.c` (and the staged headers) to the same recipe that builds
`optee_remote_attestation`, appending `he_host` to the installed binaries.

## Running the full pipeline

With a fresh nonce `$N` from the challenge server (`he-challenge`):

```sh
# 1. firmware attestation (existing optee-ra client) — verified by Veraison
optee_remote_attestation                      # uses the session nonce

# 2. bound audio output — verified by he-verify / he-challenge
he_host /usr/bin/clip.pcm $N > bundle.json
curl -s -X POST "$CHALLENGE_URL/attest?session=$SID" --data @bundle.json
```

Both are signed by the same attested key, so a PASS on both means: *genuine,
unmodified Honest Ear firmware produced this exact minimal output for this exact
fresh challenge.*

On i.MX 8M Plus, pass the device's CAAM FullKey via `--key-hex <FullKey>`
(printed by the existing `--generate-blackkey` flow) so the bound output is
signed by the non-extractable hardware key.
