# Runbook — from zero to a verified bound output

Two phases: (A) host-only, runnable anywhere; (B) on-device, which needs the
`optee-ra` build (Docker + ~40 GB) and Arm hardware for Tiers 2–3.

---

## Phase A — host (no TEE, no Docker)

Prereqs: `gcc`, `go` (>=1.23), `openssl`, `python3`.

```sh
cd honest-ear
make test          # C unit tests + Go unit tests + e2e (audio + vision) + tamper self-test
```

Expected: detector unit tests pass, payload golden vector matches, Go verifier
tests pass, and the audio e2e prints `13 passed, 0 failed` (4 positive fixtures,
each asserting event-class + verify-PASS = 8, plus 5 rejection cases = 13). The
vision occupancy e2e (`make vision-e2e`) also runs and passes, exercising the
same bind+verify path on camera-style frames (empty/occupied + a tamper case).
This validates everything except OP-TEE itself.

Manual single run + live challenge flow: see the project README quickstart.

### Phase A+ — optional public-verifiability legs (host, laptop-runnable)

Both run on a laptop with their own toolchains; only a *live testnet* deploy is
deferred (funded key + RPC).

```sh
cd zk && cargo test -p oo_detector   # the Rust detector port matches the C one
cd zk && cargo run --release -- ../test/fixtures/alarm.pcm   # STARK prove+verify (~min)
cd onchain && forge install && forge test   # verify the Groth16 receipt on a local EVM
```

See [`zk/README.md`](../zk/README.md) and [`onchain/README.md`](../onchain/README.md).

---

## Phase B — on device

> **Quick path:** on a machine with Docker and **≥45 GB free**,
> `tools/run_qemu.sh /path/to/optee-ra` automates B0–B4's deterministic setup
> (Veraison up, provisioning, relying party, attester container) behind a
> disk-safety preflight, then prints the exact interactive QEMU commands. The
> manual steps below are the full reference.

### B0. Build base optee-ra on QEMU (the reliable path)

Follow the upstream `optee-ra` README steps 0–6. Summary:

```sh
git clone https://github.com/iisec-suzaki/optee-ra && cd optee-ra
# Veraison (pinned commit per upstream README):
git clone https://github.com/veraison/services.git
( cd services && git checkout 8f5734c )
make -C services docker-deploy
source services/deployments/docker/env.bash   # or env.zsh on zsh
veraison status                                # vts/provisioning running
```

Budget **a full day** for the first OP-TEE + QEMU image build (~30–40 GB; clear
disk first) and watch the Veraison version-lock. Confirm a baseline attestation
PASS before adding anything.

### B1. Stage Honest Ear into the tree

```sh
honest-ear/tools/stage_optee.sh /path/to/optee-ra
```

This copies the shared sources + TA/PTA/host add-ons in and prints a checklist.
Apply the small edits per the INTEGRATION.md files:

- `src/optee/pta/INTEGRATION.md` — add `PTA_REMOTE_ATTESTATION_SIGN_DATA` (id
  `0x3`), paste `cmd_sign_data`, add the dispatch case (outside the CAAM guard).
- `src/optee/ta/INTEGRATION.md` — add `ATTEST_AUDIO` (id 3) + `TRIP_TAMPER`
  (id 4), include `he_audio_ta.h`, add dispatch cases, add `he_*.c` to `sub.mk`,
  bump `TA_STACK_SIZE` to 4 KB.
- `src/optee/host/INTEGRATION.md` — add `he_host` to the host build.

Rebuild the OP-TEE image and host binaries.

### B2. Update reference values for the new TA measurement

The TA measurement changes when you add code. Re-provision Veraison reference
values (the `provisoning/` flow + `provisoning/data/comid-psa-ta-qemu.json`).
Re-run a baseline attestation and confirm PASS.

### B3. Run the bound-output loop

```sh
# 1. start the verifier (renders a QR per challenge if `qrencode` is installed)
cd honest-ear/src/verifier && go run ./cmd/he-challenge --addr :8090 &

# 2. mint a fresh challenge: returns {"session":...,"nonce":...,"attest_url":...}
RESP=$(curl -s http://<host>:8090/challenge)
SID=$(echo "$RESP"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["session"])')
N=$(echo "$RESP"    | python3 -c 'import sys,json;print(json.load(sys.stdin)["nonce"])')

# 3. on the device: firmware attestation (existing client) — verified by Veraison
optee_remote_attestation                 # -> Veraison PASS (firmware identity)

# 4. on the device: bound audio output with the SAME nonce $N
he_host /usr/bin/clip.pcm "$N" > bundle.json

# 5. verify the bound output against that session
curl -s -X POST "http://<host>:8090/attest?session=$SID" --data @bundle.json
#    -> {"verdict":"PASS","event":"alarm_tone",...}
```

A clip is just raw int16 mono PCM (`python3 test/gen_frames.py` makes samples;
`sox in.wav -r 16000 -c 1 -e signed -b 16 out.pcm` converts real audio).

Steps 3–4 are automated headlessly by
[`../tools/qemu_bound_output.expect`](../tools/qemu_bound_output.expect) (boots,
logs in, runs `he_host` with `$HE_NONCE`, prints the signed bundle) — the same
pattern as `qemu_attest.expect` in B3a.

### B3a. Verified working on QEMU — the real gotchas

This path has actually produced a green `affirming` Veraison attestation (see
[`SAMPLE_ATTESTATION.md`](SAMPLE_ATTESTATION.md)). Things that *will* bite you:

- **The upstream attester Dockerfile crams the whole build into one `RUN` with no
  download retries.** Transient timeouts fetching the ARM toolchains or buildroot
  packages then fail the entire ~40-min build. Fix: split that `RUN` into
  sync / toolchains / make layers, **wrap `make toolchains` and `make` in retry
  loops** (buildroot/toolchains resume incrementally within a layer), and build
  with **`docker build --network=host`** (the bridge network was the flaky part).
- **Stage the PTA header onto the TA include path** (`tools/stage_optee.sh` does
  it) and keep the GP-1.1 `uint32_t` length params — see `src/optee/ta/INTEGRATION.md`.
- **Re-provision the reference value to the TA's reported measurement** so the
  status goes `warning` → `affirming` (the measurement changes because we add
  in-enclave code — that's expected; you publish *your* firmware's measurement).
  Run **`veraison clear-stores` before re-provisioning a new measurement** — a
  stale reference value otherwise lingers and the appraisal stays `warning`.
- **If `/tmp` got cleared, restore the CA cert** before provisioning:
  `mkdir -p /tmp/veraison/certs && cp services/deployments/docker/src/certs/rootCA.crt /tmp/veraison/certs/`.
- **Drive QEMU headlessly with [`../tools/qemu_attest.expect`](../tools/qemu_attest.expect)**
  (`docker cp` it in, `docker exec … expect …`). It starts the soc_term consoles,
  runs `make run-only` (which skips its own xterms when the ports are listening),
  sends `c` to the frozen (`-S`) QEMU monitor, logs in, and runs
  `optee_remote_attestation`. It also kills any leftover QEMU first — a stale one
  holds the gdb socket and blocks the next boot.

### B4. Tier 2 — i.MX 8M Plus (hardware-bound key)

- Build the Yocto image (`attester/container-imx`) and follow optee-ra's i.MX
  secure-boot docs (the `attester/container-imx` README / upstream NXP
  secure-boot guide). **Do not put one-way fuse burning on the critical
  path** — develop in Open mode; a live run must never depend on a fuse.
- Generate the device CAAM black key with the existing `--generate-blackkey`
  flow; it prints a `FullKey` (PubX‖PubY‖blob). Store it as the device key file.
- Pass `--key-hex <FullKey>` to `he_host` so the bound output is signed by the
  non-extractable key. Pin the device's PubX/PubY in the verifier
  (`he-verify --pin-x --pin-y` / `he-challenge --pin-x --pin-y`).
- Prove anti-clone: copy the key blob to a second i.MX → attestation FAILS
  (different device JDKEK).

### B5. Tier 3 — tamper enclosure

Build and run the watcher (`src/tamper/README.md`):

```sh
cd honest-ear/src/tamper && make
sudo ./bin/he-tamper --chip /dev/gpiochip0 --line 17 --active-low \
     --key-file /var/lib/honest-ear/device.fullkey --exec "he_host --trip"
```

Open the lid → key erased + TA flag latched → re-run B3 → attestation FAIL even
with correct firmware. The fail-closed behaviour is demonstrated headlessly in
QEMU by [`../tools/qemu_tamper.expect`](../tools/qemu_tamper.expect) (healthy
run → `he_host --trip` → re-attest returns `TEE_ERROR_SECURITY`).

---

## Reproducibility notes

The 30–40 GB build plus the Veraison version-lock are the slow, fragile parts.
Keep a pre-provisioned, snapshotted QEMU image so a clean run doesn't depend on
rebuilding the world. The `affirming` appraisal in
[`SAMPLE_ATTESTATION.md`](SAMPLE_ATTESTATION.md) was produced by exactly these
steps.
