# Hardware — the real device, end to end

> **Status (honest):** nothing here has run on physical hardware yet. Everything
> proven so far is on QEMU (Arm TrustZone) + the host verifier — Tier 1, the
> in-enclave bound output, and the fail-closed tamper path. This document is the
> turnkey plan for when a board arrives: bill of materials, the full flow, the
> wiring, and exactly which guarantees each tier buys. The build/provision
> specifics live in [`RUNBOOK.md`](RUNBOOK.md) Phase B; this is the product +
> hardware view that sits on top of it.

## Pick a board

| | **Raspberry Pi 3B+** (~$60 all-in) | **i.MX 8M Plus board** (~$250+) |
|---|---|---|
| optee-ra support | yes | yes |
| What it proves | Tier 1 on **real silicon** (genuine attested firmware, real TrustZone — not an emulator) | Tier 1 **+ Tier 2 device identity** |
| Signing key | shared embedded test key (no hardware key) | **CAAM black key** — the private half never leaves the chip |
| Anti-replay counter | best-effort (REE-backed storage) | rollback-proof (eMMC **RPMB**) |
| Secure boot | limited | **AHAB** signed boot |

The Pi is the cheap "it runs on real hardware" step. The **i.MX 8M Plus is the
real target**: CAAM is what makes "*this specific device*, un-clonable" true
rather than just "genuine code".

## Bill of materials

- **Board:** i.MX 8M Plus dev board (NXP EVK, or a Variscite/Toradex/Compulab
  SoM board) — or a Raspberry Pi 3B+ for the Tier-1-on-silicon step.
- **Boot media + console:** microSD/eMMC, 5 V PSU, a USB-UART cable.
- **Mic:** an I2S MEMS mic (INMP441, ~$5) or a mic HAT. (USB mic also works for a
  first bring-up.)
- **Enclosure (Tier 3):** a clear case, conductive foil tape or thin wire for a
  normally-closed loop around the seam + power feedthrough, an LDR
  (photoresistor), a resistor, and a status LED. ~$10–15.
- **Production tamper:** an ATECC608 secure element (~$1) + a coin cell, so key
  destruction happens in hardware and detection works while powered off.

## What the device is, does, and how it's used

A small **see-through box** that listens but can *prove* it only ever emits a
minimal `alarm / voice / none` verdict — and goes cryptographically dead the
instant it's opened.

```
            ┌───────────────────────────────┐  clear case, foil tamper loop
   mic ───▶ │  board (i.MX 8M Plus / Pi)    │  around the seam + an LDR
            │   • OP-TEE secure world: the  │
            │     Honest Ear TA + CAAM key  │  ● status LED
            │   • normal world: he_host,    │
            │     he-tamper watcher (GPIO)  │  ⎓ power feedthrough (also looped)
            └───────────────────────────────┘
```

**Use:** mount it → enroll its public key (pin it in the verifier + append it to
the transparency log) → anyone walks up, scans the QR (a fresh challenge), and
their phone shows live: *this is the genuine published firmware, it emitted only
this minimal verdict, for this fresh nonce* — or RED. Open the case → it's dead.

## The end-to-end flow

0. **Acquire** the BOM above.
1. **Build & flash firmware.** Build the OP-TEE image for the board (Yocto via
   `attester/container-imx` for i.MX; the Pi build otherwise), stage Honest Ear
   (`tools/stage_optee.sh` + the INTEGRATION.md edits), do a **reproducible
   build and publish the TA measurement** ([`REPRODUCIBLE.md`](REPRODUCIBLE.md)),
   flash. Develop in **Open boot mode** — never burn fuses on the bring-up path.
   See [`RUNBOOK.md`](RUNBOOK.md) B0–B2.
2. **Provision device identity** (i.MX). Generate the CAAM black key on the
   device with the existing `--generate-blackkey` flow; it prints a `FullKey`
   (`PubX‖PubY‖blob`). The private half stays in CAAM. See `RUNBOOK.md` B4.
3. **Enroll the public key** (host side — runnable today, see below): pin
   `PubX/PubY` in the verifier **and** append it to the transparency log, then
   sign a checkpoint. Provision Veraison reference values for the firmware
   measurement.
4. **Wire the sensor + tamper.** Connect the mic; route the foil loop + LDR to a
   GPIO and run the existing watcher:
   ```sh
   sudo src/tamper/bin/he-tamper --chip /dev/gpiochip0 --line 17 --active-low \
        --key-file /var/lib/honest-ear/device.fullkey --exec "he_host --trip"
   ```
   In production, route the tamper line into the ATECC608/CAAM so the *private
   key inside the chip* is zeroized in hardware, battery-backed.
5. **Run the loop.** mic → `ATTEST_AUDIO`: the in-enclave integer detector
   classifies, the raw PCM is **zeroized**, the predicate is serialized as
   deterministic CBOR and **signed by the CAAM key** (PTA_SIGN_DATA), bound to a
   verifier nonce + an **RPMB monotonic counter**:
   ```sh
   he_host /usr/bin/clip.pcm "$NONCE" --key-hex "$FULLKEY" > bundle.json
   ```
6. **Verify.** The `he-challenge` server / phone `/v` page issues the nonce, gets
   the bundle, and checks signature + firmware identity (Veraison `affirming`) +
   endorsement pin (the logged CAAM pubkey) + freshness + counter → live
   PASS/FAIL. This is the exact path already proven on QEMU + the host verifier.
7. **Tamper / anti-clone.** Open the case → loop breaks → key erased + TA flag
   latched → attestation FAILS even with correct firmware. Copy the SD to a
   second board → its CAAM key differs → pin/log mismatch → FAILS.

### Enrolling a device key (runnable today on a laptop)

This part needs no board — it's the existing `he-log` + `he-verify` tools. Given
a device's public coordinates (`$DX`, `$DY` hex, from step 2's FullKey):

```sh
cd src/verifier
go build -o /tmp/he-log ./cmd/he-log
LK=$(/tmp/he-log genkey | awk '/priv/{print $3}')      # the log's signing key
/tmp/he-log add  --log device.log  "$DX$DY"            # append the endorsement
/tmp/he-log prove --log device.log --key "$LK" --index 0 > endorsement.json
/tmp/he-log verify --proof endorsement.json            # -> PASS, it's logged
```

The verifier then pins that device with
`he-verify --pin-x $DX --pin-y $DY` (or `he-challenge --pin-x --pin-y`), and a
clone that can't reproduce signatures under the logged key is rejected.

## Phones & Android — what fits, what doesn't

Of the original five options — *AOSP fork, Play Store app, Pi/i.MX devboard, buy
a tamper enclosure, DIY enclosure* — the devboard + DIY enclosure are what this
project is built on. The phone options are tempting but land in the wrong place
for the **sensor**, and the right place for the **verifier**.

**Sensor on a phone — no.** A normal Android app runs in the **normal world**;
the mic data flows through Android's userspace audio stack, so "we discarded the
audio" is back to a *promise*. The attestation you can get —
**Play Integrity** — is closed and Google-rooted: it attests device/app
integrity to Google's policy, **not** "this specific open detector ran in an
enclave with no exfil path." You can't load your own Trusted App into a stock
phone's TrustZone (it's OEM/Google-signed). An **AOSP fork** doesn't fix the root
problem — you still don't own the phone's TEE, and you'd be rebuilding the
optee-ra/Veraison story while fighting a locked platform. The i.MX/OP-TEE path
gives the real guarantee with **you** owning the TA. *(Verdict: skip the app and
the AOSP fork for the sensor.)*

**Phone as the verifier — yes.** The phone is the natural **auditor**: scan the
QR, issue the fresh challenge, verify the device's proof. The mobile `/v` page
already does exactly this in a browser; a native app would add camera QR scan,
offline verification, and pinned-endorsement management. The phone *checks* the
box; it isn't the box.

**Phone as a second prover — maybe (roadmap).** Android **hardware key
attestation** (StrongBox/Keystore) is a legitimate independent attestation root.
In the 2-of-3 multi-prover plan, a phone could be one leg alongside the OP-TEE
device and a TPM — different silicon, different failure mode.

**TPM as a heterogeneous root — demonstrated (`make tpm-e2e`).** A P-256 key
generated INSIDE a TPM (its private half never leaves the chip) signs an Honest
Ear artifact that the *unmodified* stdlib verifier accepts after enrolling only
its public X/Y — concrete evidence the verifier is root-agnostic and substantiates
the "TPM on PC" claim with a genuinely different keystore/root than the QEMU test
key. It runs against a **software TPM (swtpm)** in a dedicated CI job (so "TPM" here
is the emulator, not separate hardware); on a real TPM set
`TPM2TOOLS_TCTI=device:/dev/tpmrm0`. HONEST SCOPE: the TPM did **not** observe the
audio and there is no measured-boot/PCR binding of the detector to this key — it
is a signing-root demonstration, **not** a second witness of the event, and is
strictly weaker than the OP-TEE Tier-1 attest+bind+verify.

## Honest gaps that only close on real hardware

| Gap | Status |
|---|---|
| Secure-world audio capture (I2S/PDM in the secure world) | normal world feeds the TA today; a real driver effort — the main remaining "analog-hole" |
| TA reproducible build re-derivable on-device | host artifacts reproducible today; TA recipe documented |
| RPMB monotonic counter + AHAB secure boot | board-specific bring-up |
| Powered-off tamper (battery + secure element) | design only |
| 2-of-3 multi-prover (a real 2nd/3rd root) | verifier logic done; hardware leg not wired |
| Audited detector model (vs the threshold stub) | roadmap |

None of these is missing polish — they need an i.MX board, an enclosure, or a
proving toolchain. Until then, the verifier, the binding, and the whole
attest → bind → verify loop are proven on QEMU and runnable on a laptop.
