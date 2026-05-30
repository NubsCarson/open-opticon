# Sample attestation — a real, green OP-TEE run

This is a genuine end-to-end run on QEMU (Arm TrustZone) on a dev laptop: OP-TEE
boots, the Honest Ear TA + the `PTA_SIGN_DATA` PTA run, the PTA emits a real
PSA/COSE attestation token, and **Veraison verifies it as fully `affirming`**.
Not a simulation — the host simulator path (`make test`) is separate; this is
the actual TEE.

## How it was produced

Per [`RUNBOOK.md`](RUNBOOK.md) Phase B: `optee-attester` image built, container
run with the PTA/TA mounted, OP-TEE rebuilt with `CFG_REMOTE_ATTESTATION_PTA=y`,
reference values provisioned for the TA's measured firmware, then driven headless
with [`../tools/qemu_attest.expect`](../tools/qemu_attest.expect):

```
optee_remote_attestation         # in the QEMU guest, as root
```

## The evidence (PTA → CA)

A 310-byte CBOR/COSE PSA attestation token signed by the attestation key, e.g.:

```
d28443a10126a058eba71901097818687474703a2f2f61726d2e636f6d2f7073612f322e302e30
19095a1a1808e66819095b19300019095c582071656d752d6f707465652d72612d303030303030
... (COSE_Sign1: protected hdr ES256, PSA claims, nonce, measurement, signer-id,
    instance-id, 64-byte ECDSA signature) ...
```

Claims include `eat_profile = http://arm.com/psa/2.0.0`, the verifier's fresh
nonce, `psa-implementation-id = qemu-optee-ra-0000000000000001`, the TA
`measurement-value`, the `signer-id`, and the `psa-instance-id`.

## The Veraison verdict (EAR)

Veraison returned a signed EAR JWT whose decoded payload is:

```json
{
  "submods": {
    "PSA_IOT": {
      "ear.status": "affirming",
      "ear.trustworthiness-vector": {
        "configuration": 0,
        "executables": 2,
        "file-system": 0,
        "hardware": 2,
        "instance-identity": 2,
        "runtime-opaque": 2,
        "sourced-data": 0,
        "storage-opaque": 2
      },
      "ear.veraison.annotated-evidence": {
        "eat-profile": "http://arm.com/psa/2.0.0",
        "psa-implementation-id": "cWVtdS1vcHRlZS1yYS0wMDAwMDAwMDAwMDAwMDAwMDE=",
        "psa-instance-id": "AZDHHoAwT5jWVWpALAWTszqArL0I5K/5xAKfbhfhA5lR",
        "psa-software-components": [
          {
            "measurement-type": "ARoT",
            "measurement-value": "HqLzzpodsF4k9oSVJ3/u22XbGa4oZcLez8AyEB9FDXs=",
            "signer-id": "rLsRx+TaIXIFUjzkzhokWuGiOa48a/2eeHH35di66Gs="
          }
        ]
      }
    }
  }
}
```

`ear.status: affirming` with `executables: 2` and `instance-identity: 2` means
Veraison confirmed: genuine published firmware (the measurement matches the
provisioned reference value), correct attestation key, fresh nonce. This is the
trust verdict the whole project is about — **and it ran on the laptop.**

## The bound audio output — verified in-enclave

The attestation above proves the *firmware*. The point of Honest Ear is what that
firmware then *does*: produce a signed predicate about audio without leaking the
audio. That step also ran inside this same QEMU TEE.

`he_host` fed a 1 s 3.1 kHz alarm clip (`clip.pcm`) to the `ATTEST_AUDIO` TA. The
in-enclave integer Goertzel detector classified it, bound the result to the
verifier's fresh nonce plus a monotonic anti-replay counter, serialized it as
deterministic CBOR, and signed it inside the enclave via `PTA_SIGN_DATA`. The raw
PCM never left the TA. The bundle emitted in the guest:

```json
{
  "schema": "honest-ear/bound-output/v1",
  "payload": "a90001015820bfafae49b4136fbb1ab0e25b4040095d4901dbc3b2db1d4183c550cafc477ec1020203f4040105183e061903e0070108582051e7de71c7f04ed661fcd4588a5399eafa51553fd6a0ac9b2d173eadab73f9d0",
  "sig": "a4a30c413ff5794803954b8659aff2f976578c2cae36e3ff10e6087277d743021b224e74e02d55a4023f7ef4f3b459df08363bd2d16b8a1a9a71de977fe799af",
  "pub_x": "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e",
  "pub_y": "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723"
}
```

`pub_x`/`pub_y` are byte-identical to the attestation key Veraison verified above
(`HE_TESTKEY_*_HEX`) — i.e. the bound output is signed by the *same* key whose
firmware just appraised `affirming`. Verifying it on the host:

```
$ he-verify --nonce bfafae49…477ec1 bundle.json
PASS  bound output verified (signature + freshness + anti-replay)
  event        : alarm_tone
  presence     : 1
  voice_active : false
  frames       : 62  (~992 ms observed)
  counter      : 1
  nonce        : bfafae49…477ec1
  config_hash  : 51e7de71…73f9d0
```

`frames: 62 (~992 ms)` matches the 1 s clip; `event: alarm_tone` with
`voice_active: false` is the detector correctly calling a pure tone (not speech).
Re-running with any other nonce yields `FAIL  nonce mismatch` — the freshness gate
rejects stale/replayed evidence. This is the complete chain the project claims:
**attest the firmware → bind a minimal predicate from that firmware to a fresh
challenge → verify the bound output**, all on the laptop, no simulator.

## Notes

- Before provisioning the reference value to the TA's real measurement, the
  status was `warning` (`executables: 33`) — the expected measurement mismatch,
  because our in-enclave detector code (`he_audio_ta.c` etc.) changes the TA's
  measured hash (and it changes again whenever that code changes — the value
  above is build-specific). Publishing that measurement as the reference value
  is exactly the intended trust model: the verifier checks against the
  *published* firmware.
- **Gotcha:** when you provision a *new* measurement, run
  `veraison clear-stores` first — a stale reference value otherwise coexists and
  the appraisal stays `warning` (`executables: 33`) even though the reported
  measurement matches your new entry.
- The QEMU test build uses a shared embedded key, so this proves *genuine
  published code in OP-TEE*, not device identity; device identity needs the
  i.MX 8M Plus CAAM hardware-bound key (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
- `configuration`/`file-system`/`sourced-data` are `0` (no claim) — neutral, not
  a failure.
