# Tamper watcher

A small Linux normal-world daemon that watches the enclosure tamper loop and
makes the device's signing key cryptographically unavailable on breach.

## Wiring (PoC, ~$5 of parts)

- A **normally-closed loop** of conductive foil tape / thin wire routed around
  the inside of the clear case and across the lid seam and the power
  feedthrough, both ends to a GPIO and ground.
- The GPIO uses an internal pull-up; the closed loop holds the line at logic 1
  (with `--active-low`, choose polarity to match your wiring). Opening the lid
  breaks the loop → edge → breach.
- Optional: an **LDR (photoresistor)** in parallel so that *light hitting the
  inside* of an opaque-until-opened compartment also trips it.

## Run

```sh
make
sudo ./bin/he-tamper \
    --chip /dev/gpiochip0 --line 17 --active-low \
    --key-file /var/lib/honest-ear/device.fullkey \
    --flag-file /var/lib/honest-ear/tamper.tripped \
    --exec "he_host --trip"
```

On breach it: (1) securely erases `--key-file` (the device's signing-key
material), (2) writes `--flag-file`, and (3) runs `--exec` (here latching the
TA-side tamper flag so the enclave refuses to attest even where the key cannot
be physically destroyed, e.g. the QEMU embedded key).

`--simulate` runs the breach action immediately with no GPIO (for testing):

```sh
make test
```

## Honesty about scope

This is **PoC-grade** tamper response: a determined attacker can bridge the
loop before cutting, glitch power to skip the handler, or desolder storage. It
makes the fail-closed behaviour legible and testable. The **production**
answer routes the tamper line into a secure element (ATECC608 / Zymkey 4i) or
the i.MX CAAM, so the *private key inside the chip* is zeroized in hardware,
with a backup battery so detection works while the device is powered off —
the PCI-PTS / HSM anti-tamper-mesh model. See `../../docs/THREAT_MODEL.md`.
