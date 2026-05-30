#!/usr/bin/env python3
"""Generate deterministic int16 mono PCM fixtures for Honest Ear tests.

Outputs raw signed 16-bit little-endian, 16 kHz mono:
  silence.pcm  - all zeros                       -> expect NONE
  alarm.pcm    - 3100 Hz tone                    -> expect alarm_tone
  voice.pcm    - broadband noise (voice-like)    -> expect voice
  quiet.pcm    - very low-amplitude noise        -> expect NONE (below floor)

No third-party deps. Deterministic (fixed PRNG seed) so tests are reproducible.
"""
import math
import os
import struct
import sys

SR = 16000
DUR = 1.0
N = int(SR * DUR)


def write_pcm(path, samples):
    with open(path, "wb") as f:
        f.write(struct.pack("<%dh" % len(samples), *samples))
    print("wrote %s (%d samples)" % (path, len(samples)))


def clamp16(v):
    return max(-32768, min(32767, int(v)))


def gen_silence():
    return [0] * N


def gen_tone(freq, amp):
    return [clamp16(amp * math.sin(2 * math.pi * freq * i / SR)) for i in range(N)]


# Simple reproducible LCG matching the C test's spirit (values differ; that's
# fine — the detector decision is what we assert, not bit-exact samples).
def gen_noise(amp):
    out = []
    s = 0x12345678
    for _ in range(N):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        v = ((s >> 16) & 0xFFFF) - 32768
        out.append(clamp16(v * amp / 32768))
    return out


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    os.makedirs(outdir, exist_ok=True)
    write_pcm(os.path.join(outdir, "silence.pcm"), gen_silence())
    write_pcm(os.path.join(outdir, "alarm.pcm"), gen_tone(3100, 12000))
    write_pcm(os.path.join(outdir, "voice.pcm"), gen_noise(14000))
    write_pcm(os.path.join(outdir, "quiet.pcm"), gen_noise(150))


if __name__ == "__main__":
    main()
