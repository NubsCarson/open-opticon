#!/usr/bin/env python3
"""Generate deterministic 8-bit grayscale PGM fixtures for the vision path.

Outputs binary P5 PGM, 64x64, maxval 255:
  empty.pgm     - flat field (value 128)                 -> expect "empty"
  occupied.pgm  - a textured 32x32 subject on the field  -> expect "occupied"

The "subject" is a block of vertical 0/255 stripes: strong in-tile gradients
that the occupancy detector reads as structure, exactly like test_vision.c. No
third-party deps; deterministic so tests are reproducible.
"""
import os
import sys

W = H = 64
FLAT = 128


def write_pgm(path, pixels):
    with open(path, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (W, H))
        f.write(bytes(pixels))
    print("wrote %s (%dx%d)" % (path, W, H))


def gen_empty():
    return [FLAT] * (W * H)


def gen_occupied():
    px = [FLAT] * (W * H)
    # a 32x32 striped block in the top-left (covers a 2x2 group of 16px tiles)
    for y in range(32):
        for x in range(32):
            px[y * W + x] = 255 if (x & 1) else 0
    return px


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    os.makedirs(outdir, exist_ok=True)
    write_pgm(os.path.join(outdir, "empty.pgm"), gen_empty())
    write_pgm(os.path.join(outdir, "occupied.pgm"), gen_occupied())


if __name__ == "__main__":
    main()
