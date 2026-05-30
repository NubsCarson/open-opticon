#!/usr/bin/env python3
"""Render the open-opticon terminal walkthrough to an mp4 + gif (+ an asciinema cast).

No screen recorder, no TTY, no network: the scene outputs are the *real* captured
stdout of the host tools and the QEMU drivers; this just paints them into a
terminal canvas with a typing effect so the flow is legible. Tokyo Night Storm
palette. Needs only Pillow + ffmpeg.

    python3 tools/render_video.py --nonce <hex> --out docs/assets

Frames are written to a temp dir and muxed by ffmpeg; the .cast is emitted too so
it can be replayed with `asciinema play`.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

# --- Tokyo Night Storm palette (matches the rest of the rice) --------------
BG       = (36, 40, 59)      # #24283b
BG_BAR   = (26, 29, 43)      # title bar
FG       = (192, 202, 245)   # #c0caf5
DIM      = (86, 95, 137)     # #565f89  comments
PROMPT   = (125, 207, 255)   # #7dcfff
ANSI = {                     # SGR fg code -> rgb
    30: (54, 58, 79),   31: (247, 118, 142), 32: (158, 206, 106),
    33: (224, 175, 104), 34: (122, 162, 247), 35: (187, 154, 247),
    36: (125, 207, 255), 37: (192, 202, 245),
    90: (86, 95, 137),  91: (247, 118, 142), 92: (158, 206, 106),
    93: (224, 175, 104), 94: (122, 162, 247), 95: (187, 154, 247),
    96: (125, 207, 255), 97: (255, 255, 255),
}
DOTS = [(247, 118, 142), (224, 175, 104), (158, 206, 106)]  # traffic lights

FONT_R = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def parse_ansi(line):
    """Split a line into (text, color, bold) runs, honouring a subset of SGR."""
    runs, pos, color, bold = [], 0, FG, False
    for m in SGR.finditer(line):
        if m.start() > pos:
            runs.append((line[pos:m.start()], color, bold))
        for code in (int(c) if c else 0 for c in m.group(1).split(";")):
            if code == 0:
                color, bold = FG, False
            elif code == 1:
                bold = True
            elif code in ANSI:
                color = ANSI[code]
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], color, bold))
    return runs or [("", FG, False)]


class Term:
    def __init__(self, cols=98, rows=32, fs=20, scale=2):
        self.cols, self.rows, self.scale = cols, rows, scale
        self.fr = ImageFont.truetype(FONT_R, fs * scale)
        self.fb = ImageFont.truetype(FONT_B, fs * scale)
        self.cw = round(self.fr.getlength("M"))
        asc, desc = self.fr.getmetrics()
        self.ch = asc + desc + 6 * scale
        self.pad = 18 * scale
        self.bar = 34 * scale
        self.W = self.pad * 2 + self.cw * cols
        self.H = self.bar + self.pad * 2 + self.ch * rows
        self.lines = []          # list of raw strings (may carry ANSI)
        self.frames = []
        self.cast = []           # asciinema v2 events
        self.t = 0.0

    # -- frame capture -------------------------------------------------------
    def _emit_cast(self, text):
        self.cast.append([round(self.t, 3), "o", text])

    def snap(self, hold=1, cursor=True):
        img = Image.new("RGB", (self.W, self.H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, self.W, self.bar], fill=BG_BAR)
        for i, c in enumerate(DOTS):
            cx = self.pad + i * 22 * self.scale + 8 * self.scale
            r = 6 * self.scale
            cy = self.bar // 2
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=c)
        title = "open-opticon walkthrough"
        tw = self.fb.getlength(title)
        d.text(((self.W - tw) / 2, (self.bar - self.ch) / 2 + 2 * self.scale),
               title, font=self.fb, fill=DIM)
        y = self.bar + self.pad
        view = self.lines[-self.rows:]
        for li, raw in enumerate(view):
            x = self.pad
            for text, color, bold in parse_ansi(raw):
                d.text((x, y), text, font=self.fb if bold else self.fr, fill=color)
                x += self.cw * len(text)
            if cursor and li == len(view) - 1:
                d.rectangle([x + 2, y + 2 * self.scale, x + self.cw,
                             y + self.ch - 2 * self.scale], fill=PROMPT)
            y += self.ch
        for _ in range(max(1, hold)):
            self.frames.append(img)
        self.t += max(1, hold) / FPS

    # -- authoring primitives ------------------------------------------------
    def type(self, cmd, prompt="honest-ear $ "):
        """Type a command char-by-char on a fresh prompt line."""
        self.lines.append(prompt)
        self._emit_cast(prompt)
        for ch in cmd:
            self.lines[-1] += ch
            self._emit_cast(ch)
            self.snap(hold=2, cursor=True)
        self.snap(hold=8)

    def out(self, text, per_line=2):
        for ln in text.rstrip("\n").split("\n"):
            self.lines.append(ln)
            self._emit_cast(ln + "\r\n")
            self.snap(hold=per_line, cursor=False)

    def blank(self, n=1):
        for _ in range(n):
            self.lines.append("")
        self.snap(hold=2, cursor=False)

    def comment(self, text):
        self.lines.append(f"\x1b[90m{text}\x1b[0m")
        self._emit_cast(text + "\r\n")
        self.snap(hold=10, cursor=False)

    def card(self, big, small_lines, hold=42):
        """A centred title card (used for open/close)."""
        img = Image.new("RGB", (self.W, self.H), BG)
        d = ImageDraw.Draw(img)
        fbig = ImageFont.truetype(FONT_B, 46 * self.scale)
        bw = fbig.getlength(big)
        cy = self.H // 2 - 70 * self.scale
        d.text(((self.W - bw) / 2, cy), big, font=fbig, fill=PROMPT)
        yy = cy + 70 * self.scale
        for txt, col in small_lines:
            f = self.fr
            w = f.getlength(txt)
            d.text(((self.W - w) / 2, yy), txt, font=f, fill=col)
            yy += self.ch + 4 * self.scale
        for _ in range(hold):
            self.frames.append(img)
        self.t += hold / FPS

    def hold(self, n):
        self.snap(hold=n, cursor=False)


FPS = 24


def read(p):
    with open(p) as f:
        return f.read()


def trim(text, keep_head=None, keep_tail=None, drop_re=None):
    lines = text.rstrip("\n").split("\n")
    if drop_re:
        lines = [l for l in lines if not re.search(drop_re, l)]
    if keep_head is not None and keep_tail is not None and len(lines) > keep_head + keep_tail + 1:
        lines = lines[:keep_head] + ["\x1b[90m    ...\x1b[0m"] + lines[-keep_tail:]
    return "\n".join(lines)


def build(caps, nonce):
    t = Term()
    short_nonce = nonce[:12] + "…" + nonce[-6:]

    t.card("open-opticon",
           [("a surveillance device that proves its own restraint", FG),
            ("", FG),
            ("verifiable · non-panopticon · OP-TEE remote attestation", DIM)])

    t.comment("# 1) the whole host pipeline: detector, in-enclave signing, verifier, tamper")
    t.type("make test")
    t.out(trim(read(f"{caps}/01_make_test.txt"), keep_head=6, keep_tail=4))
    t.blank()

    t.comment("# 2) a REAL OP-TEE attestation on Arm TrustZone (QEMU) — Veraison's verdict")
    t.out(read(f"{caps}/ear.txt"))
    t.blank()

    t.comment("# 3) bound audio output, signed INSIDE the enclave (raw PCM never leaves the TA)")
    t.type(f"he_host /usr/bin/clip.pcm {short_nonce}      # run in the guest TEE")
    t.out(read(f"{caps}/02_bundle_display.txt"))
    t.out("\x1b[90m# pub_x/pub_y == the key Veraison just attested\x1b[0m")
    t.blank()

    t.comment("# 4) verify the bound output on the host")
    t.type(f"he-verify --nonce {short_nonce} bundle.json")
    t.out(read(f"{caps}/03_verify_pass.txt"))
    t.blank()

    t.comment("# 5) it rejects tampered / replayed / cloned evidence")
    t.type(f"he-verify --nonce DEADBEEF… bundle.json        # stale nonce")
    t.out(read(f"{caps}/04_wrong_nonce.txt"))
    t.type(f"he-verify --pin-x <other-device> bundle.json   # cloned to another box")
    t.out(read(f"{caps}/06_clone_fail.txt"))
    t.type(f"he-verify --last-counter 1 bundle.json          # replay")
    t.out(trim(read(f"{caps}/07_replay_fail.txt"), keep_head=1, keep_tail=0))
    t.blank()

    t.comment("# 6) Tier 3 — open the enclosure lid: the enclave refuses to attest")
    t.out(read(f"{caps}/tamper.txt"))
    t.blank()
    t.hold(20)

    t.card("proven on a laptop",
           [("attest the firmware → bind a minimal predicate → verify", FG),
            ("", FG),
            ("github.com/NubsCarson/open-opticon", PROMPT)])
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--caps", default="/tmp/demo_caps")
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--out", default="docs/assets")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    t = build(args.caps, args.nonce)
    print(f"rendered {len(t.frames)} frames @ {FPS}fps "
          f"= {len(t.frames)/FPS:.1f}s  ({t.W}x{t.H})")

    tmp = tempfile.mkdtemp(prefix="oo_frames_")
    try:
        for i, fr in enumerate(t.frames):
            fr.save(f"{tmp}/f{i:05d}.png")
        # poster = the opening title card, scaled like the video
        poster = os.path.join(args.out, "walkthrough_poster.png")
        t.frames[0].resize((t.W // 2, t.H // 2)).save(poster)
        mp4 = os.path.join(args.out, "walkthrough.mp4")
        gif = os.path.join(args.out, "walkthrough.gif")
        pal = f"{tmp}/pal.png"
        subprocess.run(
            ["ffmpeg", "-y", "-framerate", str(FPS), "-i", f"{tmp}/f%05d.png",
             "-vf", "scale=iw/2:ih/2:flags=lanczos", "-c:v", "libx264",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart", mp4],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Compact GIF fallback (mp4 is the primary): drop to 7fps + 600px + a
        # small palette so a 40s clip stays ~2 MB, not tens.
        gif_vf = "fps=7,scale=600:-1:flags=lanczos"
        subprocess.run(
            ["ffmpeg", "-y", "-framerate", str(FPS), "-i", f"{tmp}/f%05d.png",
             "-vf", f"{gif_vf},palettegen=max_colors=80", pal],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["ffmpeg", "-y", "-framerate", str(FPS), "-i", f"{tmp}/f%05d.png",
             "-i", pal, "-lavfi",
             f"{gif_vf}[x];[x][1:v]paletteuse=dither=none", gif],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    cast = os.path.join(args.out, "walkthrough.cast")
    with open(cast, "w") as f:
        f.write(json.dumps({"version": 2, "width": t.cols, "height": t.rows,
                            "title": "open-opticon walkthrough"}) + "\n")
        for ev in t.cast:
            f.write(json.dumps(ev) + "\n")

    for p in (poster, mp4, gif, cast):
        print(f"  wrote {p}  ({os.path.getsize(p)//1024} KB)")


if __name__ == "__main__":
    main()
