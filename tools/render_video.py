#!/usr/bin/env python3
"""Render the open-opticon walkthrough — a guided, 16:9 explainer.

Each step shows the same chrome, a plain-English caption, a terminal card with
the real command + curated real output, and a one-line takeaway. The values are
the actual outputs of the tools (Veraison affirming, alarm_tone / ~992 ms, the
FAIL reasons, TEE_ERROR_SECURITY 0xffff000f); this just composes them into a
legible video. Matches the site's palette. Needs only Pillow + ffmpeg.

    python3 tools/render_video.py --nonce <hex> --out docs/assets

Frames stream to a temp dir (held frames are hard-linked, not re-encoded) and are
muxed by ffmpeg into walkthrough.mp4 + .gif; a poster and an asciinema .cast of
the raw commands/outputs are emitted too.
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

S = 2                       # supersample; output is downscaled to 1280x720
W, H = 1280 * S, 720 * S
M = 64 * S                  # page margin
FPS = 30

C = {                       # palette (matches docs/index.html)
    "bg": (9, 9, 11), "card": (16, 16, 20), "border": (38, 38, 43),
    "fg": (250, 250, 250), "muted": (161, 161, 170), "muted2": (113, 113, 122),
    "green": (74, 222, 128), "red": (248, 113, 113), "blue": (96, 165, 250),
    "amber": (251, 191, 36), "violet": (167, 139, 250),
}
DEJ = "/usr/share/fonts/truetype/dejavu"


def font(name, px):
    return ImageFont.truetype(f"{DEJ}/{name}.ttf", px * S)


F = {
    "eyebrow": font("DejaVuSans-Bold", 12), "caption": font("DejaVuSans", 25),
    "title": font("DejaVuSans-Bold", 60), "subtitle": font("DejaVuSans", 21),
    "mono": font("DejaVuSansMono", 17), "monob": font("DejaVuSansMono-Bold", 17),
    "take": font("DejaVuSans", 17), "brand": font("DejaVuSansMono-Bold", 14),
    "chap": font("DejaVuSansMono", 13),
}
MONO_W = round(F["mono"].getlength("M"))
MONO_LH = 27 * S


def canvas():
    img = Image.new("RGB", (W, H), C["bg"])
    return img, ImageDraw.Draw(img)


def tracked(d, xy, s, fnt, fill, extra):
    """Draw text with letter spacing (PIL has no native tracking)."""
    x, y = xy
    for ch in s:
        d.text((x, y), ch, font=fnt, fill=fill)
        x += d.textlength(ch, font=fnt) + extra


def wrap(s, fnt, max_w):
    words, lines, cur = s.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if F["caption"].getlength(t) <= max_w or not cur:
            cur = t
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def chrome(d, chapter, step):
    d.text((M, 26 * S), "open-opticon", font=F["brand"], fill=C["fg"])
    bw = d.textlength("open-opticon", font=F["brand"])
    d.text((M + bw, 26 * S), "/", font=F["brand"], fill=C["muted2"])
    if chapter:
        label = f"{chapter}   {step}/5"
        d.text((W - M - d.textlength(label, font=F["chap"]), 28 * S),
               label, font=F["chap"], fill=C["muted2"])
    d.line([(0, 60 * S), (W, 60 * S)], fill=C["border"], width=1)


def seglen(segs):
    return sum(len(t) for t, _ in segs)


def draw_mono(d, x, y, segs, bold=False):
    fnt = F["monob"] if bold else F["mono"]
    for t, col in segs:
        d.text((x, y), t, font=fnt, fill=C[col])
        x += MONO_W * len(t)


def compose_step(sc, typed, shown, take):
    """One step frame at a given reveal state."""
    img, d = canvas()
    chrome(d, sc["chapter"], sc["step"])
    tracked(d, (M, 84 * S), sc["eyebrow"], F["eyebrow"], C["muted2"], 2 * S)
    cy = 112 * S
    for ln in wrap(sc["caption"], F["caption"], W - 2 * M):
        d.text((M, cy), ln, font=F["caption"], fill=C["fg"])
        cy += 34 * S

    # terminal card
    tx0, ty0, tx1, ty1 = M, 226 * S, W - M, 588 * S
    d.rounded_rectangle([tx0, ty0, tx1, ty1], radius=10 * S,
                        fill=C["card"], outline=C["border"], width=1)
    d.text((tx0 + 18 * S, ty0 + 14 * S), sc["header"], font=F["chap"], fill=C["muted2"])
    d.line([(tx0, ty0 + 42 * S), (tx1, ty0 + 42 * S)], fill=C["border"], width=1)

    x, y = tx0 + 18 * S, ty0 + 60 * S
    if sc.get("command") is not None:
        cmd = sc["command"][:typed]
        d.text((x, y), "$ ", font=F["monob"], fill=C["muted2"])
        d.text((x + MONO_W * 2, y), cmd, font=F["mono"], fill=C["fg"])
        if typed < len(sc["command"]):  # block cursor while typing
            cx = x + MONO_W * (2 + len(cmd))
            d.rectangle([cx, y + 3 * S, cx + MONO_W, y + MONO_LH - 4 * S], fill=C["blue"])
        y += int(MONO_LH * 1.4)
    for seg in sc["out"][:shown]:
        if seg == []:
            y += MONO_LH // 2
            continue
        draw_mono(d, x, y, seg)
        y += MONO_LH

    if take and sc.get("take"):
        col, txt = sc["take"]
        ty = ty1 + 26 * S
        d.ellipse([M, ty + 8 * S, M + 8 * S, ty + 16 * S], fill=C[col])
        d.text((M + 18 * S, ty), txt, font=F["take"], fill=C["muted"])
    return img


def compose_card(title, subs):
    img, d = canvas()
    tw = d.textlength(title, font=F["title"])
    d.text(((W - tw) / 2, H / 2 - 96 * S), title, font=F["title"], fill=C["fg"])
    y = H / 2 + 16 * S
    for i, s in enumerate(subs):
        col = C["muted"] if i == 0 else C["muted2"]
        fnt = F["subtitle"]
        d.text(((W - d.textlength(s, font=fnt)) / 2, y), s, font=fnt, fill=col)
        y += 36 * S
    return img


class Frames:
    def __init__(self, d):
        self.d, self.i = d, 0

    def add(self, img, seconds):
        n = max(1, round(seconds * FPS))
        p0 = f"{self.d}/f{self.i:06d}.png"
        img.save(p0)
        self.i += 1
        for _ in range(n - 1):
            p = f"{self.d}/f{self.i:06d}.png"
            try:
                os.link(p0, p)
            except OSError:
                img.save(p)
            self.i += 1


def render_step(fr, sc):
    cmd = sc.get("command")
    if cmd is not None:
        for k in range(len(cmd) + 1):       # typing
            fr.add(compose_step(sc, k, 0, False), 0.9 / max(1, len(cmd)))
        fr.add(compose_step(sc, len(cmd), 0, False), 0.4)
    full = seglen  # noqa: F841 (kept for clarity below)
    for n in range(1, len(sc["out"]) + 1):  # reveal output line by line
        fr.add(compose_step(sc, len(cmd) if cmd else 0, n, False), 0.45)
    last = len(sc["out"])
    fr.add(compose_step(sc, len(cmd) if cmd else 0, last, True), 2.6)


def steps(nonce):
    n = nonce[:10] + "…"
    return [
        {"chapter": "ATTEST", "step": 1, "eyebrow": "STEP 1 — ATTEST",
         "caption": "First, prove the firmware is the exact published code.",
         "header": "veraison · firmware attestation",
         "command": "optee_remote_attestation",
         "out": [[("# PSA/COSE token  →  Veraison", "muted2")], [],
                 [("ear.status            ", "muted"), ("affirming", "green")],
                 [("executables=", "muted"), ("2", "green"), ("  instance-identity=", "muted"),
                  ("2", "green"), ("  hardware=", "muted"), ("2", "green")]],
         "take": ("green", "Veraison confirms genuine, unmodified firmware.")},
        {"chapter": "DETECT & BIND", "step": 2, "eyebrow": "STEP 2 — DETECT & BIND",
         "caption": "The detector runs inside the enclave. The raw audio is processed and discarded there.",
         "header": "he_host · in-enclave bound output",
         "command": f"he_host /usr/bin/clip.pcm {n}",
         "out": [[("{", "muted")],
                 [('  "schema"', "blue"), (": ", "muted"), ('"honest-ear/bound-output/v1"', "amber")],
                 [('  "payload"', "blue"), (": ", "muted"), ('"a9000101…ab73f9d0"', "amber")],
                 [('  "sig"', "blue"), (":     ", "muted"), ('"a4a30c41…7fe799af"', "amber")],
                 [('  "pub_x"', "blue"), (":   ", "muted"), ('"30a0424c…0aafec3e"', "amber")],
                 [("}", "muted")]],
         "take": ("blue", "Only a ~95-byte signed verdict leaves. The audio never does.")},
        {"chapter": "VERIFY", "step": 3, "eyebrow": "STEP 3 — VERIFY",
         "caption": "Anyone can check the verdict: signature, firmware identity, freshness, anti-replay.",
         "header": "he-verify",
         "command": f"he-verify --nonce {n} bundle.json",
         "out": [[("PASS", "green"), ("  bound output verified", "fg")],
                 [("  event ", "muted"), ("alarm_tone", "fg"),
                  ("   ~992 ms   voice: false", "muted2")]],
         "take": ("green", "PASS = genuine firmware, fresh challenge, not replayed.")},
        {"chapter": "REJECTS FORGERY", "step": 4, "eyebrow": "STEP 4 — REJECTS FORGERY",
         "caption": "Tampered, stale, cloned, or replayed evidence is refused.",
         "header": "he-verify · negative cases", "command": None,
         "out": [[("FAIL", "red"), ("  nonce mismatch (stale / replayed)", "muted")],
                 [("FAIL", "red"), ("  public key ≠ pinned device (cloned)", "muted")],
                 [("FAIL", "red"), ("  counter not greater than last seen (replay)", "muted")]],
         "take": ("red", "Every forgery path turns the verdict red.")},
        {"chapter": "TAMPER = DEAD", "step": 5, "eyebrow": "STEP 5 — TAMPER = DEAD",
         "caption": "Open the enclosure and the enclave refuses to attest — even with correct firmware.",
         "header": "he_host · after the lid opens",
         "command": "he_host --trip   &&   he_host clip.pcm $NONCE",
         "out": [[("tamper flag latched", "amber")],
                 [("FAIL", "red"), ("  attest_audio: ", "muted"), ("0xffff000f", "red"),
                  ("  TEE_ERROR_SECURITY", "muted")]],
         "take": ("red", "An opened device is cryptographically dead.")},
    ]


def write_cast(path, scs):
    with open(path, "w") as f:
        f.write(json.dumps({"version": 2, "width": 96, "height": 28,
                            "title": "open-opticon walkthrough"}) + "\n")
        t = 0.0
        for sc in scs:
            if sc.get("command"):
                t += 0.4
                f.write(json.dumps([round(t, 2), "o", "$ " + sc["command"] + "\r\n"]) + "\n")
            for seg in sc["out"]:
                t += 0.3
                line = "".join(txt for txt, _ in seg)
                f.write(json.dumps([round(t, 2), "o", line + "\r\n"]) + "\n")
            t += 0.6


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--out", default="docs/assets")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    scs = steps(args.nonce)

    tmp = tempfile.mkdtemp(prefix="oo_wt_")
    fr = Frames(tmp)
    intro = compose_card("open-opticon",
                         ["A sensor that proves what it isn't doing.",
                          "verifiable · non-panopticon · OP-TEE remote attestation"])
    fr.add(intro, 3.2)
    for sc in scs:
        render_step(fr, sc)
    fr.add(compose_card("attest → bind → verify",
                        ["Proven on a laptop. No special hardware.",
                         "github.com/NubsCarson/open-opticon"]), 4.0)

    print(f"{fr.i} frames @ {FPS}fps = {fr.i / FPS:.1f}s  (render {W}x{H} → 1280x720)")
    poster = os.path.join(args.out, "walkthrough_poster.png")
    intro.resize((W // S, H // S)).save(poster)
    mp4 = os.path.join(args.out, "walkthrough.mp4")
    gif = os.path.join(args.out, "walkthrough.gif")
    pal = f"{tmp}/pal.png"
    src = ["-framerate", str(FPS), "-i", f"{tmp}/f%06d.png"]
    try:
        subprocess.run(["ffmpeg", "-y", *src, "-vf", "scale=1280:720:flags=lanczos",
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", mp4],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gif_vf = "fps=8,scale=720:-1:flags=lanczos"
        subprocess.run(["ffmpeg", "-y", *src, "-vf", f"{gif_vf},palettegen=max_colors=96", pal],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ffmpeg", "-y", *src, "-i", pal, "-lavfi",
                        f"{gif_vf}[x];[x][1:v]paletteuse=dither=bayer", gif],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    cast = os.path.join(args.out, "walkthrough.cast")
    write_cast(cast, scs)
    for p in (poster, mp4, gif, cast):
        print(f"  wrote {p}  ({os.path.getsize(p) // 1024} KB)")


if __name__ == "__main__":
    main()
