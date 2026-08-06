#!/usr/bin/env python3
"""Assemble the ghe-wizard demo frames into an animated GIF.

Normalizes frames to a common width on a dark canvas and sequences them with
per-frame hold durations to read like a short product tour.
"""
import os
import sys
from PIL import Image

FRAME_DIR = os.path.join(os.path.dirname(__file__), "frames")
OUT = os.path.join(os.path.dirname(__file__), "demo.gif")

BG = (13, 17, 23)  # matches the dashboard background
CANVAS_W = 820
PAD = 14

# (filename, hold in ms)
SEQUENCE = [
    ("f01_landing.png", 1600),
    ("f02_scorecard_top.png", 2200),
    ("f03_domains.png", 1800),
    ("f04_findings_fail.png", 2000),
    ("f05_expanded.png", 2600),
    ("f06_remediation_modal.png", 2800),
]


def load_and_fit(path):
    im = Image.open(path).convert("RGB")
    # Scale to fit within the canvas content width.
    max_w = CANVAS_W - 2 * PAD
    if im.width > max_w:
        h = round(im.height * max_w / im.width)
        im = im.resize((max_w, h), Image.LANCZOS)
    return im


def frame_on_canvas(im, canvas_h):
    canvas = Image.new("RGB", (CANVAS_W, canvas_h), BG)
    x = (CANVAS_W - im.width) // 2
    # Top-align content for a steady, readable tour.
    canvas.paste(im, (x, PAD))
    return canvas


def main():
    imgs = []
    for name, _ in SEQUENCE:
        p = os.path.join(FRAME_DIR, name)
        if not os.path.exists(p):
            print(f"missing frame: {p}", file=sys.stderr)
            return 1
        imgs.append(load_and_fit(p))

    canvas_h = max(i.height for i in imgs) + 2 * PAD
    frames = [frame_on_canvas(i, canvas_h) for i in imgs]
    durations = [d for _, d in SEQUENCE]

    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    size_kb = os.path.getsize(OUT) / 1024
    print(f"wrote {OUT} ({CANVAS_W}x{canvas_h}, {len(frames)} frames, {size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
