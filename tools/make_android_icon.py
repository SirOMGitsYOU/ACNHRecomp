#!/usr/bin/env python3
"""The Android launcher icons (android/res/mipmap-*/ic_launcher.png from artwork/iconRounded.png, ic_launcher_round.png
from artwork/iconCircular.png) and android/icon_512.png (the rounded one; tools/make_icons.sh makes the computers' icons
from it). No Nintendo artwork. Needs Pillow."""
import os
from PIL import Image


def square(path):
    """The image centered on a transparent square (the artwork is a pixel or two off square)."""
    im = Image.open(path).convert("RGBA")
    side = max(im.size)
    sq = Image.new("RGBA", (side, side))
    sq.paste(im, ((side - im.width) // 2, (side - im.height) // 2))
    return sq


def main():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    out = os.path.join(root, "android", "res")
    rounded = square(os.path.join(root, "artwork", "iconRounded.png"))
    circle = square(os.path.join(root, "artwork", "iconCircular.png"))
    for name, px in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)):
        d = os.path.join(out, f"mipmap-{name}")
        os.makedirs(d, exist_ok=True)
        rounded.resize((px, px), Image.LANCZOS).save(os.path.join(d, "ic_launcher.png"))
        circle.resize((px, px), Image.LANCZOS).save(os.path.join(d, "ic_launcher_round.png"))
    rounded.resize((512, 512), Image.LANCZOS).save(os.path.join(out, "..", "icon_512.png"))


if __name__ == "__main__":
    main()
