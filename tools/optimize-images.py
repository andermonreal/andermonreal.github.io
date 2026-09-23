#!/usr/bin/env python3
"""
Optimize writeup banners and wire up blur-up placeholders.

For every `assets/img/**/banner.png` it:
  * writes an optimized `banner.webp` beside it (and removes the .png),
  * generates a tiny base64 LQIP (Low-Quality Image Placeholder),
  * rewrites the matching posts' front matter: `banner.png` -> `banner.webp`
    and injects/refreshes an `image.lqip:` field (Chirpy blurs it up while the
    real banner loads).

Re-runnable: on later runs it also picks up banners already converted to .webp,
so adding a new machine is just "drop banner.png, run this script".

Requires Pillow with WebP support (already available in this repo's env).
Run from the repo root:  python3 tools/optimize-images.py
"""

import base64
import glob
import io
import os
import re
import sys

from PIL import Image

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG_ROOT = os.path.join(REPO, "assets", "img")
POSTS = glob.glob(os.path.join(REPO, "_posts", "**", "*.md"), recursive=True)

WEBP_QUALITY = 80      # main banner
LQIP_WIDTH = 32        # tiny placeholder width in px
LQIP_QUALITY = 40


def to_webp(png_path):
    """Convert a banner.png to banner.webp (same dir), return the .webp path."""
    webp_path = png_path[:-4] + ".webp"
    with Image.open(png_path) as im:
        im = im.convert("RGBA")
        im.save(webp_path, "WEBP", quality=WEBP_QUALITY, method=6)
    old = os.path.getsize(png_path)
    new = os.path.getsize(webp_path)
    os.remove(png_path)
    print(f"  {os.path.relpath(png_path, REPO)}: {old//1024}KB -> {new//1024}KB webp")
    return webp_path


def make_lqip(webp_path):
    """Return a data: URI for a tiny blurred placeholder of the banner."""
    with Image.open(webp_path) as im:
        im = im.convert("RGBA")
        w, h = im.size
        tw = LQIP_WIDTH
        th = max(1, round(h * tw / w))
        tiny = im.resize((tw, th), Image.LANCZOS)
        buf = io.BytesIO()
        tiny.save(buf, "WEBP", quality=LQIP_QUALITY, method=6)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/webp;base64,{b64}"


def build_banner_map():
    """dir (relative to assets/img) -> {'webp': path, 'lqip': datauri}."""
    mapping = {}
    # Convert any remaining PNG banners first.
    for png in sorted(glob.glob(os.path.join(IMG_ROOT, "**", "banner.png"), recursive=True)):
        to_webp(png)
    # Now index every webp banner (freshly converted + pre-existing).
    for webp in sorted(glob.glob(os.path.join(IMG_ROOT, "**", "banner.webp"), recursive=True)):
        rel = "/" + os.path.relpath(webp, REPO).replace(os.sep, "/")  # /assets/img/.../banner.webp
        mapping[rel] = {"webp": webp, "lqip": make_lqip(webp)}
    return mapping


def split_front_matter(text):
    """Return (front_matter_lines, rest) or (None, None) if no front matter."""
    if not text.startswith("---"):
        return None, None
    parts = text.split("\n")
    if parts[0].strip() != "---":
        return None, None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            return parts[: i + 1], parts[i + 1:]
    return None, None


PATH_RE = re.compile(r'^(\s*)path:\s*(["\']?)(\S*/banner)\.(png|webp)\2\s*$')


def update_post(path, mapping):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    fm, rest = split_front_matter(text)
    if fm is None:
        return False

    out = []
    changed = False
    i = 0
    while i < len(fm):
        line = fm[i]
        m = PATH_RE.match(line)
        if m:
            indent, quote, stem, _ext = m.groups()
            webp_ref = f"{stem}.webp"
            key = webp_ref  # e.g. /assets/img/HTB/Foo/banner.webp
            entry = mapping.get(key)
            # Rewrite path to .webp
            out.append(f'{indent}path: {webp_ref}')
            changed = True
            # Drop an existing lqip line right after (we re-inject a fresh one).
            if i + 1 < len(fm) and re.match(r'^\s*lqip:\s*', fm[i + 1]):
                i += 1
            if entry:
                out.append(f'{indent}lqip: "{entry["lqip"]}"')
            i += 1
            continue
        out.append(line)
        i += 1

    if changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out + rest))
    return changed


def main():
    if not os.path.isdir(IMG_ROOT):
        sys.exit("assets/img not found - run from the repo root")

    print("== Converting banners to WebP + generating LQIP ==")
    mapping = build_banner_map()
    print(f"   {len(mapping)} banners ready")

    print("== Updating post front matter ==")
    n = sum(1 for p in POSTS if update_post(p, mapping))
    print(f"   {n} post files updated")


if __name__ == "__main__":
    main()
