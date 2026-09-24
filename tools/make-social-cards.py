#!/usr/bin/env python3
"""
Social-preview cards (Open Graph / Twitter, 1200x630) for every writeup and
one for the site itself.

When a writeup is shared on LinkedIn, X, Slack…, the preview used to be the
round machine art (820x940), which those sites crop into a meaningless strip.
This renders a proper landscape card per writeup instead — the art ringed in
its difficulty colour over its own blurred glow, the platform, the title, the
difficulty / OS / protected pills and the first CVE or technique tags — plus a
site card (avatar, name, headline numbers) for every other page.

  assets/img/og/<post-slug>.jpg   one per writeup (both languages share it)
  assets/img/og/site.jpg          the default (`social_preview_image`)

_includes/head.html points og:image / twitter:image at these files for every
slug listed in _data/social_cards.json (also written here). CI runs this
script before every build, so a new writeup gets its card automatically; both
outputs are git-ignored. Run it locally to preview:

  python3 tools/make-social-cards.py

Needs Pillow. Fonts (Lato, IBM Plex Mono — SIL OFL) live in tools/fonts/.
"""

import glob
import json
import os
import re

from PIL import Image, ImageDraw, ImageFilter, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# English first: a slug already carded from _posts/en is not redone from /es.
POSTS = sorted(glob.glob(os.path.join(REPO, "_posts", "en", "*.md"))) + sorted(
    glob.glob(os.path.join(REPO, "_posts", "es", "*.md"))
)
OUT = os.path.join(REPO, "assets", "img", "og")
# The slugs that got a card. _includes/head.html reads it (as site.data) to
# decide whether a writeup's og:image is its card — a data file because, under
# jekyll-polyglot, the Spanish build cannot see /assets in site.static_files.
MANIFEST = os.path.join(REPO, "_data", "social_cards.json")
FONTS = os.path.join(REPO, "tools", "fonts")
AVATAR = os.path.join(REPO, "assets", "img", "avatar.jpeg")

W, H = 1200, 630
S = 2  # everything is drawn at 2x and downsampled: anti-aliased shapes

# The site's dark palette (see assets/css/jekyll-theme-chirpy.scss).
BG = (13, 17, 23)
TEXT = (230, 237, 243)
SOFT = (201, 209, 217)
MUTED = (139, 148, 158)
HAIRLINE = (255, 255, 255, 22)
ACCENT = (159, 239, 0)  # HTB green
LINK = (138, 180, 248)
DIFFICULTY = {  # fill, ink — the validated dark steps used on the site
    "Easy": ((10, 126, 58), (255, 255, 255)),
    "Medium": ((187, 136, 5), (26, 26, 26)),
    "Hard": ((217, 0, 56), (255, 255, 255)),
    "Insane": ((138, 74, 245), (255, 255, 255)),
}
OS_COLOUR = {"linux": (224, 142, 11), "windows": (43, 136, 216), "android": (52, 179, 111)}

SITE_HOST = "andermonreal.github.io"
AUTHOR = "Ander Monreal"


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTS, name), size * S)


def px(value):
    return int(round(value * S))


# --- front matter -----------------------------------------------------------

def front_matter(path):
    text = open(path, encoding="utf-8").read()
    if not text.startswith("---"):
        return None
    block = text[3:text.find("\n---", 3)]

    def scalar(key):
        m = re.search(rf"^{key}:\s*(.+?)\s*$", block, re.M)
        return m.group(1).strip().strip("\"'") if m else ""

    def items(key):
        m = re.search(rf"^{key}:\s*\[(.*)\]\s*$", block, re.M)
        return [t.strip().strip("\"'") for t in m.group(1).split(",") if t.strip()] if m else []

    image = re.search(r"^image:\s*\n\s+path:\s*(\S+)", block, re.M) or re.search(
        r"^image:\s*(\S+)\s*$", block, re.M
    )
    return {
        "title": scalar("title"),
        "categories": items("categories"),
        "tags": items("tags"),
        "image": image.group(1).strip("\"'") if image else "",
        "protected": scalar("protected") == "true",
        "hidden": scalar("hidden") == "true",
    }


def machine_meta(fm):
    """Difficulty, platform and OS — read the same way as the site does."""
    difficulty = next((c for c in fm["categories"] if c in DIFFICULTY), "")
    platform = next((c for c in fm["categories"] if c not in DIFFICULTY), "")
    tags = [t.lower() for t in fm["tags"]]
    osname = next((o for o in ("linux", "windows", "android") if o in tags), "")
    return difficulty, platform, osname


def card_tags(fm, title):
    """CVE ids first, then technique tags — like the Machines list."""
    cves = [t.upper() for t in fm["tags"] if t.lower().startswith("cve-")]
    rest = [
        t for t in fm["tags"]
        if not t.lower().startswith("cve-")
        and t.lower() not in ("cve", "mobile", "linux", "windows", "android", title.lower())
    ]
    return cves + rest


# --- drawing helpers ------------------------------------------------------------

def load_round(path, diameter):
    """The art as a circle: centre-cropped square (like `cover`), round mask."""
    im = Image.open(path).convert("RGBA")
    side = min(im.size)
    left, top = (im.width - side) // 2, (im.height - side) // 2
    im = im.crop((left, top, left + side, top + side)).resize((diameter, diameter), Image.LANCZOS)
    mask = Image.new("L", (diameter, diameter), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, diameter - 1, diameter - 1), fill=255)
    alpha = Image.composite(im.getchannel("A"), mask, mask)
    im.putalpha(alpha)
    return im


def glow(canvas, centre, radius, colour, alpha, blur):
    """A soft radial light: a filled circle, blurred, alpha-composited."""
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    cx, cy = centre
    ImageDraw.Draw(layer).ellipse(
        (cx - radius, cy - radius, cx + radius, cy + radius), fill=colour + (alpha,)
    )
    canvas.alpha_composite(layer.filter(ImageFilter.GaussianBlur(blur)))


def art_glow(canvas, art_path, centre, size, alpha):
    """The artwork itself, blurred big, as ambient light (like the site). The
    art sits inside a wider transparent square so the blur can fade out
    completely — blurred right up to its own edge it would end in a hard line."""
    try:
        art = load_round(art_path, int(size * 0.6))
    except (OSError, ValueError):
        return
    padded = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    padded.alpha_composite(art, ((size - art.width) // 2, (size - art.height) // 2))
    padded = padded.filter(ImageFilter.GaussianBlur(px(60)))
    padded.putalpha(padded.getchannel("A").point(lambda a: int(a * alpha)))
    canvas.alpha_composite(padded, (centre[0] - size // 2, centre[1] - size // 2))


def grid(canvas):
    """A faint blueprint grid fading towards the edges."""
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    step = px(40)
    for x in range(0, canvas.width, step):
        draw.line((x, 0, x, canvas.height), fill=(255, 255, 255, 12), width=S)
    for y in range(0, canvas.height, step):
        draw.line((0, y, canvas.width, y), fill=(255, 255, 255, 12), width=S)
    fade = Image.new("L", canvas.size, 0)
    ImageDraw.Draw(fade).ellipse(
        (px(250), px(-250), px(1550), px(850)), fill=255
    )
    fade = fade.filter(ImageFilter.GaussianBlur(px(160)))
    layer.putalpha(Image.composite(layer.getchannel("A"), Image.new("L", canvas.size, 0), fade))
    canvas.alpha_composite(layer)


def top_bar(canvas, colour):
    """Accent along the top edge, fading out to the right."""
    bar = Image.new("RGBA", (canvas.width, px(7)), colour + (255,))
    fade = Image.linear_gradient("L").rotate(90, expand=True).resize((canvas.width, px(7)))
    fade = fade.point(lambda v: 255 - v)  # opaque on the left
    fade = fade.point(lambda v: min(255, int(v * 1.25)))
    bar.putalpha(fade)
    canvas.alpha_composite(bar, (0, 0))


def ringed_art(canvas, art_path, centre, diameter, ring_colour):
    """Art circle with a background gap and a coloured ring, like `.wu-art`."""
    cx, cy = centre
    draw = ImageDraw.Draw(canvas)
    gap, ring = px(9), px(11)
    outer = diameter // 2 + gap + ring
    draw.ellipse((cx - outer, cy - outer, cx + outer, cy + outer), fill=ring_colour + (255,))
    inner = diameter // 2 + gap
    draw.ellipse((cx - inner, cy - inner, cx + inner, cy + inner), fill=BG + (255,))
    try:
        art = load_round(art_path, diameter)
    except (OSError, ValueError):
        return
    canvas.alpha_composite(art, (cx - diameter // 2, cy - diameter // 2))


def gradient_text(canvas, xy, text, fnt, start, end):
    """Text filled with a left-to-right gradient (the site's title effect)."""
    x, y = xy
    left, top, right, bottom = fnt.getbbox(text)
    w, h = right, bottom
    mask = Image.new("L", (w + px(4), h + px(4)), 0)
    ImageDraw.Draw(mask).text((0, 0), text, font=fnt, fill=255)
    # rotate(90) leaves 0 on the left and 255 on the right.
    ramp = Image.linear_gradient("L").rotate(90, expand=True).resize(mask.size)
    # Hold the start colour for the first ~45%, then blend (like the CSS).
    ramp = ramp.point(lambda v: 0 if v < 115 else min(255, int((v - 115) * 1.25)))
    fill = Image.composite(
        Image.new("RGBA", mask.size, end + (255,)), Image.new("RGBA", mask.size, start + (255,)), ramp
    )
    fill.putalpha(mask)
    canvas.alpha_composite(fill, (x, y))
    return w, h


def overlay(canvas):
    """A transparent layer to draw translucent things on. ImageDraw writes an
    RGBA colour straight into an RGBA image (no blending), so anything with
    alpha < 255 is drawn here and alpha-composited afterwards."""
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    return layer, ImageDraw.Draw(layer)


def pill(canvas, x, y, text, fnt, fill=None, ink=SOFT, outline=None, dot=None, height=44):
    """A rounded label; returns its width."""
    layer, draw = overlay(canvas)
    h = px(height)
    pad = px(18)
    dot_w = px(22) if dot else 0
    tw = int(draw.textlength(text, font=fnt))
    w = pad * 2 + dot_w + tw
    box = (x, y, x + w, y + h)
    if fill:
        draw.rounded_rectangle(box, radius=h // 2, fill=fill + (255,))
    if outline:
        draw.rounded_rectangle(box, radius=h // 2, outline=outline, width=px(2))
    if dot:
        r = px(6)
        cx, cy = x + pad + r, y + h // 2
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=dot + (255,))
    ascent, descent = fnt.getmetrics()
    ty = y + (h - (ascent + descent)) // 2 + px(1)
    draw.text((x + pad + dot_w, ty), text, font=fnt, fill=ink + (255,) if len(ink) == 3 else ink)
    canvas.alpha_composite(layer)
    return w


def fit_font(draw, text, name, max_width, sizes):
    for size in sizes:
        fnt = font(name, size)
        if draw.textlength(text, font=fnt) <= max_width:
            return fnt
    return font(name, sizes[-1])


def footer(canvas, avatar_path):
    layer, line = overlay(canvas)
    y_line = px(528)
    line.line((px(60), y_line, px(1140), y_line), fill=HAIRLINE, width=S)
    canvas.alpha_composite(layer)
    draw = ImageDraw.Draw(canvas)

    size = px(46)
    try:
        avatar = load_round(avatar_path, size)
        canvas.alpha_composite(avatar, (px(60), px(552)))
    except (OSError, ValueError):
        pass
    name_font = font("Lato-Bold.ttf", 26)
    draw.text((px(122), px(559)), AUTHOR, font=name_font, fill=TEXT + (255,))
    name_w = draw.textlength(AUTHOR, font=name_font)
    draw.text(
        (px(122) + name_w + px(14), px(561)), "·  Offensive security",
        font=font("Lato-Regular.ttf", 24), fill=MUTED + (255,),
    )
    host_font = font("IBMPlexMono-Medium.ttf", 22)
    host_w = draw.textlength(SITE_HOST, font=host_font)
    draw.text((px(1140) - host_w, px(563)), SITE_HOST, font=host_font, fill=MUTED + (255,))


def save(canvas, name):
    os.makedirs(OUT, exist_ok=True)
    final = canvas.resize((W, H), Image.LANCZOS).convert("RGB")
    final.save(os.path.join(OUT, name), "JPEG", quality=88, optimize=True, progressive=True)


# --- the cards --------------------------------------------------------------------

def writeup_card(fm, slug):
    difficulty, platform, osname = machine_meta(fm)
    diff_fill, diff_ink = DIFFICULTY.get(difficulty, (LINK, (13, 17, 23)))
    art = os.path.join(REPO, fm["image"].lstrip("/")) if fm["image"] else AVATAR

    canvas = Image.new("RGBA", (px(W), px(H)), BG + (255,))
    grid(canvas)
    art_centre = (px(262), px(282))
    art_glow(canvas, art, art_centre, px(1000), 0.6)
    glow(canvas, art_centre, px(210), diff_fill, 90, px(70))
    top_bar(canvas, diff_fill)
    ringed_art(canvas, art, art_centre, px(318), diff_fill)

    draw = ImageDraw.Draw(canvas)
    x0 = px(505)
    kicker = f"// {platform} · writeup" if platform else "// writeup"
    draw.text((x0, px(118)), kicker, font=font("IBMPlexMono-SemiBold.ttf", 26), fill=ACCENT + (255,))

    title_font = fit_font(draw, fm["title"], "Lato-Black.ttf", px(630), list(range(108, 63, -4)))
    _, title_h = gradient_text(canvas, (x0 - px(3), px(158)), fm["title"], title_font, TEXT, diff_fill)

    y = px(158) + title_h + px(28)
    x = x0
    label_font = font("Lato-Black.ttf", 22)
    if difficulty:
        x += pill(canvas, x, y, difficulty.upper(), label_font, fill=diff_fill, ink=diff_ink) + px(12)
    if osname:
        x += pill(canvas, x, y, osname.capitalize(), font("Lato-Bold.ttf", 24),
                  outline=(255, 255, 255, 50), dot=OS_COLOUR[osname]) + px(12)
    if fm["protected"]:
        pill(canvas, x, y, "PROTECTED", label_font, outline=(255, 255, 255, 50), ink=MUTED)

    # First technique tags, CVE ids first (monospace, CVEs in the accent).
    y += px(66)
    x = x0
    tag_font = font("IBMPlexMono-SemiBold.ttf", 21)
    layer, tags = overlay(canvas)
    for tag in card_tags(fm, fm["title"])[:3]:
        is_cve = tag.startswith("CVE-")
        w = int(tags.textlength(tag, font=tag_font)) + px(28)
        if x + w > px(1150):
            break
        tags.rounded_rectangle(
            (x, y, x + w, y + px(38)), radius=px(8),
            fill=(LINK + (34,)) if is_cve else (255, 255, 255, 14),
            outline=(LINK + (110,)) if is_cve else (255, 255, 255, 40), width=S,
        )
        tags.text((x + px(14), y + px(7)), tag, font=tag_font,
                  fill=(LINK if is_cve else SOFT) + (255,))
        x += w + px(10)
    canvas.alpha_composite(layer)

    footer(canvas, AVATAR)
    save(canvas, f"{slug}.jpg")


def site_card(posts):
    writeups = [fm for fm in posts if not fm["hidden"]]
    cves = {t.lower() for fm in writeups for t in fm["tags"] if t.lower().startswith("cve-")}
    platforms = {machine_meta(fm)[1] for fm in writeups} - {""}

    canvas = Image.new("RGBA", (px(W), px(H)), BG + (255,))
    grid(canvas)
    centre = (px(262), px(282))
    glow(canvas, centre, px(230), ACCENT, 70, px(80))
    top_bar(canvas, ACCENT)
    ringed_art(canvas, AVATAR, centre, px(318), ACCENT)

    draw = ImageDraw.Draw(canvas)
    x0 = px(505)
    draw.text((x0, px(112)), "// offensive security portfolio",
              font=font("IBMPlexMono-SemiBold.ttf", 26), fill=ACCENT + (255,))
    name_font = fit_font(draw, AUTHOR, "Lato-Black.ttf", px(640), list(range(100, 63, -4)))
    _, name_h = gradient_text(canvas, (x0 - px(3), px(150)), AUTHOR, name_font, TEXT, ACCENT)
    draw.text((x0, px(150) + name_h + px(18)), "Computer Engineer · MSc in Cybersecurity",
              font=font("Lato-Bold.ttf", 30), fill=SOFT + (255,))

    y = px(150) + name_h + px(82)
    x = x0
    stat_font = font("IBMPlexMono-SemiBold.ttf", 23)
    for label in (f"{len(writeups)} writeups", f"{len(cves)} CVEs", f"{len(platforms)} platforms"):
        x += pill(canvas, x, y, label, stat_font, outline=(255, 255, 255, 55), ink=TEXT) + px(12)

    footer(canvas, AVATAR)
    save(canvas, "site.jpg")


def main():
    posts, slugs = [], []
    for path in POSTS:
        fm = front_matter(path)
        if not fm or not fm["title"]:
            continue
        slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", os.path.basename(path))[:-3]
        if slug in slugs:
            continue
        writeup_card(fm, slug)
        posts.append(fm)
        slugs.append(slug)
    site_card(posts)

    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(sorted(slugs), fh, indent=0)
        fh.write("\n")
    print(f"social cards: {len(posts)} writeups + site -> {os.path.relpath(OUT, REPO)}/")


if __name__ == "__main__":
    main()
