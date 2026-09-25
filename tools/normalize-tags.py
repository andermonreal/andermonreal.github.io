#!/usr/bin/env python3
"""
Unify tag spellings that collide on the same tag page.

Chirpy builds one page per tag at /tags/<slug>/, and different spellings of a
tag share a slug: "LFI" and "lfi", "credential reuse" and "credential-reuse".
Jekyll then writes both pages to the same file and one overwrites the other,
so a tag page silently lists only part of its writeups (the build shows it as
"Conflict: The following destination is shared by multiple files").

This script finds every such group across all posts (both languages) and
rewrites the `tags: [...]` front-matter line to one spelling per group:

  1. a spelling with spaces   ("privilege escalation" over "privilege-escalation")
  2. then one with capitals   ("LFI" over "lfi", "CVE-2026-1" over "cve-2026-1")
  3. then the most used one.

Posts that end up listing the same tag twice keep it once. Other tags are
left exactly as written. Re-runnable; it only touches files that change.

Usage (from the repo root):
  python3 tools/normalize-tags.py           # rewrite posts, report changes
  python3 tools/normalize-tags.py --check   # report only; exit 1 on conflicts

CI runs it before the build, so a new variant never breaks a tag page.
"""

import collections
import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = sorted(glob.glob(os.path.join(REPO, "_posts", "**", "*.md"), recursive=True))
TAGS_RE = re.compile(r"^(tags:\s*\[)(.*)(\]\s*)$", re.M)

# Curated synonym merges: tags that name the same thing with different words
# (the slug pass only catches different spellings of the SAME word). Left is
# rewritten to right. Keep right a spelling already used elsewhere.
ALIASES = {
    "password-reuse": "credential reuse",
    "path-traversal": "directory traversal",
    "insecure-deserialization": "deserialization",
    "null session smb enumeration": "smb null session",
    "null session smb": "smb null session",
    "samba force user privesc": "samba force user",
}


def slugify(tag):
    """The slug Chirpy/Jekyll gives a tag page (default slugify mode)."""
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", tag.lower())).strip("-")


def split_tags(inner):
    """Split the inline list into (raw_item, bare_tag) pairs."""
    items = []
    for raw in inner.split(","):
        bare = raw.strip().strip("\"'")
        if bare:
            items.append((raw.strip(), bare))
    return items


def main():
    check_only = "--check" in sys.argv[1:]

    usage = collections.Counter()
    spellings = collections.defaultdict(set)
    for path in POSTS:
        match = TAGS_RE.search(open(path, encoding="utf-8").read())
        if not match:
            continue
        for _raw, tag in split_tags(match.group(2)):
            usage[tag] += 1
            spellings[slugify(tag)].add(tag)

    canonical = {}
    for variants in spellings.values():
        if len(variants) < 2:
            continue
        best = max(variants, key=lambda t: (" " in t, t != t.lower(), usage[t], t))
        for variant in variants:
            if variant != best:
                canonical[variant] = best

    # Curated merges of tags that mean the same thing but don't share a slug
    # (so the loop above can't catch them). variant -> canonical spelling.
    for variant, best in ALIASES.items():
        canonical[variant] = best

    if not canonical:
        print("tags: no conflicting spellings")
        return 0

    for variant, best in sorted(canonical.items(), key=lambda kv: kv[1].lower()):
        print(f"tags: {variant!r} -> {best!r}")

    if check_only:
        return 1

    changed = 0
    for path in POSTS:
        text = open(path, encoding="utf-8").read()
        match = TAGS_RE.search(text)
        if not match:
            continue

        seen, out = set(), []
        for raw, tag in split_tags(match.group(2)):
            tag = canonical.get(tag, tag)
            if tag in seen:
                continue
            seen.add(tag)
            # Keep the original quoting when the tag itself did not change.
            out.append(raw if raw.strip("\"'") == tag else tag)

        new_line = match.group(1) + ", ".join(out) + match.group(3)
        if new_line != match.group(0):
            text = text[: match.start()] + new_line + text[match.end():]
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            changed += 1

    print(f"tags: {changed} post files updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
