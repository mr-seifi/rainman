#!/usr/bin/env bash
# Publish the rainman tour to https://aminseifi.com/rainman/ (nginx webroot on
# this server). site/index.html is a document fragment (title + style + body
# content); this wraps it in a full HTML document and copies it into place.
set -euo pipefail
cd "$(dirname "$0")"

DEST="${1:-/var/www/aminseifi.com/rainman}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$TMP" <<'PY'
import re, sys

src = open("index.html", encoding="utf-8").read()
# head-only pieces: title, font stylesheet, the page's own <style>
title = re.search(r"<title>.*?</title>", src, re.S).group(0)
font = re.search(r'<link rel="stylesheet"[^>]*>', src).group(0)
style = re.search(r"<style>.*?</style>", src, re.S).group(0)
body = src
for part in (title, font, style):
    body = body.replace(part, "", 1)
body = re.sub(r'<meta name="claude:[^>]*>\s*', "", body).strip()

doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
{title}
<meta name="description" content="rainman merges the output of your recon tools into one deduplicated attack-surface graph you can query, triage and pipe back into your tools.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
{font}
<style>body{{margin:0}}img{{max-width:100%}}[hidden]{{display:none!important}}</style>
{style}
</head>
<body>
{body}
</body>
</html>
"""
open(sys.argv[1], "w", encoding="utf-8").write(doc)
PY

mkdir -p "$DEST"
install -m 644 "$TMP" "$DEST/index.html"
echo "Deployed to $DEST/index.html"
