"""Rend la sortie texte capturée d'une commande en image PNG façon terminal.

Usage : python scripts/render-terminal.py <entrée.txt> <sortie.png> "<titre de fenêtre>"

Le texte n'est pas modifié (hors suppression des codes ANSI et retour à la ligne des
lignes trop longues) : l'image est une capture fidèle d'une exécution réelle.
"""
import re
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

FONT_PATHS = [r"C:\Windows\Fonts\CascadiaMono.ttf", r"C:\Windows\Fonts\consola.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
FONT_SIZE = 15
WRAP = 150
BG, FG, BAR = (12, 12, 12), (204, 204, 204), (40, 40, 40)
PROMPT, OK, KO, WARN = (97, 214, 214), (22, 198, 12), (231, 72, 86), (249, 241, 165)

OK_WORDS = re.compile(r"réussi|Passed|no leaks found|verified against|successfully rolled out|"
                      r"\bRunning\b|condition met|\bReady\b|✓|HTTP 200|SUCCESSES|0 HIGH", re.I)
KO_WORDS = re.compile(r"Failed|denied|refus|blocked|FAILURES|leaks found: [1-9]|rejected|"
                      r"\(HIGH|CRITICAL\)|no signatures found|error|\bX\b|exit=1|GH013", re.I)
WARN_WORDS = re.compile(r"WARN|WARNING|RuleID|Finding|File:|KSV", re.I)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\^\[\[[0-9;]*m")


def load_font():
    for path in FONT_PATHS:
        try:
            return ImageFont.truetype(path, FONT_SIZE)
        except OSError:
            continue
    return ImageFont.load_default()


def colour(line):
    if line.startswith("# ") or line.startswith("(annotations"):
        return (150, 150, 255)
    if line.startswith("PS>") or line.startswith("$ "):
        return PROMPT
    if KO_WORDS.search(line):
        return KO
    if OK_WORDS.search(line):
        return OK
    if WARN_WORDS.search(line):
        return WARN
    return FG


def main(src, dst, title):
    with open(src, encoding="utf-8-sig") as handle:
        raw = ANSI.sub("", handle.read()).replace("\t", "    ").rstrip().splitlines()
    lines = []
    for line in raw:
        lines.extend(textwrap.wrap(line, WRAP, replace_whitespace=False, drop_whitespace=False) or [""])

    font = load_font()
    char_w = font.getbbox("M")[2]
    line_h = int(FONT_SIZE * 1.45)
    width = max(char_w * (max(len(l) for l in lines) + 4), 900)
    height = 44 + line_h * len(lines) + 24
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, 32], fill=BAR)
    for i, dot in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([12 + i * 22, 10, 24 + i * 22, 22], fill=dot)
    draw.text((86, 7), title, font=font, fill=(230, 230, 230))
    y = 44
    for line in lines:
        draw.text((14, y), line, font=font, fill=colour(line))
        y += line_h
    img.save(dst, optimize=True)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
