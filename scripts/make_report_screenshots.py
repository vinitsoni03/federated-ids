"""Render report screenshots: code excerpts (syntax-highlighted, with line numbers) and terminal captures.

    python scripts/make_report_screenshots.py [--terminal-dir .tmp/report] [--out reports/screenshots]

Code excerpts are read from the repository at the line ranges in CODE, so the images always match the
source. Terminal captures are the text files in --terminal-dir (real command output saved beforehand;
IP addresses already redacted there). Nothing is fetched or executed.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from pygments import lex
from pygments.lexers import get_lexer_for_filename
from pygments.styles import get_style_by_name

ROOT = Path(__file__).resolve().parents[1]
FONT = "C:/Windows/Fonts/consola.ttf"
FONT_B = "C:/Windows/Fonts/consolab.ttf"
SIZE = 18
PAD = 22
BAR = 38

# (output name, file, first line, last line)
CODE = [
    ("code_aggregators", "src/federated_ids/federated/aggregators.py", 17, 51),
    ("code_poisoning", "src/federated_ids/attacks/poisoning.py", 55, 64),
    ("code_evasion_constraints", "src/federated_ids/attacks/evasion.py", 57, 72),
    ("code_flower_client", "flower_app/fids_flower/client_app.py", 13, 36),
    ("code_flower_server", "flower_app/fids_flower/server_app.py", 44, 58),
    ("code_leakage_test", "tests/test_ciciot_and_splits.py", 85, 103),
    ("code_serving_endpoint", "serving/app.py", 47, 82),
    ("code_run_hybrid", "scripts/azure/run_hybrid.sh", 30, 50),
]
# (output name, text file, window title)
TERMINAL = [
    ("az_vms", "az_vms.txt", "Azure CLI - virtual machines in fids-rg"),
    ("az_resources", "az_resources.txt", "Azure CLI - resources in fids-rg"),
    ("az_nsg", "az_nsg.txt", "Azure CLI - network security rule (operator IPs redacted)"),
    ("az_budget", "az_budget.txt", "Azure CLI - budget on fids-rg"),
    ("run_log", "run_log.txt", "Flower hybrid run - 10 clients (5 Azure + 5 laptop), 30 rounds"),
    ("pytest", "pytest.txt", "Test suite"),
]


def window(lines: list[list[tuple[str, str, bool]]], title: str, bg: str, gutter: int = 0,
           gutter_text: list[str] | None = None, gutter_fg: str = "#6e7681") -> Image.Image:
    """Draw coloured text runs inside a window frame with a title bar."""
    f, fb = ImageFont.truetype(FONT, SIZE), ImageFont.truetype(FONT_B, SIZE)
    cw = f.getbbox("M")[2]
    lh = int(SIZE * 1.45)
    width = max((sum(len(t) for t, _, _ in ln) for ln in lines), default=40)
    W = PAD * 2 + gutter * cw + max(width, len(title) + 10) * cw
    H = BAR + PAD * 2 + lh * len(lines)
    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAR], fill="#2d333b")
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        d.ellipse([14 + i * 22, 13, 26 + i * 22, 25], fill=c)
    d.text((90, 9), title, font=f, fill="#c9d1d9")
    y = BAR + PAD
    for i, ln in enumerate(lines):
        x = PAD
        if gutter_text:
            d.text((x, y), gutter_text[i].rjust(gutter - 2), font=f, fill=gutter_fg)
            x += gutter * cw
        for text, color, bold in ln:
            d.text((x, y), text, font=fb if bold else f, fill=color)
            x += len(text) * cw
        y += lh
    return img


def render_code(path: str, a: int, b: int) -> Image.Image:
    src = (ROOT / path).read_text(encoding="utf-8").splitlines()[a - 1:b]
    style = get_style_by_name("github-dark")
    lexer = get_lexer_for_filename(path)
    lines: list[list[tuple[str, str, bool]]] = [[]]
    for tok, val in lex("\n".join(src) + "\n", lexer):
        s = style.style_for_token(tok)
        color, bold = "#" + (s["color"] or "c9d1d9"), bool(s["bold"])
        for j, part in enumerate(val.replace("\t", "    ").split("\n")):
            if j:
                lines.append([])
            if part:
                lines[-1].append((part, color, bold))
    lines = lines[:len(src)]
    nums = [str(n) for n in range(a, a + len(src))]
    return window(lines, f"{path}  (lines {a}-{b})", style.background_color or "#0d1117",
                  gutter=len(str(b)) + 3, gutter_text=nums)


def render_terminal(text: str, title: str) -> Image.Image:
    lines = []
    for raw in text.replace("\t", "    ").splitlines():
        if raw.startswith("$ "):
            lines.append([("$ ", "#3fb950", True), (raw[2:], "#e6edf3", True)])
        elif "passed" in raw or "finished" in raw or "Received 10 results and 0 failures" in raw:
            lines.append([(raw, "#3fb950", False)])
        else:
            lines.append([(raw, "#c9d1d9", False)])
    return window(lines, title, "#0d1117")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--terminal-dir", default=str(ROOT / ".tmp/report"))
    ap.add_argument("--out", default=str(ROOT / "reports/screenshots"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, path, a, b in CODE:
        render_code(path, a, b).save(out / f"{name}.png")
        print("wrote", out / f"{name}.png")
    for name, fname, title in TERMINAL:
        p = Path(args.terminal_dir) / fname
        if not p.exists():
            print("skip (missing)", p)
            continue
        render_terminal(p.read_text(encoding="utf-8"), title).save(out / f"{name}.png")
        print("wrote", out / f"{name}.png")


if __name__ == "__main__":
    main()
