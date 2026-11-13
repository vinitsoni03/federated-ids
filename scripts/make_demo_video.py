"""Turn the recorded dashboard walkthrough (GIF from the browser recorder) into a captioned MP4 demo video.

Steps: pick key frames from the GIF, draw a title bar and a caption under each one (Pillow), then let
PowerPoint export the timed slides as MP4 (COM CreateVideo; PowerPoint COM works on this laptop, Word COM
does not). No ffmpeg is needed.

Usage:
    python scripts/make_demo_video.py <recording.gif> <out.mp4>
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
NAVY, WHITE, GREY = (27, 42, 74), (255, 255, 255), (225, 230, 238)
FONT = "C:/Windows/Fonts/segoeui.ttf"
BOLD = "C:/Windows/Fonts/segoeuib.ttf"

# (frame index in the GIF, seconds on screen, section, caption)
SEGMENTS = [
    (0, 6, "1 · Detect", "A real held-out Benign test window. The detector's attack score is below the threshold "
                         "calibrated for 1 % benign false positives, so no alarm is raised."),
    (1, 5, "1 · Detect", "A DDoS window from the test set: flagged as ATTACK and classified as DDoS."),
    (3, 5, "1 · Detect", "A Spoofing window: flagged as ATTACK and classified as Spoofing by the frozen v2 model."),
    (8, 8, "1 · Detect", "Scan of all 320 demo windows with the adversarially hardened model at 1 % FPR: 1 of 40 "
                         "benign windows raises an alarm and 198 of 280 attack windows are detected. Low-rate "
                         "families (Web, Recon) remain the hard ones - this Spoofing window is now missed."),
    (10, 5, "2 · Evasion attack", "A black-box attacker sees only the verdict. It may only pad its own packets "
                                  "(up to the MTU), slow down (r ≥ 0.1) and set a benign-looking TTL."),
    (16, 6, "2 · Evasion attack", "Against this Spoofing window every one of the 112 allowed disguises fails: "
                                  "the window stays detected."),
    (17, 8, "2 · Evasion attack", "All 280 attack windows: the attacker turns 32.5 % of detected windows Benign "
                                  "on the frozen model, but only 15.7 % on the model after two rounds of "
                                  "adversarial training (red = frozen, green = hardened)."),
    (24, 9, "2 · Evasion attack", "A Web window is evaded after 4 queries just by changing the TTL: the frozen "
                                  "model now says Benign. The same disguised window sent to the hardened model is "
                                  "still detected as Web. 0 constraint violations."),
    (26, 7, "3 · Federated training", "Real Flower deployment: server on an Azure VM, 5 clients on a second Azure "
                                      "VM and 5 on this laptop, over TLS. Only model weights travel (30.1 MB in "
                                      "30 rounds); raw traffic never leaves a client."),
    (32, 4, "3 · Federated training", "Replay of the recorded run, round by round."),
    (34, 8, "3 · Federated training", "After 30 rounds: test macro-F1 0.669 while the benign false-positive rate "
                                      "falls - identical to the simulator with the same seed and partition."),
    (36, 9, "4 · Results", "Headline numbers, read live from reports/tables: detection at a 1 % false-positive "
                           "rate, evasion before and after adversarial training, and GridStratLLM detection "
                           "without the ARP signature."),
    (38, 7, "4 · Results", "LLM-planned smart-grid attacks are still found by S7 timing/volume features "
                           "(AUC 0.90-1.00, 98-100 % of sessions) after removing every ARP feature."),
]

TITLE = ("Adversarially Robust Federated Intrusion Detection",
         "Live demo of the project dashboard",
         "Vinit Soni (E23CSEU0437) · Bennett University")
CLOSING = [
    "Leakage-aware CICIoT2023: 8-class macro-F1 0.687 (MLP), 83-86 % of attacks detected at 1 % FPR",
    "Federated training (FedAvg) within 0.6-2.5 points of centralised; Flower on Azure = simulator",
    "2 of 10 poisoning clients collapse FedAvg; median / trimmed mean neutralise them (IID)",
    "Evasion at 1 % FPR: 24-49 % → 8-17 % after two rounds of adversarial training",
    "LLM-planned attacks (GridStratLLM): leave-one-LLM-out AUC 0.90-1.00, even without ARP features",
]


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


def wrap(draw: ImageDraw.ImageDraw, text: str, f: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines, line = [], ""
    for word in text.split():
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=f) <= width:
            line = trial
        else:
            lines.append(line)
            line = word
    return lines + [line]


def caption_slide(frame: Image.Image, section: str, caption: str) -> Image.Image:
    canvas = Image.new("RGB", (W, H), GREY)
    d = ImageDraw.Draw(canvas)
    d.rectangle([0, 0, W, 70], fill=NAVY)
    d.text((40, 14), section, font=font(BOLD, 34), fill=WHITE)
    d.text((W - 40, 22), "Federated IDS - live demo", font=font(FONT, 24), fill=(190, 200, 220), anchor="ra")
    cap_h = 230
    area_w, area_h = W - 80, H - 70 - cap_h - 30
    f = frame.copy()
    f.thumbnail((area_w, area_h), Image.LANCZOS)
    canvas.paste(f, ((W - f.width) // 2, 70 + 15 + (area_h - f.height) // 2))
    d.rectangle([0, H - cap_h, W, H], fill=WHITE)
    d.rectangle([0, H - cap_h, 12, H], fill=NAVY)
    cf = font(FONT, 38)
    y = H - cap_h + 28
    for line in wrap(d, caption, cf, W - 120)[:4]:
        d.text((60, y), line, font=cf, fill=(20, 20, 20))
        y += 48
    return canvas


def card(lines: list[str], heading: str, sub: str | None = None) -> Image.Image:
    canvas = Image.new("RGB", (W, H), NAVY)
    d = ImageDraw.Draw(canvas)
    d.text((W // 2, 300 if sub else 180), heading, font=font(BOLD, 64), fill=WHITE, anchor="mm")
    if sub:
        d.text((W // 2, 400), sub, font=font(FONT, 40), fill=(200, 210, 230), anchor="mm")
        y = 520
        for line in lines:
            d.text((W // 2, y), line, font=font(FONT, 34), fill=(200, 210, 230), anchor="mm")
            y += 56
    else:
        y = 300
        for line in lines:
            d.text((140, y), "•  " + line, font=font(FONT, 38), fill=WHITE)
            y += 100
    return canvas


def frames(gif: Path) -> list[Image.Image]:
    im, out = Image.open(gif), []
    try:
        while True:
            out.append(im.convert("RGB"))
            im.seek(im.tell() + 1)
    except EOFError:
        return out


PS = r"""
$ErrorActionPreference = 'Stop'
$pp = New-Object -ComObject PowerPoint.Application
$pres = $pp.Presentations.Add(0)
$pres.PageSetup.SlideWidth = 960
$pres.PageSetup.SlideHeight = 540
$items = Get-Content -LiteralPath '__LIST__'
$i = 1
foreach ($line in $items) {
  $parts = $line.Split('|')
  $s = $pres.Slides.Add($i, 12)
  [void]$s.Shapes.AddPicture($parts[0], 0, -1, 0, 0, 960, 540)
  $s.SlideShowTransition.AdvanceOnTime = -1
  $s.SlideShowTransition.AdvanceTime = [double]$parts[1]
  $s.SlideShowTransition.EntryEffect = 1793
  $i++
}
$pres.CreateVideo('__OUT__', $true, 5, 1080, 25, 90)
$t = 0
while (($pres.CreateVideoStatus -eq 1 -or $pres.CreateVideoStatus -eq 2) -and $t -lt 900) { Start-Sleep -Seconds 3; $t += 3 }
$status = $pres.CreateVideoStatus
$pres.Close()
$pp.Quit()
Write-Output "status=$status seconds=$t"
"""


def main(gif: str, out: str) -> int:
    fr = frames(Path(gif))
    tmp = Path(tempfile.mkdtemp(prefix="demo_video_"))
    slides = [(card(TITLE[2:], TITLE[0], TITLE[1]), 5)]
    slides += [(caption_slide(fr[k], sec, cap), secs) for k, secs, sec, cap in SEGMENTS]
    slides += [(card(CLOSING, "What the demo shows"), 10)]
    rows = []
    for i, (img, secs) in enumerate(slides):
        p = tmp / f"s{i:02d}.png"
        img.save(p)
        rows.append(f"{p}|{secs}")
    lst = tmp / "slides.txt"
    lst.write_text("\n".join(rows), encoding="ascii")
    ps1 = tmp / "export.ps1"
    ps1.write_text(PS.replace("__LIST__", str(lst)).replace("__OUT__", str(Path(out).resolve())), encoding="ascii")
    total = sum(s for _, s in slides)
    print(f"{len(slides)} slides, {total} s; exporting with PowerPoint ...")
    res = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)],
                         capture_output=True, text=True, timeout=1200)
    print(res.stdout.strip(), res.stderr.strip())
    return 0 if "status=3" in res.stdout else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
