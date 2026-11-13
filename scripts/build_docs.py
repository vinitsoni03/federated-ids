"""Build the written deliverables (final report, literature review) as .docx and .pdf.

Format: Times New Roman, 12 pt body, 1.5 line spacing, justified, A4; level-1 headings 16 pt bold uppercase
centred; level-2 headings 14 pt bold; level-3 12 pt bold; level-4 12 pt bold italic;
captions 11 pt; table text 10 pt.

* Word: pandoc with a reference.docx whose styles are rewritten to that format.
* PDF:  pandoc -> standalone HTML with the same rules in CSS -> headless Chrome --print-to-pdf.
  (Word COM automation hangs on this laptop, so it is not used.)

Markdown conventions understood by the filter (see FILTER below):
* ``::: pagebreak`` / ``:::``   page break
* ``::: toc`` / ``:::``         table of contents (Word: TOC field, updated when the file is opened;
                                PDF: list of chapter and section headings)
* ``::: {custom-style="Cover"}`` centred cover-page text (style defined here for Word, CSS for PDF)

Usage:
    python scripts/build_docs.py reports/final_report.md reports/literature_review.md
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
PANDOC = shutil.which("pandoc") or str(Path.home() / "AppData/Local/Pandoc/pandoc.exe")

# Lists may follow a paragraph line directly (the final report is written that way).
MD_FORMAT = "markdown+lists_without_preceding_blankline"

# Lua filter shared by both outputs.
FILTER = r"""
local function toc_blocks(doc)
  local items = {}
  for _, b in ipairs(doc.blocks) do
    if b.t == "Header" and b.level <= 2 and not b.classes:includes("unlisted") then
      local link = pandoc.Link(b.content, "#" .. b.identifier)
      local para = pandoc.Plain({link})
      if b.level == 1 then
        table.insert(items, pandoc.Div({para}, pandoc.Attr("", {"toc1"})))
      else
        table.insert(items, pandoc.Div({para}, pandoc.Attr("", {"toc2"})))
      end
    end
  end
  return items
end

function Pandoc(doc)
  local out = {}
  for _, b in ipairs(doc.blocks) do
    if b.t == "Div" and b.classes:includes("pagebreak") then
      if FORMAT == "docx" then
        table.insert(out, pandoc.RawBlock("openxml",
          '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'))
      else
        table.insert(out, pandoc.RawBlock("html", '<div class="pagebreak"></div>'))
      end
    elseif b.t == "Div" and b.classes:includes("toc") then
      if FORMAT == "docx" then
        table.insert(out, pandoc.RawBlock("openxml",
          '<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>' ..
          '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>' ..
          '<w:r><w:fldChar w:fldCharType="separate"/></w:r>' ..
          '<w:r><w:t>Right-click here and choose Update Field to build the table of contents.</w:t></w:r>' ..
          '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'))
      else
        table.insert(out, pandoc.Div(toc_blocks(doc), pandoc.Attr("", {"toclist"})))
      end
    else
      table.insert(out, b)
    end
  end
  doc.blocks = out
  return doc
end
"""

# ---------------------------------------------------------------- Word styles
FONT = '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="Times New Roman" w:cs="Times New Roman"/>'


def _style(sid: str, name: str, ppr: str = "", rpr: str = "", based: str = "Normal",
           kind: str = "paragraph", extra: str = "") -> str:
    based_xml = f'<w:basedOn w:val="{based}"/>' if based else ""
    return (f'<w:style w:type="{kind}" w:customStyle="1" w:styleId="{sid}"><w:name w:val="{name}"/>'
            f'{based_xml}{extra}<w:qFormat/><w:pPr>{ppr}</w:pPr><w:rPr>{FONT}{rpr}</w:rPr></w:style>')


BODY_PPR = '<w:spacing w:before="0" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="both"/>'
STYLES = {
    "Normal": _style("Normal", "Normal", BODY_PPR, '<w:sz w:val="24"/><w:szCs w:val="24"/>', based=""),
    "BodyText": _style("BodyText", "Body Text", BODY_PPR, '<w:sz w:val="24"/><w:szCs w:val="24"/>'),
    "FirstParagraph": _style("FirstParagraph", "First Paragraph", BODY_PPR, "", based="BodyText"),
    # Compact is what pandoc uses inside tables and tight lists: 10 pt, single spacing.
    "Compact": _style("Compact", "Compact",
                      '<w:spacing w:before="20" w:after="20" w:line="240" w:lineRule="auto"/><w:jc w:val="left"/>',
                      '<w:sz w:val="20"/><w:szCs w:val="20"/>', based="BodyText"),
    "Title": _style("Title", "Title",
                    '<w:keepNext/><w:spacing w:before="240" w:after="240"/><w:jc w:val="center"/>',
                    '<w:b/><w:sz w:val="36"/><w:szCs w:val="36"/>', based="Normal"),
    "Subtitle": _style("Subtitle", "Subtitle", '<w:spacing w:after="240"/><w:jc w:val="center"/>',
                       '<w:sz w:val="28"/><w:szCs w:val="28"/>', based="Title"),
    "Author": _style("Author", "Author", '<w:jc w:val="center"/>', '<w:sz w:val="24"/>', based="Normal"),
    "Date": _style("Date", "Date", '<w:jc w:val="center"/>', '<w:sz w:val="24"/>', based="Normal"),
    "Heading1": _style("Heading1", "heading 1",
                       '<w:keepNext/><w:pageBreakBefore/><w:spacing w:before="0" w:after="360"/>'
                       '<w:jc w:val="center"/><w:outlineLvl w:val="0"/>',
                       '<w:b/><w:caps/><w:sz w:val="32"/><w:szCs w:val="32"/>'),
    "Heading2": _style("Heading2", "heading 2",
                       '<w:keepNext/><w:spacing w:before="240" w:after="120"/><w:jc w:val="left"/>'
                       '<w:outlineLvl w:val="1"/>',
                       '<w:b/><w:sz w:val="28"/><w:szCs w:val="28"/>'),
    "Heading3": _style("Heading3", "heading 3",
                       '<w:keepNext/><w:spacing w:before="200" w:after="80"/><w:jc w:val="left"/>'
                       '<w:outlineLvl w:val="2"/>',
                       '<w:b/><w:sz w:val="24"/><w:szCs w:val="24"/>'),
    "Heading4": _style("Heading4", "heading 4",
                       '<w:keepNext/><w:spacing w:before="160" w:after="60"/><w:jc w:val="left"/>'
                       '<w:outlineLvl w:val="3"/>',
                       '<w:b/><w:i/><w:sz w:val="24"/><w:szCs w:val="24"/>'),
    "TableCaption": _style("TableCaption", "Table Caption",
                           '<w:keepNext/><w:spacing w:before="120" w:after="60"/><w:jc w:val="center"/>',
                           '<w:b/><w:sz w:val="22"/><w:szCs w:val="22"/>'),
    "ImageCaption": _style("ImageCaption", "Image Caption",
                           '<w:spacing w:before="60" w:after="200"/><w:jc w:val="center"/>',
                           '<w:i/><w:sz w:val="22"/><w:szCs w:val="22"/>'),
    "CaptionedFigure": _style("CaptionedFigure", "Captioned Figure",
                              '<w:keepNext/><w:jc w:val="center"/>', ""),
    "Figure": _style("Figure", "Figure", '<w:keepNext/><w:jc w:val="center"/>', ""),
    "Cover": _style("Cover", "Cover",
                    '<w:spacing w:before="120" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="center"/>',
                    '<w:sz w:val="28"/><w:szCs w:val="28"/>'),
    "TOCHeading": _style("TOCHeading", "TOC Heading",
                         '<w:keepNext/><w:spacing w:after="240"/><w:jc w:val="center"/>',
                         '<w:b/><w:caps/><w:sz w:val="32"/><w:szCs w:val="32"/>'),
}

A4_SECT = ('<w:sectPr><w:footerReference w:type="default" r:id="rIdFooterPg"/>'
           '<w:pgSz w:w="11906" w:h="16838"/>'
           '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" '
           'w:footer="708" w:gutter="0"/></w:sectPr>')
FOOTER = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
          '<w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
          '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
          '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
          '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r>'
          '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')


def make_reference_docx(out: Path) -> None:
    """Pandoc's default reference.docx with the report styles, A4 page and page numbers."""
    raw = subprocess.run([PANDOC, "--print-default-data-file", "reference.docx"],
                         check=True, capture_output=True).stdout
    src = out.with_suffix(".default.docx")
    src.write_bytes(raw)
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "word/styles.xml":
                xml = data.decode("utf8")
                # Body defaults: Times New Roman 12 pt.
                xml = re.sub(r"<w:rPrDefault>.*?</w:rPrDefault>",
                             f'<w:rPrDefault><w:rPr>{FONT}<w:sz w:val="24"/><w:szCs w:val="24"/>'
                             '<w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>', xml, flags=re.S)
                for sid, new in STYLES.items():
                    pattern = r'<w:style [^>]*w:styleId="%s"[^>]*>.*?</w:style>' % sid
                    if re.search(pattern, xml, flags=re.S):
                        xml = re.sub(pattern, lambda _m, n=new: n, xml, count=1, flags=re.S)
                    else:
                        xml = xml.replace("</w:styles>", new + "</w:styles>")
                # Black heading/title text (pandoc's defaults are blue).
                xml = re.sub(r'<w:color w:val="[0-9A-Fa-f]{6}"[^/]*/>', "", xml)
                data = xml.encode("utf8")
            elif item.filename == "word/document.xml":
                xml = data.decode("utf8")
                xml = re.sub(r"<w:sectPr.*?</w:sectPr>", A4_SECT, xml, flags=re.S)
                data = xml.encode("utf8")
            elif item.filename == "word/_rels/document.xml.rels":
                xml = data.decode("utf8").replace(
                    "</Relationships>",
                    '<Relationship Id="rIdFooterPg" '
                    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" '
                    'Target="footer1.xml"/></Relationships>')
                data = xml.encode("utf8")
            elif item.filename == "[Content_Types].xml":
                xml = data.decode("utf8").replace(
                    "</Types>",
                    '<Override PartName="/word/footer1.xml" ContentType="application/'
                    'vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>')
                data = xml.encode("utf8")
            zout.writestr(item, data)
        zout.writestr("word/footer1.xml", FOOTER)
    src.unlink()


# ---------------------------------------------------------------- PDF (HTML) styles
CSS = """
@page { size: A4; margin: 25mm 25mm 22mm 25mm;
        @bottom-center { content: counter(page); font-family: 'Times New Roman', serif; font-size: 10pt; } }
@page :first { @bottom-center { content: none; } }
html { font-family: 'Times New Roman', Times, serif; font-size: 12pt; color: #000; }
body { margin: 0; max-width: none; line-height: 1.5; text-align: justify; hyphens: auto; }
header#title-block-header { text-align: center; margin: 30mm 0 10mm; }
header .title { font-size: 20pt; font-weight: bold; }
header .subtitle { font-size: 14pt; }
header .author, header .date { font-size: 12pt; }
h1 { font-size: 16pt; font-weight: bold; text-transform: uppercase; text-align: center;
     break-before: page; margin: 0 0 14pt; }
h2 { font-size: 14pt; font-weight: bold; margin: 16pt 0 6pt; break-after: avoid; }
h3 { font-size: 12pt; font-weight: bold; margin: 12pt 0 4pt; break-after: avoid; }
h4 { font-size: 12pt; font-weight: bold; font-style: italic; margin: 10pt 0 4pt; break-after: avoid; }
p { margin: 0 0 6pt; orphans: 3; widows: 3; }
ul, ol { margin: 0 0 6pt; padding-left: 22pt; }
li { margin: 0 0 2pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 10pt; line-height: 1.25;
        text-align: left; break-inside: auto; }
tr { break-inside: avoid; }
th, td { border: 0.6pt solid #555; padding: 2pt 4pt; vertical-align: top; }
thead th { background: #e8e8e8; }
caption { caption-side: top; font-size: 11pt; font-weight: bold; padding-bottom: 3pt; text-align: center; }
figure { margin: 8pt 0 12pt; text-align: center; break-inside: avoid; }
figure img { max-width: 100%; max-height: 200mm; }
figcaption { font-size: 11pt; font-style: italic; margin-top: 3pt; text-align: center; }
code { font-family: Consolas, monospace; font-size: 10pt; }
pre { font-size: 9pt; line-height: 1.2; white-space: pre-wrap; border: 0.5pt solid #999; padding: 4pt; }
a { color: #000; text-decoration: none; }
.pagebreak { break-after: page; }
div[data-custom-style="Cover"] { text-align: center; font-size: 14pt; }
div[data-custom-style="Cover"] p { text-align: center; margin: 0 0 8pt; }
.toclist { margin-top: 6pt; }
.toc1 { font-weight: bold; margin-top: 6pt; }
.toc2 { margin-left: 18pt; }
.toc1 p, .toc2 p { margin: 0; text-align: left; }
"""


def build(md: Path, ref_docx: Path, tmp: Path) -> None:
    filt = tmp / "deliverables.lua"
    filt.write_text(FILTER, encoding="utf8")
    res = md.parent
    docx = md.with_suffix(".docx")
    subprocess.run([PANDOC, str(md), "-f", MD_FORMAT, "-o", str(docx), "--reference-doc", str(ref_docx),
                    "--lua-filter", str(filt), "--resource-path", str(res)], check=True)
    css = tmp / "deliverables.css"
    css.write_text(CSS, encoding="utf8")
    html = tmp / (md.stem + ".html")
    subprocess.run([PANDOC, str(md), "-f", MD_FORMAT, "-o", str(html), "--standalone", "--embed-resources",
                    "--lua-filter", str(filt), "--resource-path", str(res), "--css", str(css),
                    "--metadata", "lang=en-GB"], check=True)
    pdf = md.with_suffix(".pdf")
    subprocess.run([str(CHROME), "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf}", html.as_uri()], check=True, capture_output=True,
                   timeout=180)
    print(f"built {docx.name}, {pdf.name} ({pdf.stat().st_size // 1024} KB)")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        ref = tmp / "reference.docx"
        make_reference_docx(ref)
        for name in argv:
            build(Path(name).resolve(), ref, tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
