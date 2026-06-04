# -*- coding: utf-8 -*-
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

PPT = Path(r"d:/文档/xwechat_files/wxid_khk0tui54ai122_f010/msg/file/2026-05/ZKP-PQC-PLS_IoV安全认证汇报.pptx")
OUT = Path(__file__).resolve().parents[1] / "docs" / "ppt_extracted.txt"

def main() -> None:
    z = zipfile.ZipFile(PPT)
    slides = sorted(
        [n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml", n)],
        key=lambda x: int(re.search(r"slide(\d+)", x).group(1)),
    )
    lines = []
    for i, name in enumerate(slides, 1):
        root = ET.fromstring(z.read(name))
        texts = []
        for t in root.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}t"):
            if t.text:
                texts.append(t.text)
            if t.tail:
                texts.append(t.tail)
        body = "".join(texts).strip()
        lines.append(f"--- Slide {i} ---\n{body or '[empty]'}\n")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(slides)} slides to {OUT}")

if __name__ == "__main__":
    main()
