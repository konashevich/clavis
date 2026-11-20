#!/usr/bin/env python3
"""Parse Gemini batchexecute payload for Canvas markdown bodies and write HTML files."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

RAW = Path("/mnt/merged_ssd/clavis/gemini-export/_api_hNvQHb_raw.txt")
CANVAS_DIR = Path("/mnt/merged_ssd/clavis/gemini-export/canvas")

TARGETS = [
    ("Secure Android Data Vault Specification", "secure-android-data-vault-specification.html"),
    ("Secure Vault Inter-App Protocol (SVIAP)", "secure-vault-inter-app-protocol-sviap.html"),
    ("Draft Notes: Secure Vault", "draft-notes-secure-vault.html"),
    ("Market Review: Secure Vault Project", "market-review-secure-vault-project.html"),
    ("CLAVIS Protocol Specification", "clavis-protocol-specification.html"),
    ("CLAVIS: Proof of Concept Roadmap (v1.1)", "clavis-proof-of-concept-roadmap-v1-1.html"),
    ("Draft Notes: CLAVIS Project", "draft-notes-clavis-project.html"),
    ("CLAVIS: Minimal PoC Scope (Medical)", "clavis-minimal-poc-scope-medical.html"),
    ("CLAVIS: Medical Credential Example", "clavis-medical-credential-example.html"),
]


def unescape_md(s: str) -> str:
    """Unescape Gemini's multiply-escaped markdown string."""
    t = s
    # Prefer JSON decode if it looks like a quoted string
    for _ in range(5):
        prev = t
        if "\\n" in t or '\\"' in t or "\\\\" in t:
            try:
                t = json.loads('"' + t.replace('"', '\\"').replace("\\\\", "\\") + '"')
            except Exception:
                t = (
                    t.replace("\\\\n", "\n")
                    .replace("\\n", "\n")
                    .replace("\\\\t", "\t")
                    .replace("\\t", "\t")
                    .replace('\\"', '"')
                    .replace("\\\\`", "`")
                    .replace("\\\\\\\\", "\\")
                )
                # collapse remaining \\n
                while "\\\\n" in t:
                    t = t.replace("\\\\n", "\n")
                while "\\n" in t:
                    t = t.replace("\\n", "\n")
                t = t.replace('\\"', '"')
        if t == prev:
            break
    # Final cleanup of literal backslash-n if still present as two chars after partial decode
    t = t.replace("\\n", "\n").replace('\\"', '"')
    return t


def md_to_simple_html(md: str) -> str:
    """Minimal markdown→HTML for headings, lists, code, paragraphs. Verbatim-ish."""
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    code_lang = ""
    code_buf: list[str] = []
    list_type = None  # 'ul' | 'ol'

    def close_list():
        nonlocal list_type
        if list_type:
            out.append(f"</{list_type}>")
            list_type = None

    def flush_code():
        nonlocal in_code, code_buf, code_lang
        body = html.escape("\n".join(code_buf))
        lang_attr = f' class="language-{html.escape(code_lang)}"' if code_lang else ""
        out.append(f"<pre><code{lang_attr}>{body}</code></pre>")
        in_code = False
        code_buf = []
        code_lang = ""

    def inline_fmt(s: str) -> str:
        s = html.escape(s)
        # code
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        # bold/italic (order matters)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", s)
        return s

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                flush_code()
            else:
                close_list()
                in_code = True
                code_lang = line[3:].strip()
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            close_list()
            level = len(heading.group(1))
            out.append(f"<h{level}>{inline_fmt(heading.group(2))}</h{level}>")
            i += 1
            continue

        ul = re.match(r"^[-*]\s+(.*)$", line)
        ol = re.match(r"^(\d+)\.\s+(.*)$", line)
        if ul:
            if list_type != "ul":
                close_list()
                out.append("<ul>")
                list_type = "ul"
            out.append(f"<li>{inline_fmt(ul.group(1))}</li>")
            i += 1
            continue
        if ol:
            if list_type != "ol":
                close_list()
                out.append("<ol>")
                list_type = "ol"
            out.append(f"<li>{inline_fmt(ol.group(2))}</li>")
            i += 1
            continue

        close_list()
        if line.strip() == "":
            i += 1
            continue
        # accumulate paragraph
        para = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith("#") and not lines[i].startswith("```") and not re.match(r"^[-*]\s+", lines[i]) and not re.match(r"^\d+\.\s+", lines[i]):
            para.append(lines[i])
            i += 1
        out.append("<p>" + "<br>\n".join(inline_fmt(p) for p in para) + "</p>")

    if in_code:
        flush_code()
    close_list()
    return "\n".join(out)


def wrap_html(title: str, md: str, source_note: str) -> str:
    body = md_to_simple_html(md)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: "IBM Plex Sans", "Segoe UI", sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.55; color: #1a1a1a; }}
h1,h2,h3,h4 {{ line-height: 1.25; }}
pre {{ background: #f5f5f5; padding: .85rem 1rem; overflow-x: auto; border-radius: 6px; }}
code {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: .92em; }}
pre code {{ font-size: .88em; }}
.meta {{ color: #666; font-size: .9rem; margin-bottom: 1.5rem; }}
a {{ color: #1a73e8; }}
hr {{ border: none; border-top: 1px solid #ddd; margin: 2rem 0; }}
.source-md {{ white-space: pre-wrap; background: #fafafa; border: 1px solid #e5e5e5; padding: 1rem; border-radius: 6px; font-size: .85rem; }}
</style>
</head>
<body>
<p><a href="../index.html">← Back to transcript</a></p>
<h1>{html.escape(title)}</h1>
<p class="meta">{html.escape(source_note)}</p>
<article class="canvas-body">
{body}
</article>
<hr>
<details>
<summary>Raw markdown (verbatim)</summary>
<pre class="source-md">{html.escape(md)}</pre>
</details>
</body>
</html>
"""


def main() -> None:
    text = RAW.read_text(encoding="utf-8")
    # Pattern inside batchexecute escaped JSON:
    # \"filename.md\",\"uuid\",\"Title\",null,\"# markdown...\"
    pattern = re.compile(
        r'\\"((?:c_)?[^"\\]*?\.md)\\",\\"([0-9a-f-]{36})\\",\\"([^"\\]+)\\",null,\\"((?:\\.|[^"\\])*)\\"',
    )
    matches = list(pattern.finditer(text))
    print("md entries found:", len(matches))

    by_title: dict[str, dict] = {}
    for m in matches:
        fname, uuid, title, body = m.group(1), m.group(2), m.group(3), m.group(4)
        if title not in by_title or len(body) > len(by_title[title]["body_raw"]):
            by_title[title] = {
                "fname": fname,
                "uuid": uuid,
                "body_raw": body,
                "title": title,
            }

    print("unique titles:", len(by_title))
    for t, info in sorted(by_title.items(), key=lambda x: -len(x[1]["body_raw"])):
        print(f"  [{len(info['body_raw']):6d}] {t}")

    captured = []
    missing = []
    for title, filename in TARGETS:
        info = by_title.get(title)
        if not info:
            # fuzzy: title contained
            for k, v in by_title.items():
                if title in k or k in title:
                    info = v
                    break
        if not info:
            missing.append(title)
            print("MISSING:", title)
            continue
        md = unescape_md(info["body_raw"])
        # Sanity: must look like markdown doc
        if len(md.strip()) < 40:
            missing.append(title)
            print("TOO SHORT:", title, len(md))
            continue
        note = (
            f"Extracted from Gemini batchexecute (rpcid hNvQHb) for chat "
            f"32920e9e8337e92a; source file {info['fname']}; uuid {info['uuid']}."
        )
        html_doc = wrap_html(title, md, note)
        path = CANVAS_DIR / filename
        path.write_text(html_doc, encoding="utf-8")
        captured.append((title, filename, len(md), path.stat().st_size))
        print("WROTE", filename, "md_chars=", len(md), "html_bytes=", path.stat().st_size)
        # preview
        print("  preview:", repr(md[:160].replace("\n", " / ")))

    # Also dump all discovered titles for debugging
    dump = {t: {"fname": i["fname"], "uuid": i["uuid"], "md_len": len(unescape_md(i["body_raw"]))} for t, i in by_title.items()}
    Path("/mnt/merged_ssd/clavis/gemini-export/_canvas_parse_index.json").write_text(
        json.dumps({"captured": captured, "missing": missing, "discovered": dump}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("captured", len(captured), "missing", len(missing))


if __name__ == "__main__":
    main()
