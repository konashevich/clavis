#!/usr/bin/env python3
"""Write canvas HTML files from parsed Gemini API payloads."""
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


def load_inner(path: Path):
    text = path.read_text(encoding="utf-8")
    t = text.lstrip()
    if t.startswith(")]}'"):
        t = t[4:].lstrip()
    m = re.match(r"(\d+)\n", t)
    if m:
        t = t[m.end() :]
    arr, _ = json.JSONDecoder().raw_decode(t)
    return json.loads(arr[0][2])


def md_to_simple_html(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    code_lang = ""
    code_buf: list[str] = []
    list_type = None

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
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
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
        para = [line]
        i += 1
        while (
            i < len(lines)
            and lines[i].strip()
            and not lines[i].startswith("#")
            and not lines[i].startswith("```")
            and not re.match(r"^[-*]\s+", lines[i])
            and not re.match(r"^\d+\.\s+", lines[i])
        ):
            para.append(lines[i])
            i += 1
        out.append("<p>" + "<br>\n".join(inline_fmt(p) for p in para) + "</p>")

    if in_code:
        flush_code()
    close_list()
    return "\n".join(out)


def wrap_html(title: str, body_html: str, note: str, raw_block: str, partial: bool) -> str:
    banner = ""
    if partial:
        banner = (
            '<div class="partial"><strong>Partial capture.</strong> '
            "Gemini conversation history only returned a truncated/delta version of this Canvas "
            "(ellipsis sections omitted). Replace by Export from the Gemini UI when possible.</div>"
        )
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
.meta {{ color: #666; font-size: .9rem; margin-bottom: 1.5rem; }}
a {{ color: #1a73e8; }}
hr {{ border: none; border-top: 1px solid #ddd; margin: 2rem 0; }}
.source-md {{ white-space: pre-wrap; background: #fafafa; border: 1px solid #e5e5e5; padding: 1rem; border-radius: 6px; font-size: .85rem; }}
.partial {{ background: #fff3cd; border: 1px solid #ffc107; padding: .85rem 1rem; border-radius: 8px; margin-bottom: 1.25rem; }}
</style>
</head>
<body>
<p><a href="../index.html">← Back to transcript</a></p>
<h1>{html.escape(title)}</h1>
<p class="meta">{html.escape(note)}</p>
{banner}
<article class="canvas-body">
{body_html}
</article>
<hr>
<details open>
<summary>Raw source (verbatim from Gemini API)</summary>
<pre class="source-md">{html.escape(raw_block)}</pre>
</details>
</body>
</html>
"""


def collect_md_docs(data) -> dict[str, dict]:
    found = []

    def walk(obj):
        if isinstance(obj, list):
            if (
                len(obj) >= 5
                and isinstance(obj[0], str)
                and obj[0].endswith(".md")
                and isinstance(obj[2], str)
                and isinstance(obj[4], str)
            ):
                found.append(
                    {"fname": obj[0], "uuid": obj[1], "title": obj[2], "body": obj[4]}
                )
            for v in obj:
                walk(v)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)

    walk(data)
    by: dict[str, dict] = {}
    for f in found:
        t = f["title"]
        md = f["body"]
        complete = not (md.lstrip().startswith("...") or md.lstrip().startswith("…") or "\n...\n" in md[:120] or "\n…\n" in md[:120])
        # Prefer longer; prefer complete
        score = (1 if complete else 0, len(md))
        cur = by.get(t)
        if not cur:
            by[t] = {**f, "complete": complete}
        else:
            cur_complete = cur.get("complete", False)
            cur_score = (1 if cur_complete else 0, len(cur["body"]))
            if score > cur_score:
                by[t] = {**f, "complete": complete}
    return by


def collect_medical(data) -> dict | None:
    best = None

    def walk(obj):
        nonlocal best
        if isinstance(obj, list):
            if (
                len(obj) >= 5
                and isinstance(obj[0], str)
                and "medical_credential" in obj[0]
                and isinstance(obj[2], str)
                and "Medical Credential" in obj[2]
                and isinstance(obj[4], str)
                and obj[4].lstrip().startswith("{")
            ):
                if best is None or len(obj[4]) > len(best["body"]):
                    best = {
                        "fname": obj[0],
                        "uuid": obj[1],
                        "title": obj[2],
                        "body": obj[4],
                        "complete": True,
                    }
            for v in obj:
                walk(v)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)

    walk(data)
    return best


def main() -> None:
    data = load_inner(RAW)
    by = collect_md_docs(data)
    medical = collect_medical(data)
    if medical:
        by[medical["title"]] = medical

    status = {}
    for title, filename in TARGETS:
        info = by.get(title)
        path = CANVAS_DIR / filename
        if not info:
            # keep placeholder content but update message? leave and mark missing
            status[title] = {"status": "missing", "file": filename}
            print("MISSING", title)
            continue

        body = info["body"]
        complete = info.get("complete", False)
        # Draft notes CLAVIS starts with "... (предыдущие записи)" - mark partial
        if body.lstrip().startswith("#") and ("... (предыдущие" in body[:80] or body.lstrip().startswith("#") and "\n...\n" in body[:150]):
            if "предыдущие" in body[:100] or re.search(r"\n\.\.\.\n", body[:200]):
                complete = False
                info["complete"] = False

        note = (
            f"Extracted from Gemini batchexecute rpcid=hNvQHb for chat 32920e9e8337e92a; "
            f"source={info.get('fname')}; uuid={info.get('uuid')}."
        )

        if title == "CLAVIS: Medical Credential Example" or (
            isinstance(body, str) and body.lstrip().startswith("{")
        ):
            # pretty JSON if possible
            try:
                pretty = json.dumps(json.loads(body), ensure_ascii=False, indent=2)
            except Exception:
                pretty = body
            body_html = f"<pre><code class=\"language-json\">{html.escape(pretty)}</code></pre>"
            raw_block = pretty
            complete = True
        else:
            body_html = md_to_simple_html(body)
            raw_block = body

        # Heuristic: treat short ellipsis docs as partial
        if len(body) < 1500 and ("..." in body[:100] or "…" in body[:100]):
            complete = False

        doc = wrap_html(title, body_html, note, raw_block, partial=not complete)
        path.write_text(doc, encoding="utf-8")
        status[title] = {
            "status": "full" if complete else "partial",
            "file": filename,
            "chars": len(body),
            "bytes": path.stat().st_size,
        }
        print(status[title]["status"].upper(), filename, "chars=", len(body))

    Path("/mnt/merged_ssd/clavis/gemini-export/_canvas_status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
