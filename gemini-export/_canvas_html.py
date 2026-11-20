import html, re
from pathlib import Path

def wrap(title, md, note, partial=False):
    banner=""
    if partial:
        banner="<div class=\"partial\"><strong>Partial capture.</strong> Available Canvas versions still omit earlier sections via ellipsis.</div>"
    paras=[]
    for block in md.split("\n\n"):
        block=block.strip()
        if not block: continue
        lines=block.split("\n")
        first=lines[0].strip()
        if first.startswith("Entry #"):
            paras.append(f"<h3>{html.escape(first)}</h3>")
            rest="\n".join(lines[1:]).strip()
            if rest: paras.append("<p>"+"<br>\n".join(html.escape(l) for l in rest.split("\n"))+"</p>")
        elif re.match(r"^\d+\.\d+\s+", first) and len(first)<100:
            paras.append(f"<h3>{html.escape(first)}</h3>")
            rest="\n".join(lines[1:]).strip()
            if rest: paras.append("<p>"+"<br>\n".join(html.escape(l) for l in rest.split("\n"))+"</p>")
        elif re.match(r"^\d+\.\s+\S", first) and len(first)<100:
            paras.append(f"<h2>{html.escape(first)}</h2>")
            rest="\n".join(lines[1:]).strip()
            if rest: paras.append("<p>"+"<br>\n".join(html.escape(l) for l in rest.split("\n"))+"</p>")
        elif first.startswith("Phase "):
            paras.append(f"<h3>{html.escape(first)}</h3>")
            rest="\n".join(lines[1:]).strip()
            if rest: paras.append("<p>"+"<br>\n".join(html.escape(l) for l in rest.split("\n"))+"</p>")
        elif first in ("Protocol Specification: CLAVIS","Draft Notes: CLAVIS Project") or first.startswith("CLAVIS:"):
            paras.append(f"<h1>{html.escape(first)}</h1>")
        else:
            paras.append("<p>"+"<br>\n".join(html.escape(l) for l in lines)+"</p>")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: "IBM Plex Sans", "Segoe UI", sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.55; color: #1a1a1a; }}
h1,h2,h3,h4 {{ line-height: 1.25; }}
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
{chr(10).join(paras)}
</article>
<hr>
<details open>
<summary>Raw source (verbatim)</summary>
<pre class="source-md">{html.escape(md)}</pre>
</details>
</body>
</html>
"""
