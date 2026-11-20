# CLAVIS — Gemini chat export

## Source

- **URL:** https://gemini.google.com/app/32920e9e8337e92a  
- **Title:** CLAVIS - Google Gemini  
- **Account:** authenticated (`konoshevich@gmail.com`) in Cursor browser at export time  

## What was exported

| Artifact | Status |
|----------|--------|
| `index.html` — full Q&A transcript (verbatim) | **Done** (51 user + 51 model) |
| `_raw_transcript.json` — machine-readable dump | **Done** |
| `canvas/*.html` — Canvas document bodies | **7 full + 2 partial** |

### Canvas status (9)

| # | Title | File | Status |
|---|-------|------|--------|
| 1 | Secure Android Data Vault Specification | `canvas/secure-android-data-vault-specification.html` | **Full** |
| 2 | Secure Vault Inter-App Protocol (SVIAP) | `canvas/secure-vault-inter-app-protocol-sviap.html` | **Full** |
| 3 | Draft Notes: Secure Vault | `canvas/draft-notes-secure-vault.html` | **Full** |
| 4 | Market Review: Secure Vault Project | `canvas/market-review-secure-vault-project.html` | **Full** |
| 5 | CLAVIS Protocol Specification | `canvas/clavis-protocol-specification.html` | **Full** (Previous-version walk) |
| 6 | CLAVIS: Proof of Concept Roadmap (v1.1) | `canvas/clavis-proof-of-concept-roadmap-v1-1.html` | **Full** |
| 7 | Draft Notes: CLAVIS Project | `canvas/draft-notes-clavis-project.html` | **Partial** (merged Entries #10–25 via `LpbbXc`; #1–9 not in recoverable history) |
| 8 | CLAVIS: Minimal PoC Scope (Medical) | `canvas/clavis-minimal-poc-scope-medical.html` | **Partial** (§4 addendum delta only) |
| 9 | CLAVIS: Medical Credential Example | `canvas/clavis-medical-credential-example.html` | **Full** (JSON-LD) |

## How canvas bodies were obtained

Most full canvases came **verbatim** from authenticated `batchexecute` responses (`rpcid=hNvQHb`).

Protocol Spec was completed by walking Canvas **Previous version** until the full baseline appeared in the editor.

Draft Notes (CLAVIS) was improved by capturing Canvas document fetches (`rpcid=LpbbXc`) across version walks and merging per-Entry sections. Gemini’s stored versions still omit Entry #1–9 as ellipsis/stubs, so that file remains **Partial**.

Minimal PoC (Medical) never returned a full baseline via `hNvQHb`, `LpbbXc`, or the side-panel editor (empty ProseMirror / §4-only deltas).

## Finish the 2 remaining partial canvases (manual)

In a normal desktop browser:

1. Open https://gemini.google.com/app/32920e9e8337e92a  
2. Click **Open … in Canvas**, then **Export** (or select-all → copy):

| Canvas | Overwrite file |
|--------|----------------|
| Draft Notes: CLAVIS Project | `gemini-export/canvas/draft-notes-clavis-project.html` |
| CLAVIS: Minimal PoC Scope (Medical) | `gemini-export/canvas/clavis-minimal-poc-scope-medical.html` |

Best single manual step for leftovers: open **Minimal PoC Scope (Medical)** first (still §4-only), Export; then open **Draft Notes: CLAVIS Project**, jump to the earliest version / Export to recover Entries #1–9 if Gemini still has them locally.

## Transcript method (unchanged)

1. Expanded collapsed user bubbles (`.luminous-collapsed`).  
2. CDP extract of all `user-query` / `model-response` turns.  
3. Chronological `index.html` with `#turn-N` anchors and relative links into `canvas/`.  

## Files

```
gemini-export/
  README.md
  index.html
  _raw_transcript.json
  _api_hNvQHb_raw.txt
  _canvas_status.json
  canvas/
    secure-android-data-vault-specification.html      # full
    secure-vault-inter-app-protocol-sviap.html        # full
    draft-notes-secure-vault.html                     # full
    market-review-secure-vault-project.html           # full
    clavis-protocol-specification.html                # full
    clavis-proof-of-concept-roadmap-v1-1.html         # full
    draft-notes-clavis-project.html                   # partial (#10–25 merge)
    clavis-minimal-poc-scope-medical.html             # partial (§4 only)
    clavis-medical-credential-example.html            # full (JSON)
```
