# CLAVIS — Agent Brief

**CLAVIS** (*Cryptographic Linked Attestation & Verifiable Identity System*) is a **cross-platform** personal data vault and protocol: the user holds encrypted credentials on their device, and releases them to verifiers only after explicit, hardware-gated consent.

## What we are building

A **Holder** app (the vault) that:

1. Stores personal documents/credentials **encrypted at rest** (passports, medical, financial, education, property, residential/lease, etc.).
2. Keeps signing/encryption keys in a **hardware security module** (TEE / Secure Enclave / StrongBox / equivalent). Devices without hardware-backed crypto are out of scope for the protocol.
3. Releases data only after **explicit user authorization** (biometrics and/or PIN; step-up MFA for higher risk).
4. Transmits a **Verifiable Presentation** encrypted to the verifier — never plaintext bulk export.
5. Aligns with **W3C DID / Verifiable Credentials**, industry schemas (e.g. Schema.org, HL7 FHIR, CDR/ISO 20022 where relevant), selective disclosure (Merkle / proofs), and proximity exchange (QR / NFC / BLE, ISO 18013-5 style) for in-person use.

**Problem it targets (Australia-first framing in the chat):** form fatigue, admin burden, data-entry errors (esp. healthcare), “honeypot” copies of documents on portals (e.g. rental), and pandemic-era check-in systems that lacked purpose binding and structural privacy.

## Platform stance (important)

Early chat/canvas material framed an **Android-only** Keystore app. **That framing was a mistake.**

- **Target:** all major platforms — **Android, iOS, Linux, Windows** (and equivalents), not Android alone.
- **Hard requirement:** a **hardware encryption / key-protection module** on the device. Platform APIs differ (Android Keystore, Apple Secure Enclave, TPM, etc.); the *protocol* stays platform-independent.
- Treat Android-specific wording in older specs/canvases as **historical draft language**, not product scope.

## Roles (DID / VC trust triangle)

| Role | Meaning |
|------|---------|
| **Issuer** | Signs credentials (e.g. clinic, bank, licensed professional). |
| **Holder** | CLAVIS vault on the user’s device. |
| **Verifier** | App/site/terminal requesting a presentation. |
| **Registry** | Trust directory for verifiers (Trusted / Registered / Non-Registered). |

Related ideas from the chat: operator trust hierarchy; retention / purpose binding / certificate of deletion; domain–data affinity and anomaly flags; signed dynamic requests vs static well-known manifests; web compliant handshake vs legacy form-fill fallback; encrypted document store (index + per-document containers, not one honey-pot DB).

## Preferred PoC emphasis (from chat)

Prove, in a serious domain (prefer **medical / government**, not toy “bartender” demos):

1. **Hardware-to-data binding** — decrypt/sign only via HSM + user auth.
2. **Selective disclosure** — release only needed fields with proofs.
3. **Semantic credentials** — JSON-LD / VC shaped for real schemas (e.g. FHIR-oriented medical example).

## Repository orientation

| Path | Role |
|------|------|
| `gemini-export/` | Export of the Gemini design chat + Canvas HTML bodies. |
| `gemini-export/index.html` | Chronological Q&A transcript (primary narrative of decisions). |
| `gemini-export/canvas/*.html` | Canvas artifacts extracted from that chat. |
| `notes.md`, `protocol_draft_0.1.md` | Local scratch / early protocol draft. |
| `slides/` | Full-project slide deck work started from the same chat. |

### Canvas / Gemini artifacts = **unverified drafts**

The owner has **not reviewed or approved** the Canvas files (or Gemini-generated specs derived from them). Treat **all** of `gemini-export/canvas/` as **unchecked drafts**:

- High probability of **errors, inventiveness, over-precision, or outdated framing** (including Android-centric titles such as “Secure Android Data Vault”).
- Some canvases are **incomplete/partial** even as exports (see `gemini-export/README.md` and `_canvas_status.json`).
- Do **not** treat Canvas text as locked requirements, compliance claims, or implementation truth.

**Source-of-truth order for agents:**

1. This `AGENTS.md` and explicit owner instructions in the current chat.
2. The **logic of the Gemini transcript** (`gemini-export/index.html` / `_raw_transcript.json`) — what the owner asked for and corrected over time.
3. Local drafts (`protocol_draft_0.1.md`, `notes.md`) as working notes only.
4. Canvas HTML — **reference only**, always labeled mentally as *unverified draft*.

When Canvas conflicts with the transcript or with the cross-platform rule above, **follow the chat corrections and this brief**.

## How to work in this repo

- Prefer **protocol-level, cross-platform** design over platform lock-in.
- Prefer **standards and verifier-native schemas** over proprietary CLAVIS field layouts (“zero-mapping” intent).
- Prefer **healthcare / high-stakes government** examples for demos and slides when choosing use cases.
- Do not silently promote Canvas content into “spec” without owner review.
- Do not invent regulatory or market claims beyond what the owner has accepted; mark speculation clearly.
