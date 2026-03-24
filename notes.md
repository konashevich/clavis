# Draft Notes: Secure Vault Project

## Purpose Statement

This document serves as a persistent repository for evolving thoughts, architectural ideas, and preliminary concepts related to the Secure Vault project. These notes act as a "scratchpad" for the user to capture brainstormed ideas which may later be referenced for formal implementation within the project's scope.

## Protocol of Interaction

1. **Trigger:** The user provides an idea, often prefaced by "make a draft note" or similar.
2. **Processing:** If the input is in a language other than English, it will be translated. The content will then be polished for technical clarity and professional formatting.
3. **Recording:** The refined thought will be appended to this file.
4. **Reference:** These notes remain dormant until the user explicitly requests to integrate a specific idea into the project's formal specifications or protocols.

## 📝 Draft Entries

### Entry #1: The Australian Productivity & Administrative Burden Case

*Date: March 24, 2026*(Content regarding form fatigue, labor productivity decline, and the \$1.2B healthcare error cost.)

### Entry #2: Taxonomy of Secure Data Types

*Date: March 24, 2026*(Content regarding Personal, Financial, Medical, Education, Property, and Residential data categories.)

### Entry #3: The Operator Trust Hierarchy & Verification Registry

*Date: March 24, 2026*(Content regarding Trusted, Registered, and Non-Registered operator categories.)

### Entry #4: Data Retention, Expiry, & Deletion Audit Protocol

*Date: March 24, 2026*(Content regarding the Lifecycle Contract, Audit Logs, and the "Right to be Forgotten.")

### Entry #5: Web Interaction Protocol (Compliant vs. Legacy)

*Date: March 24, 2026*(Content regarding SVIAP-ready websites vs. predictive filling for legacy sites.)

### Entry #6: Contextual Authorization & Data-Operator Matching

*Date: March 24, 2026*(Content regarding domain-data affinity, anomaly flags, and multi-factor authentication for cross-domain requests.)

### Entry #7: Lessons from the Pandemic – The Case for Structural Privacy

*Date: March 24, 2026*

**The Problem: "Emergency Quality" Solutions**During the COVID-19 pandemic, Australia saw the rapid rollout of digital check-in systems (QR codes) that lacked a unified architectural vision. This led to:

* **"Surveillance Creep":** Law enforcement in several states (WA, QLD, VIC) accessed health check-in data for criminal investigations, breaking public trust.
* **Third-Party Fragmentation:** Businesses used unverified third-party platforms, creating unsecure "honeypots" of personal data.
* **Legal Instability:** Regulations were often changed by ministerial decree rather than primary legislation.

**The Solution: SVIAP as a Universal Registration Protocol**

* **Privacy-by-Design:** The Vault provides "Ephemeral Handshakes" rather than plaintext uploads.
* **Immutable Purpose Binding:** The protocol cryptographically binds data to a specific purpose (e.g., "Health Check-in Only"), preventing mission creep.
* **Verification Over Collection:** Allows a "Green Tick" status check without the venue needing to see or store the user's name/phone.

### Entry #8: Integration with W3C DID & Verifiable Credentials (VC)

*Date: March 24, 2026*

The SVIAP protocol should be viewed as a high-security implementation of the **W3C Decentralized Identity (DID)** and **Verifiable Credentials (VC)** standards.

**1. The "Trust Triangle" Mapping:**

* **Issuer:** The licensed professionals (Entry #3) who sign the data (e.g., a Doctor signing a medical record).
* **Holder:** The Secure Vault App, which stores the encrypted VC.
* **Verifier:** The "Consumer" app requesting the data.

**2. Hardware-Enforced Credentials:**While standard VCs are often software-managed, SVIAP mandates that the private keys used to "Present" a credential are locked in the **Hardware Keystore (TEE/SE)**. This creates a "Hardware-Bound Presentation," ensuring the identity cannot be cloned even if the phone's OS is compromised.

**3. Interoperability:**By aligning with the DID/VC standards, the Secure Vault can theoretically accept credentials from any international issuer (e.g., an EU Digital Identity Wallet) while adding a superior layer of hardware-backed authorization.
