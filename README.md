# SecureCodeScan

**AI-powered vulnerability scanner | Scan 10 languages in <10 seconds**

I revived this project after a year on the shelf. It scans source code for security weaknesses across 10 languages (Python, JavaScript, Go, Rust, Java, and others), using a hybrid regex + LLM approach to keep things fast and accurate.

---

## Why I built it

Most security tools are either too slow, too noisy, or too expensive for individual developers. I wanted something that fits into a normal workflow—catch real issues, ignore false alarms, and finish before you lose focus.

The scanner is currently **free** while I gather feedback from real-world use. Your input decides what makes it into the paid version later.

---

## How it works

### Dual-pass engine
- **Pass 1 (Regex pre-filter):** Scans 5,000 lines of code in <1ms to flag suspicious patterns. This primes the system without burning LLM tokens on clean code.
- **Pass 2 (LLM reasoning):** Only the flagged blocks are passed to an LLM for deeper context-aware analysis. This keeps scan times under 10 seconds per codebase.

### Model failover for reliability
I integrated both **NVIDIA Nemotron** and **Google Gemini**. If one model fails or times out, the other takes over automatically—no manual intervention required, delivering ~99.9% uptime.

### Live threat intelligence
The scanner pulls real-time vulnerability data from the **National Vulnerability Database (NVD) API**, so findings are current and mapped to actual CVEs, not stale signatures.

---

## Security & guardrails (non-negotiable)

A security tool that leaks source code or hallucinates fixes is worse than none at all. So before anything else, I built:

- Mandatory MFA for all accounts
- Rate-limiting to prevent abuse
- Prompt injection defense and jailbreak detection
- Model poisoning safeguards
- Ephemeral code processing—no persistent storage of proprietary source

---

## What's next

I intend to turn this prototype into an enterprise-ready benchmark over the coming months:

- Drive false positives to <1%
- Move to a dedicated custom domain with enterprise-grade reliability
- Build out paid tiers with team collaboration and CI/CD integrations

---

## Try it

**Launch the prototype:**  
https://lnkd.in/d3tJWSzm

---

## Feedback welcome

Raise issues, suggest features, or just share your experience. That's what shapes the roadmap from here.
