SecureCodeScan

I revived this project after letting it sit for a year—an AI-powered vulnerability scanner that covers 10 languages (Python, JavaScript, Go, Rust, Java, and a few more). 

The goal is simple: catch security issues early without slowing down a developer's workflow.

How it works:

Runs a dual-pass engine. First, a lightweight regex pass scans 5k lines in <1ms to flag suspicious patterns. Then an LLM (NVIDIA Nemotron or Google Gemini) reasons over just those flagged blocks—saves tokens and cuts false noise.

If one model fails or times out, the other takes over automatically. That gives me ~99.9% uptime without manual intervention.

Pulls live data from the NVD API, so findings map to current CVEs rather than stale vulnerability lists.

Security guardrails (non-negotiable):
I enforced MFA across all accounts and built controls against prompt injection, rate-limit abuse, model poisoning, and jailbreak attempts. If the tool itself leaks source code or hallucinates bad advice, it defeats the purpose—so I prioritized that foundation before anything else.

Why it's free right now:
I'd rather have real developers push it to its limits, break edge cases, and tell me what actually matters before I design paid tiers. Your feedback—good or critical—is what guides the roadmap.

What's next:
I'm aiming to drive false positives below 1% and move this off a prototype subdomain onto a dedicated enterprise-ready domain. That's when I'll start charging.

Try it here:
https://lnkd.in/d3tJWSzm
