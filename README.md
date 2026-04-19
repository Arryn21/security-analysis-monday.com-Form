# Monday.com Public Form — Security Research

## Overview

Security analysis of attack surfaces exposed by unauthenticated SaaS-hosted public forms. Uses monday.com as case study platform. All company identifiers redacted.

## Purpose

Educational and defensive security research. Documents real-world attack chains that require zero technical skill from attacker but can result in full organizational compromise.

## Contents

| File | Description |
|------|-------------|
| `monday_form_security_analysis.md` | Full technical analysis |

## Topics Covered

- URL and parameter decomposition
- Region routing and data residency implications
- Form ID security model (Security Through Obscurity)
- Data poisoning via unauthenticated form submissions
- CSV injection — full payload catalog (5 tiers)
- NTLM hash theft via SMB UNC hyperlink (no-click)
- NTLMv2 capture, cracking, and relay attacks
- Full attack chain simulation with timeline
- Detection signatures (EDR, SIEM, IDS, network)
- Defensive mitigations and remediation priority

## Key Finding

A single poisoned form submission can result in full credential compromise through CSV injection → NTLM hash theft → password crack, requiring only that a staff member opens a routine CSV export. No malware deployed. No AV trigger.

## Disclaimer

All techniques documented here are publicly known, listed in OWASP guidelines, and covered by existing CVEs. No systems were compromised during this research. Intended for defensive security awareness and blue team use.

## Usage

Replace `[TARGET_ORG]` placeholder in analysis document with actual organization name for internal reporting.

---

*For educational and defensive security purposes only.*
