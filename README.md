# Task2
phising email

# phishing_report.md

## Title

Phishing Analysis Report — "CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!"

## Summary (TL;DR)

This message is a phishing email impersonating Banco do Bradesco / Livelo. Key indicators: forged display name and email address, sending IP (137.184.34.4) hosted on a cloud VPS, SPF/DKIM/DMARC failures (temporary errors / absent), suspicious Return-Path and HELO, spam score signals. Verdict: **Phishing / Scam** — do not click links or provide credentials.

---

## Evidence & IOCs (Indicators of Compromise)

* **From (display)**: BANCO DO BRADESCO LIVELO
* **From (mailbox)**: [banco.bradesco@atendimento.com.br](mailto:banco.bradesco@atendimento.com.br)
* **Envelope sender / Return-Path**: root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
* **Message ID**: `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>`
* **Subject**: CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!
* **Date**: Tue, 19 Sep 2023 18:35:49 +0000 (UTC)
* **Sending IP**: `137.184.34.4` (appears to be a cloud VPS — hostname `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` suggests DigitalOcean SFO3 flavor)
* **SPF result**: TempError (DNS timeout during lookup)
* **DKIM**: none (message not signed)
* **DMARC**: TempError
* **X-SID-PRA**: `BANCO.BRADESCO@ATENDIMENTO.COM.BR` (display/PrA mismatch — suspicious)
* **SCL (Spam Confidence Level)**: 5 (suspicious/high)
* **URLs found in HTML** (extracted from message body): `https://blog1seguimentmydomaine2bra.me/` (and various relative references to images like `header.png`, `icone-superior.png`, `icone-rodape.png`) — these domains look malicious/typosquatted.

> Note: If you will forward samples to a takedown or abuse team, include full headers + raw MIME body.

---

## Header analysis (step-by-step)

1. **Received chain**: email traversed Office365/Exchange Online Protection (EOP) frontends but the **originating hop** shows `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4)` — a cloud VPS rather than a legitimate bank mail server.
2. **SPF**: `Received-SPF: TempError` — the mail transfer agent attempted to check SPF but DNS resolution timed out. Legitimate bank domain mailboxes normally have valid SPF records and pass checks. TempError reduces trust.
3. **DKIM**: `dkim=none (message not signed)` — bank transactional emails are commonly signed. No DKIM signature is present.
4. **DMARC**: `dmarc=temperror action=none` — DMARC could not be validated due to DNS timeout. No protective action.
5. **Return-Path** mismatch: the Return-Path (`root@ubuntu...`) is inconsistent with the From header `banco.bradesco@atendimento.com.br` — typical sign of forging.
6. **Message ID / HELO**: Both reference `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`, indicating message originated from an ephemeral cloud VM.
7. **Anti-spam headers**: `X-Microsoft-Antispam`, `X-Microsoft-Antispam-Message-Info` and `SCL:5` indicate Microsoft EOP flagged the message as suspicious.

---

## Body/content analysis

* Message content is an HTML page (base64-encoded in MIME) containing Portuguese text appealing to urgency (points expiring *hoje* = today) — classic phishing lure.
* Visual impersonation: uses bank name and Livelo branding (images, logos). Images referenced in the HTML are not hosted on official bradesco.com.br/Livelo domains but rather on a suspicious domain (`blog1seguimentmydomaine2bra.me` pattern) or local paths. This is a hosting mismatch.
* Links: anchor elements link to external domains with likely typosquatting. Hover-targets and link destinations should be treated as malicious.
* No legitimate personalization (no masked customer account details, only generic greeting) — another red flag.

---

## Threat techniques (high level)

* **Impersonation / Brand abuse** — pretends to be a bank (Bradesco / Livelo).
* **Urgency/scare** — "points expiring today" to provoke quick clicks.
* **Hosting on cloud VPS** — avoids established mail infrastructure to bypass reputation checks.
* **Missing DKIM/SPF/DMARC alignment** — forgery of headers.

(Comparable MITRE ATT&CK techniques: Phishing — T1566; Impersonation T1598)

---

## Recommended actions for recipients

1. Do NOT click any links or download attachments from this email. Delete it.
2. Mark the message as phishing/spam in your mail client to improve filtering.
3. If you clicked a link and entered credentials, immediately change passwords for the affected service and enable MFA; contact your bank.
4. Report the email to the legitimate brand (Bradesco/Livelo) via their official abuse/report channels and to your mail provider.
5. If you received this on a corporate account, forward the raw message (with headers) to your security team/incident response.

---

## Recommended actions for defenders / SOC

1. **IOCs**: block `137.184.34.4` at perimeter if possible; add message headers and domain/URLs to blocklists; add sender to mail gateway denylist.
2. **Takedown**: submit abuse reports to the cloud hosting provider (use `whois` / IP lookup to find provider) and request removal of the phishing site.
3. **Mail flow rules**: create a rule to quarantine messages that claim to be from `bradesco` but come from external / cloud-origin IPs without valid SPF/DKIM.
4. **Alerting**: create SIEM rules to detect MailFrom/Return-Path mismatches and messages with `SCL >= 5` that contain brand keywords (Bradesco, Livelo).
5. **User awareness**: circulate a short bulletin to employees describing the phishing lure and instructing users how to report.

---

## Appendix — quick forensic commands

```
# Lookup IP owner and ASN
whois 137.184.34.4

# Reverse DNS
dig -x 137.184.34.4 +short

# Check SPF record for the sending domain
dig txt atendimento.com.br +short

# Check domain WHOIS
whois blog1seguimentmydomaine2bra.me

# Submit header to online analyzers
# - use Mozilla/Google/Proofpoint header analyzers as needed
```

---

# README.md

## Project: phishing-sample-analysis

**Purpose**: This repository contains a phishing sample (headers + HTML) and a forensic analysis report. Use it for training, detection testing, and improving mail filters. **Only handle samples in a safe environment** — do not host live phishing pages or click malicious links.

### Files in this repo

* `phishing_report.md` — Detailed analysis and IOCs (this document).
* `sample_headers_and_body.txt` — Raw email headers + base64 MIME body (include only if you store the original sample).
* `README.md` — This file.

### How to reproduce the analysis

1. Save the raw email (full source) to a file: `raw.eml`.
2. Extract headers: `sed -n '1,200p' raw.eml > headers.txt` (adjust ranges).
3. Decode base64 HTML body if needed (example):

   ```bash
   # If the body is base64 in the MIME part, extract and decode
   awk '/^Content-Transfer-Encoding: base64/{flag=1;next}/^$/{flag=0}flag' raw.eml | base64 -d > body.html
   ```
4. Use automated header analysis services or local tools:

   * `spamassassin -D -t raw.eml`
   * `ripmime` / `munpack` to extract MIME parts
   * Online header analyzers (MxToolbox, Microsoft Message Header Analyzer)
5. Resolve IOCs:

   * `whois 137.184.34.4`
   * `dig txt atendimento.com.br +short`
   * Open URLs only in an isolated sandbox (or not at all).

### Recommended tools

* `dig`, `whois`, `nslookup`
* `ripmime`, `munpack`, `ripgrep`
* `spamassassin`
* Browser sandbox / isolated VM for safe review

### Responsible handling

* Do NOT publish active phishing URLs or credentials in public repos.
* Redact or hash sensitive data (PII, account numbers) before sharing.
* When reporting to banks or hosting providers include full headers and timestamps.

### Contribution

If you improve the analysis or add indicators, open a PR and include source references and evidence.

### License

MIT — use for training and research only. Attribution appreciated.

---

*End of document.*
