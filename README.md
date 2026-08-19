# Malware Analysis — SintaLocker Ransomware

A behavioral analysis of **SintaLocker**, a 2017-era Windows ransomware family (CryPy variant), broken down stage by stage and mapped to MITRE ATT&CK, with detection rules and mitigations for each stage.

> **Note on scope:** this is a defensive/analytical writeup.
## Why this exists

Understanding how malware actually behaves — not just "ransomware encrypts your files" but the specific sequence of anti-recovery, lockdown, persistence, and backdoor steps a real sample takes is what turns a detection rule from a generic signature into something grounded in real attacker behavior. 

## What's covered

- **Full execution flow** — from initial C2 check-in through file encryption to ransom note delivery
- **Stage-by-stage breakdown** — 7 stages, each mapped to a MITRE ATT&CK technique ID
- **Detection guidance per stage** — what an analyst or SOC should actually alert on, and why
- **IOC table** — filenames, registry keys, command patterns (infrastructure-specific IOCs like the original C2 domain are deliberately omitted as stale/non-actionable)
- **Mitigations table** — practical countermeasures per stage
- **Ready-to-use Wazuh detection rules** — 4 rules following the same format as the Wazuh Detection Lab repo, covering shadow copy deletion, boot recovery tampering, backdoor account creation, and mass ransom-note file creation

## Report

See [`sintalocker-analysis-report.md`](sintalocker-analysis-report.md) for the full writeup.

## Key takeaways

The two most useful detections that came out of this analysis are ones that generalize well beyond this specific sample:

- **Volume Shadow Copy deletion** (`vssadmin delete shadows /all`) — one of the highest-confidence ransomware indicators available, since legitimate use outside planned maintenance is extremely rare
- **Local account creation chained with an admin-group add** — a near-universal pattern for ransomware operators establishing standing backdoor access, and one that's easy to miss during incident cleanup if a responder focuses only on removing the ransomware binary itself

Both patterns show up across many ransomware families beyond SintaLocker, which is why they're worth detecting generically rather than only as family-specific signatures.
