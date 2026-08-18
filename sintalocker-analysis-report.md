# Malware Analysis Report: SintaLocker Ransomware

**Analyst:** Radhesh Mutreja
**Sample family:** SintaLocker (CryPy variant)
**Platform:** Windows
**Classification:** Ransomware / Crypto-locker with backdoor persistence
**First publicly documented:** ~May 2017 (GData, Tripwire, SensorsTechForum)

---

## 1. Summary

SintaLocker is a Windows-targeting ransomware family, identified by security researchers as a spinoff of the CryPy ransomware family. It first surfaced in the wild around May 2017 and never achieved wide distribution — reporting at the time described it as being in a fairly lethargic state of distribution, with only a couple of reports of active attacks.

What makes it worth analyzing beyond "yet another 2017 crypto-locker" is that it doesn't stop at encryption — the sample combines file encryption, anti-recovery measures, victim intimidation (lockdown + wallpaper change), and a **persistent remote-access backdoor** via a newly created admin account with RDP enabled. That combination — extortion payload *plus* standing remote access — is a pattern still seen in modern ransomware operations (many current groups maintain backdoor access even after "resolving" an incident, specifically to enable re-extortion).

This report breaks the sample down stage by stage, maps each stage to MITRE ATT&CK, and lays out detection and mitigation guidance an analyst or blue team could act on.

---

## 2. Execution Flow Overview

```
Launch
  │
  ▼
C2 Check-in (victim fingerprinting + config pull)
  │
  ▼
Anti-Recovery Hardening (disable recovery, delete shadow copies)
  │
  ▼
System Lockdown (disable RegEdit, Task Manager, cmd, Run dialog)
  │
  ▼
Backdoor Account Creation (enable RDP, add attacker-controlled admin user)
  │
  ▼
File Discovery & Encryption (walk drives/folders, AES-encrypt, relocate, delete original)
  │
  ▼
Persistence (registry Run key)
  │
  ▼
Ransom Note Drop + Desktop Wallpaper Change
```

---

## 3. Stage-by-Stage Analysis with MITRE ATT&CK Mapping

### 3.1 Command-and-Control Check-in

**Behavior:** On launch, the sample collects the victim's OS/platform info (`platform.uname()`) and local IP address, base64-encodes both, and sends them as URL parameters to a hardcoded C2 endpoint. It expects a JSON response containing a victim ID and a pair of credential-like fields, which are used later to create the backdoor account.

**Why it matters for detection:** This is the single point of failure for the entire attack chain — if the C2 server is unreachable, the malware has no victim ID or backdoor credentials to work with. This is also true retroactively: since the original C2 infrastructure for this sample is long dead, even a victim from 2017 who paid the ransom would very likely be unable to recover, since the decryption key never lived locally.

| ATT&CK Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 |
| Gather Victim Host Information | T1592 |

**Detection guidance:**
- Outbound HTTP GET requests containing base64-encoded strings in URL query parameters, especially to newly-registered or low-reputation domains, from a process with no legitimate reason to make web requests
- A Sysmon Event ID 3 (NetworkConnect) correlated with a Sysmon Event ID 1 (ProcessCreate) showing a Python interpreter or PyInstaller-compiled binary as the source process is a strong anomaly signal in most enterprise environments, where Python isn't commonly run interactively by end users

---

### 3.2 Anti-Recovery Hardening

**Behavior:** The sample disables Windows's automatic recovery and boot failure handling via `bcdedit`, then deletes all Volume Shadow Copies via `vssadmin Delete Shadows /All /Quiet`. This removes the two most common built-in Windows self-recovery mechanisms before encryption even begins.

| ATT&CK Technique | ID |
|---|---|
| Inhibit System Recovery | T1490 |

**Detection guidance:** this is one of the highest-confidence ransomware indicators available, and one of the easiest to detect reliably — legitimate use of `vssadmin delete shadows /all` is extremely rare outside of deliberate, planned administrative action. See [`rules/sintalocker-detection-rules.xml`](#6-example-detection-rules) below.

---

### 3.3 System Lockdown

**Behavior:** The sample writes several `HKCU\...\Policies\System` and `Policies\Explorer` registry values to disable Registry Editor, Task Manager, `cmd.exe`, and the "Run" dialog. This is a defensive/anti-forensic measure aimed at slowing down a victim (or an incident responder working live on the box) from investigating or killing the process.

| ATT&CK Technique | ID |
|---|---|
| Impair Defenses: Disable or Modify Tools | T1562.001 |

**Detection guidance:** registry writes to `DisableRegistryTools`, `DisableTaskMgr`, `DisableCMD`, or `NoRun` under `CurrentVersion\Policies\` are rarely legitimate outside of managed Group Policy deployment — a write to these keys originating from a non-GPO process (i.e., not `gpupdate`/`svchost` under a GPO context) is a strong indicator.

---

### 3.4 Backdoor Account Creation

**Behavior:** The sample enables Remote Desktop by flipping `fDenyTSConnections` to 0, then creates a new local user account using the username/password pulled from the C2 config, and adds that account to the local Administrators group.

This is arguably the most operationally dangerous stage of the whole chain — even if a victim fully removes the ransomware binary and restores from backup, this backdoor account persists unless it's specifically found and removed, giving the attacker standing remote access.

| ATT&CK Technique | ID |
|---|---|
| Create Account: Local Account | T1136.001 |
| Remote Services: Remote Desktop Protocol | T1021.001 |
| Modify Registry (RDP enablement) | T1112 |

**Detection guidance:** this is the single most important stage to alert on, because it's the one most likely to be missed during incident cleanup. Any `net user <name> <password> /add` immediately followed by `net localgroup administrators <name> /add` within the same process tree is an extremely high-confidence indicator of an attacker establishing persistence, not routine IT administration (real sysadmin account provisioning virtually never happens via two chained `net.exe`/`cmd.exe` calls from an unrelated parent process).

---

### 3.5 File Discovery and Encryption

**Behavior:** The sample walks a large, hardcoded list of file extensions (covering documents, source code, backups, media, database files, VM disk images, and even cryptocurrency wallet files) across the user's profile folders and every mapped drive letter from D: through Z:. For each matching file, it generates a random AES key, encrypts the file's contents, writes the encrypted output to a new randomly-named file inside a hidden folder, and deletes the original.

| ATT&CK Technique | ID |
|---|---|
| Data Encrypted for Impact | T1486 |
| File and Directory Discovery | T1083 |

**Detection guidance:** the single strongest detection opportunity in the entire chain, because the *behavior* is nearly impossible for a ransomware family to avoid without failing at its core purpose:
- A high-volume burst of file **create** + **delete** operations against files of many different extensions, from a single process, in a short time window, is the canonical ransomware behavioral signature — most modern EDR/XDR products (and Wazuh via File Integrity Monitoring / `syscheck`) can alert on this pattern generically, without needing family-specific signatures
- The specific "encrypt into a new randomly-named file inside a new hidden folder, then delete original" pattern is slightly more distinctive than simple in-place encryption, and worth a dedicated FIM rule watching for new hidden directories appearing across many locations simultaneously

---

### 3.6 Persistence

**Behavior:** The sample adds itself to a startup mechanism (implementation detail not fully visible in the excerpt reviewed, but consistent with public reporting that it uses standard Windows Run-key-based persistence).

| ATT&CK Technique | ID |
|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |

**Detection guidance:** see the Registry Run Key persistence detection already built out in my [Wazuh detection lab](../wazuh-detection-lab/scenarios/05-persistence-registry-run-key/) — the same Sysmon Event ID 13 approach applies directly here.

---

### 3.7 Victim Notification

**Behavior:** Drops a ransom note (`README_FOR_DECRYPT.txt`/`.md`) into the encrypted folders and the desktop, containing a victim ID, a Bitcoin address, a contact email, and a fixed ransom amount. It then downloads and sets a ransom-themed desktop wallpaper as an additional, hard-to-miss notification.

| ATT&CK Technique | ID |
|---|---|
| Data Destruction (indirect, via original file deletion) | T1485 |

**Detection guidance:** file-creation of a large number of identically-named ransom-note files across many directories in a short window is a strong secondary confirmation signal, useful for automated response playbooks (e.g., auto-isolating a host the moment 5+ identically-named new `.txt`/`.md` files appear across different folders).

---

## 4. Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| Ransom note filename | `README_FOR_DECRYPT.txt` / `README_FOR_DECRYPT.md` |
| Encrypted file extension | `.sinta` (some variants use no extension) |
| Encrypted-file staging folder | `__SINTA I LOVE YOU__` |
| Registry keys modified | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools`, `DisableTaskMgr`, `DisableCMD`; `HKCU\...\Policies\Explorer\NoRun` |
| RDP enablement | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` set to `0` |
| Shadow copy deletion | `vssadmin Delete Shadows /All /Quiet` |
| Boot recovery disable | `bcdedit /set {default} recoveryenabled No`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures` |
| Backdoor account creation pattern | `net user <name> <password> /add` chained with `net localgroup administrators <name> /add` |

*(Note: the specific C2 domain and BTC address observed in the 2017 sample are not included here as actionable IOCs — that infrastructure is nearly a decade stale and including it adds no defensive value; a real incident should always be checked against current threat-intel feeds for live infrastructure.)*

---

## 5. Countermeasures / Mitigations

| Stage | Mitigation |
|---|---|
| C2 check-in | Egress filtering / DNS-layer blocking of newly-observed domains; block outbound traffic from user-writable directories (`%TEMP%`, `%APPDATA%`) at the host firewall level |
| Shadow copy deletion | Restrict `vssadmin`/`wmic shadowcopy` execution via application control (AppLocker/WDAC) to admin-only contexts; alert on any execution outside of patch/maintenance windows |
| Registry lockdown | Baseline and alert on writes to `Policies\System` and `Policies\Explorer` keys outside of GPO push events |
| Backdoor account | Enforce a policy alerting on **any** new local Administrators-group membership change, correlated with account creation in the same session; disable RDP by default on endpoints where it isn't a business requirement |
| File encryption | Deploy File Integrity Monitoring / behavioral EDR rules tuned to high-volume, multi-extension create+delete bursts; maintain offline/immutable backups (this sample specifically targets every mapped drive letter, so network-attached "backup" drives that stay mapped and writable are not protection — the sample would encrypt those too) |
| Persistence | Standard Run-key monitoring (see Wazuh lab scenario 05) |
| General | User-level: disable macro/script execution from email attachments if that's the likely delivery vector (not confirmed for this specific sample, but standard for the ransomware class); org-level: maintain a tested, offline backup + restore process, since paying this specific family's ransom is documented as frequently unsuccessful in restoring files even after payment |

---

## 6. Example Detection Rules (Wazuh)

Drop-in additions to the custom rule set, following the same structure as my [Wazuh detection lab](../wazuh-detection-lab/):

```xml
<group name="sintalocker,ransomware,">

  <!-- Shadow copy deletion - one of the highest-confidence ransomware indicators -->
  <rule id="100150" level="15">
    <if_sid>audit_command</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)vssadmin.*delete.*shadows</field>
    <description>Volume Shadow Copy deletion detected - high-confidence ransomware pre-encryption behavior</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>ransomware,attack,</group>
  </rule>

  <!-- Boot recovery disabled via bcdedit -->
  <rule id="100151" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)bcdedit\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(recoveryenabled no|bootstatuspolicy ignoreallfailures)</field>
    <description>Boot recovery options disabled via bcdedit - ransomware anti-recovery behavior</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>ransomware,attack,</group>
  </rule>

  <!-- Backdoor account creation chained with admin group add -->
  <rule id="100152" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)net (user|localgroup administrators) .* /add</field>
    <description>Local account created and added to Administrators - possible ransomware backdoor persistence</description>
    <mitre>
      <id>T1136.001</id>
      <id>T1021.001</id>
    </mitre>
    <group>ransomware,persistence,attack,</group>
  </rule>

  <!-- Ransom note mass file creation -->
  <rule id="100153" level="15" frequency="5" timeframe="60">
    <if_group>sysmon_event11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)readme.*decrypt.*\.(txt|md)$</field>
    <description>Multiple ransom-note-pattern files created across directories in short window - active ransomware encryption in progress</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,attack,</group>
  </rule>

</group>
```

---

## 7. Conclusion

SintaLocker is a relatively unsophisticated, non-widely-distributed ransomware sample from 2017, but it's a good teaching case precisely because every stage maps cleanly to a well-known ATT&CK technique, and each stage has a corresponding detection opportunity that generalizes well beyond this specific family. The shadow-copy-deletion and backdoor-account-creation stages in particular are worth internalizing as near-universal ransomware indicators — most modern ransomware families, regardless of sophistication, still perform some version of both, because inhibiting recovery and maintaining standing access are goals that don't change even as encryption routines and delivery mechanisms evolve.

This report deliberately does not include the sample's functional encryption or C2 communication code, since a defensive writeup doesn't need to be reproducible as working malware to be useful — the behavioral description and detection logic above is what an analyst or blue team would actually act on.
