# JADE SPIDER Threat Hunt – Full Incident Report

## 1. Report Info

- **Report ID:** IR-2025-11-AZUKI-JADE-SPIDER  
- **Analyst:** Dennis Medder  
- **Date:** November 2025  
- **Severity:** High  
- **Status:** Contained  

---

## 2. Executive Summary

This report documents a simulated intrustion attributed to the financially motivated threat actor **JADE SPIDER** against **Azuki Import/Export Trading Co.** The attacker gained access to an IT admin workstation (`azuki-sl`) through Remote Desktop Protocol (RDP) using valid credentials.

Once inside, the attacker executed a malicious PowerShell script (`wupdate.ps1`) to automate:

- Windows Defender tampering
- Malware staging
- Credential dumping from LSASS
- Persistence via a new local admin account
- Data staging into a ZIP archive
- Exfiltration to a Discord webhook
- Event log clearing
- An attempted RDP-based lateral movement to `10.1.0.188`

The intrusion emphasizes the risks associated with exposed RDP, lack of MFA, and reliance on default logging without additional behavioral detections.

---

## 3. The 5 W’s + H

### WHO

- **Victim organization:** Azuki Import/Export Trading Co.  
- **Primary host:** `azuki-sl` (IT admin workstation)  
- **Primary user:** `kenji.sato`  
- **Attacker IP (initial access):** `10.0.8.9`  
- **Lateral movement target:** `10.1.0.188`  

---

### WHAT

JADE SPIDER conducted a full attack chain operation, including:

- Initial access via RDP
- Execution of a malicious script
- Defense evasion through AV exclusions and log clearing
- Credential dumping
- Persistence through a hidden local admin account
- Data collection and compression
- Exfiltration over HTTPS to Discord
- Attempted lateral movement

The primary objective was to steal sensitive contract and pricing data.

---

### WHEN

- **First observed activity:** `2025-11-19 01:36 UTC` – RDP logon from `10.0.8.9`  
- **Last observed activity:** `2025-11-19 14:11 UTC` – log clearing and lateral movement attempt  
- **Approximate duration:** ~12.5 hours

---

### WHERE

- **Compromised host:** `azuki-sl`  
- **Secondary target (attempted):** `10.1.0.188`  

All confirmed malicious activity occurred on `azuki-sl`, with an RDP attempt toward `10.1.0.188` indicative of planned lateral movement.

---

### WHY

JADE SPIDER is described as:

- Financially motivated
- Focused on logistics and import/export
- Known for data theft followed by potential ransomware or extortion

In this scenario, the attacker targeted **contracts and pricing data**, which could provide competitive or extortion value. The incident brief mentions that Azuki’s competitor undercut them by precisely 3%, implying stolen pricing intelligence.

---

### HOW (Attack Chain Overview)

1. **Initial Access – RDP**

   - Attacker authenticated to `azuki-sl` via RDP (`LogonType == 10`) from `10.0.8.9`.
   - The logon used the account `kenji.sato`.

2. **Execution – PowerShell Script**

   - A PowerShell script named `wupdate.ps1` was created in a Temp directory and executed.
   - The name is designed to resemble a legitimate Windows Update script.

3. **Defense Evasion – AV Exclusions**

   - Windows Defender exclusions were added for certain paths and file extensions.
   - This would allow malware and tools to run with reduced likelihood of detection.

4. **Malware Staging – WindowsCache Directory**

   - Attacker used `curl.exe` to download tools into:
     - `C:\ProgramData\WindowsCache\svchost.exe`
     - `C:\ProgramData\WindowsCache\mm.exe`
   - This directory was used as a **staging folder** for tools and data.

5. **Credential Access – LSASS Dumping**

   - The tool `mm.exe` was used to run a Mimikatz-like command:
     - `sekurlsa::logonpasswords`
   - This collected logon credentials from LSASS, enabling further compromise and lateral movement.

6. **Persistence – Local Admin Account**

   - The attacker created a new local user:
     - `net user support ********** /add`
   - Then added it to the Administrators group:
     - `net localgroup Administrators support /add`
   - This ensured a backdoor account remained even if the original credential was changed.

7. **Collection – Data Staging**

   - Files of interest were collected and compressed into:
     - `C:\ProgramData\WindowsCache\export-data.zip`
   - This ZIP file was used as the container for exfiltration.

8. **Exfiltration – Discord Webhook**

   - `curl.exe` was used to upload `export-data.zip` to a Discord webhook over HTTPS.
   - This provides a stealthy C2 / exfil channel leveraging a legitimate cloud service.

9. **Anti-Forensics – Log Clearing**

   - `wevtutil.exe` was used to clear:
     - Security log
     - System log
     - Application log
   - This is a strong indicator of malicious intent and attempt to hinder investigation.

10. **Lateral Movement Attempt – RDP**

    - The attacker used:
      - `cmdkey.exe` to store credentials for `10.1.0.188`
      - `mstsc.exe /v:10.1.0.188` to attempt RDP
    - This indicates targeting of another internal system, likely with higher value or data access.

---

## 4. Timeline (Detailed)

| Time (UTC) | Event | Process/File | Notes |
|------------|--------|--------------|-------|
| 01:36 | External RDP logon to `azuki-sl` | N/A | `LogonType=10`, source IP `10.0.8.9` |
| 01:49 | Malicious script created | `wupdate.ps1` | Dropped into Temp directory |
| 01:50 | AV exclusions configured | `powershell.exe` | Windows Defender paths/extensions excluded |
| 01:52 | Tools downloaded | `curl.exe` | `svchost.exe`, `mm.exe` downloaded into `WindowsCache` |
| 01:55 | Credential dumping | `mm.exe` | Executes `sekurlsa::logonpasswords`-style module |
| 02:01 | Backdoor local admin created | `net.exe` / `net1.exe` | Local account `support`, added to Administrators |
| 02:05 | Data archive created | `export-data.zip` | Staged in `C:\ProgramData\WindowsCache` |
| 02:08 | Exfiltration to Discord | `curl.exe` | HTTPS upload to Discord webhook |
| 02:11 | Event logs cleared | `wevtutil.exe` | Security, System, Application logs cleared |
| 14:09 | Lateral movement attempt | `cmdkey.exe`, `mstsc.exe` | Credentials stored and RDP attempt to `10.1.0.188` |

---

## 5. MITRE ATT&CK Mapping

| Stage | Action | Technique ID | Notes |
|-------|--------|-------------|-------|
| Initial Access | RDP using stolen credentials | **T1133** | Remote access from `10.0.8.9` |
| Execution | PowerShell script `wupdate.ps1` | **T1059.001** | Malicious automation |
| Persistence | Local admin `support` | **T1136.001** | Backdoor account with admin rights |
| Defense Evasion | AV exclusions | **T1562.001** | Modify/disable security tools |
| Defense Evasion | Clear event logs | **T1070.001** | Anti-forensics |
| Discovery | Network/config discovery | **T1016** | Use of native tools (e.g., getmac) |
| Credential Access | LSASS dumping (`sekurlsa::logonpasswords`) | **T1003.001** | Credential theft from memory |
| Lateral Movement | RDP to `10.1.0.188` | **T1021.001** | Remote Desktop Protocol |
| Collection | Archive data in ZIP | **T1560** | `export-data.zip` |
| Command and Control | HTTPS (Discord webhook) | **T1071.001** | Web-based C2 / exfil channel |
| Exfiltration | Web service (Discord) | **T1567.002** | Exfiltration over legitimate service |

---

## 6. Impact & Risk

### Impact

- Confidential business data exfiltrated.
- Local credentials compromised.
- Logs cleared, complicating response and visibility.
- Evidence of attempted lateral movement.

### Risk

If replicated in a real environment, this type of intrusion could:

- Lead to **loss of competitive advantage** (stolen pricing/contracts).
- Expose user or admin credentials usable in other systems.
- Provide a foothold for **ransomware deployment**.
- Undermine trust in IT admin workstations.

---

## 7. Recommended Actions

### Immediate

- Isolate `azuki-sl` from the network.
- Remove `support` account and review other local accounts.
- Block known JADE SPIDER indicators (IPs, domains, hashes).
- Reset credentials used on the host, especially privileged ones.

### Short-Term (This Week)

- Enable MFA for all RDP and admin access.
- Review RDP exposure (prefer VPN or Bastion).
- Audit Defender exclusions across endpoints.
- Hunt for JADE SPIDER-like behavior in other systems.

### Long-Term

- Implement stronger network segmentation around admin workstations.
- Enhance logging and SIEM integration.
- Deploy behavior-based EDR rules for:
  - `curl.exe` used with external URLs
  - `wevtutil.exe cl`
  - `cmdkey.exe` and `mstsc.exe` chains
- Conduct security awareness around credential reuse and phishing.

---

## 8. Lessons Learned

From a learning perspective, this lab helped practice:

- Using MDE tables (Process, File, Registry, Network, Logon events)
- Writing KQL queries to pivot from one stage to the next
- Mapping activity to MITRE ATT&CK
- Reconstructing a full attack timeline
- Producing a structured incident report suitable for a portfolio

This scenario is especially useful for junior analysts who want to see how small pieces (commands, IPs, process names) all connect into a complete intrusion story.
