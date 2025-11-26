# 🕷️ JADE SPIDER – Threat Hunt Walkthrough

*A guided investigation of a simulated JADE SPIDER intrusion using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL).*

![Repo Banner](images/banner.png)

---

## 📄 Report Info

| Field | Value |
|-------|-------|
| **Report ID** | IR-2025-11-AZUKI-JADE-SPIDER |
| **Analyst** | Dennis Medder |
| **Date** | November 2025 |
| **Severity** | High |
| **Status** | Contained |

---

## 🔎 Scenario Overview

This lab simulates a financially motivated threat actor known as **JADE SPIDER** targeting:

- **Company:** Azuki Import/Export Trading Co. (梓貿易株式会社)  
- **Primary host:** `azuki-sl` (IT admin workstation)  
- **Primary goal:** Steal pricing and contract data and exfiltrate it out of the environment.

The investigation is driven mainly by **Microsoft Defender for Endpoint** telemetry and KQL queries against:

- `DeviceLogonEvents`
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceNetworkEvents`

The goal of this repo is to show **how I approached the hunt**, not just the final flags.

---

## 🧠 The 5 W’s + H (High-Level Summary)

### WHO was involved?

- **Affected system:** `azuki-sl`
- **Affected user:** `kenji.sato`
- **Attacker source IP:** `10.0.8.9` (initial RDP access)
- **Lateral movement target:** `10.1.0.188`

---

### WHAT happened?

JADE SPIDER gained access to an IT admin workstation via **RDP** using stolen credentials.  
After logging in, they executed a malicious PowerShell script (**`wupdate.ps1`**) that:

- Added Windows Defender exclusions
- Downloaded payloads (including a credential dumper)
- Dumped credentials from **LSASS**
- Created a backdoor local admin account called **`support`**
- Archived sensitive data into **`export-data.zip`**
- Exfiltrated the archive to **Discord** via HTTPS
- Cleared Windows Event Logs
- Attempted lateral movement to **10.1.0.188** via RDP

---

### WHEN did it happen?

- **First activity:** `2025-11-19 01:36 UTC` (external RDP logon)
- **Last activity:** `2025-11-19 14:11 UTC` (log clearing and lateral movement attempt)
- **Approx. duration:** ~12.5 hours of dwell time and activity.

---

### WHERE did it happen?

- **Primary impacted system:** `azuki-sl`
- **Secondary target:** `10.1.0.188` (RDP lateral movement target)
- No confirmed compromise of other hosts in this exercise, but the intent is clear.

---

### WHY did it happen?

JADE SPIDER is described as a financially motivated group focused on:

- Logistics & import/export companies  
- Long dwell time
- Data theft before impact

In this scenario, they went after **pricing and contract data**, which later appeared on “underground forums” in the story background.

From a defensive perspective, the “why” is:

- **Exposed RDP** + **valid credentials** + **no MFA** = easy foothold.

---

### HOW did they do it? (Kill Chain Walkthrough)

1. **Initial Access** – RDP Logon from `10.0.8.9` to `azuki-sl`  
2. **Execution** – Attacker runs `wupdate.ps1` via PowerShell  
3. **Defense Evasion** – Adds Windows Defender exclusions and hides tools  
4. **Credential Access** – Uses `mm.exe` + `sekurlsa::logonpasswords` to dump LSASS  
5. **Persistence** – Creates a local admin account `support`  
6. **Collection** – Stages data into `export-data.zip`  
7. **Exfiltration** – Uses `curl.exe` to send data to a **Discord webhook**  
8. **Anti-Forensics** – Clears Security/System/Application logs with `wevtutil.exe`  
9. **Lateral Movement Attempt** – Uses `cmdkey` + `mstsc` to pivot to `10.1.0.188`

Each of these stages is represented by one or more KQL queries in the `/queries` folder.

---

## 🧱 Project Structure

```text
JADE-SPIDER-Threat-Hunt/
├── README.md
├── LICENSE
├── report/
│   └── JADE-SPIDER-Report.md
├── queries/
│   ├── initial_access.kql
│   ├── execution_script.kql
│   ├── defense_evasion.kql
│   ├── credential_access.kql
│   ├── lateral_movement.kql
│   ├── exfiltration.kql
│   └── persistence.kql
├── evidence/
│   ├── timeline.csv
│   ├── iocs.txt
│   └── attack_flow.txt
└── images/
    ├── banner.png
    ├── initial_access.png
    ├── malicious_script.png
    ├── credential_dump.png
    ├── persistence_account.png
    ├── exfiltration.png
    └── lateral_movement.png
```

- **`README.md`** – This file: overview + quick summary of the hunt.
- **`report/JADE-SPIDER-Report.md`** – Longer-form incident report.
- **`queries/`** – KQL used to answer each investigation question.
- **`evidence/`** – Timeline and IOCs captured from the investigation.
- **`images/`** – Screenshots from MDE / the lab environment.

---

## 📅 Timeline (Short Form)

| Time (UTC) | What Happened | Process/File | Notes |
|------------|----------------|--------------|-------|
| 01:36 | External RDP logon | N/A | Source: `10.0.8.9`, user: `kenji.sato` |
| 01:49 | Malicious script created | `wupdate.ps1` | Dropped in Temp folder |
| 01:50 | AV exclusions added | `powershell.exe` | Windows Defender exclusions |
| 01:52 | Tools downloaded | `curl.exe` | `svchost.exe`, `mm.exe` to `C:\ProgramData\WindowsCache` |
| 01:55 | Credential dumping | `mm.exe` | `sekurlsa::logonpasswords` against LSASS |
| 02:01 | Backdoor created | `net.exe` / `net1.exe` | Local user `support` + added to Administrators |
| 02:05 | Data staged | `export-data.zip` | Archive created in `WindowsCache` |
| 02:08 | Exfiltration | `curl.exe` | Upload to Discord webhook |
| 02:11 | Logs cleared | `wevtutil.exe` | `Security`, `System`, `Application` wiped |
| 14:09 | Lateral movement attempt | `mstsc.exe` | RDP to `10.1.0.188` using saved creds |

---

## 🧩 MITRE ATT&CK Mapping (High Level)

| Stage | What They Did | Technique ID |
|-------|---------------|--------------|
| Initial Access | RDP from 10.0.8.9 | **T1133** |
| Execution | Malicious PowerShell script (`wupdate.ps1`) | **T1059.001** |
| Persistence | Local admin backdoor account (`support`) | **T1136.001** |
| Defense Evasion | Defender exclusions, log clearing | **T1562.001**, **T1070.001** |
| Discovery | Network discovery | **T1016** |
| Credential Access | LSASS dump (`sekurlsa::logonpasswords`) | **T1003.001** |
| Lateral Movement | RDP to `10.1.0.188` | **T1021.001** |
| Collection | Archive created (`export-data.zip`) | **T1560** |
| C2 | HTTPS to Discord | **T1071.001** |
| Exfiltration | Web service (Discord webhook) | **T1567.002** |

For a full narrative-style write-up, see:  
👉 `report/JADE-SPIDER-Report.md`

---

## 🧪 Queries (Quick Examples)

Full queries are stored in the `/queries` folder. Here are a few highlights.

### 1️⃣ Initial Access – RDP Logon

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where LogonType == 10  // RemoteInteractive (RDP)
| project Timestamp, AccountName, RemoteIP, LogonType
| order by Timestamp asc
```

### 2️⃣ Malicious Script Identification

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "wupdate.ps1"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

### 3️⃣ Lateral Movement – cmdkey + mstsc

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName in~ ("cmdkey.exe", "mstsc.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

---

## 🧾 IOCs (Short List)

See full list in `evidence/iocs.txt`.

**IPs**

```text
10.0.8.9
10.1.0.188
162.159.135.232
```

**Files**

```text
wupdate.ps1
mm.exe
svchost.exe
export-data.zip
```

**Accounts**

```text
kenji.sato
support
```

**Domains**

```text
discord.com
```

---

## 📚 How to Use This Repo (Learning-Focused)

If you’re a student / junior analyst:

1. Read `README.md` to understand the story.
2. Open `report/JADE-SPIDER-Report.md` for a more detailed walkthrough.
3. Explore the `queries/` folder and run the KQL in your own lab.
4. Try to re-create the investigation without looking at the answers first.
5. Practice mapping each action to MITRE ATT&CK.

---

## 📝 License

This project is licensed under the **MIT License**.  
See `LICENSE` for details.
