# Windows 11 Data Components Configuration

## 1. Data Component Overview

- Sysmon
- Windows Advanced Logging
- ELK Stack
- PowerShell Logging


---

## 2. Data Components Installation & Configuration

### 2.1 Sysmon Configuration

```powershell
sudo .\sysmon64.exe -i .\sysmonconfig-export.xml
```

### 2.2 Windows Advanced Logging







| Data Component | Name | Channel |
|-------|---------------|--------|
| CAR-2013-09-003 | SMB Session Setups | 🔜 Planned |
| CAR-2014-04-001 | Suspicious Process Injection | 🔜 Planned |
| CAR-2016-03-001 | Registry Persistence | 🔜 Planned |

### 2.1 Normal SMB Usage

- **Source:** Windows 10 → **Destination:** Windows Server
- Typical pattern:
  - A small number of connections from one client to one server.
  - SMB session setup, tree connect, file operations, then teardown.
- Observed fields:
  - Source IP: `...`
  - Dest IP: `...`
  - Dest port: 445
  - Auth user: `labuser1`

### 2.2 Suspicious / Scan-like Behavior

- **Source:** Kali → multiple hosts
- Pattern:
  - Many SMB session setup attempts in quick succession across multiple IPs.
  - Some failed auth, some succeeded.
- Signs of lateral movement / reconnaissance:
  - High fan-out (1 → many hosts).
  - Repeated authentication attempts by same user to many targets.