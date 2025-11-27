# Detection Engineering Portfolio

Welcome! This site showcases my hands-on work in:

- MITRE ATT&CK–based attack simulations  
- MITRE CAR analytics implementation  
- Detection engineering (rules, queries, scripts)  
- Telemetry analysis (Sysmon, Windows Event Logs, Zeek, pcaps)

The source code and full repository are available on GitHub:

- **GitHub Repo:** [detection-engineering-portfolio](../)

---

## 🔬 Lab Overview

I run a home detection lab on:

- **Host:** Mac Mini 2018  
- **Hypervisor:** VMware ESXi  
- **Lab VMs:**  
  - Kali Linux (attacker)  
  - Windows 10 (endpoint)  
  - Windows Server (SMB/file server; optional DC)  
  - Optional: Zeek sensor / Elastic SIEM

Details: see [`00-lab-architecture/`](../00-lab-architecture/).

---

## 📘 MITRE CAR Analytics

I’m using the MITRE Cyber Analytics Repository (CAR) as a series of “detection challenges.”

Each analytic includes:

- Lab setup & attack reproduction  
- Telemetry captures (pcaps, logs)  
- Detection logic (Sigma, KQL, SPL, EQL, Zeek)  
- Analysis, false positives, and tuning notes  

Current work:

- [CAR-2013-09-003 – SMB Session Setups](../01-car-analytics/CAR-2013-09-003-smb-session-setups/)
- (More coming soon…)

---

## 🧪 ATT&CK Technique Simulations

Separate from CAR, I also simulate individual MITRE ATT&CK techniques and build detections:

- [`02-attack-simulations/`](../02-attack-simulations/)

---

## 📜 Detection Rules

Centralized collection of detection content:

- [`03-detection-rules/sigma/`](../03-detection-rules/sigma/)
- [`03-detection-rules/splunk/`](../03-detection-rules/splunk/)
- [`03-detection-rules/sentinel-kql/`](../03-detection-rules/sentinel-kql/)
- [`03-detection-rules/zeek/`](../03-detection-rules/zeek/)

---

## 🧠 Writeups & Lessons Learned

Reflections and general detection engineering notes:

- [`05-writeups/`](../05-writeups/)

---

Thanks for visiting!  
If you’d like to collaborate or discuss detections, feel free to reach out via GitHub or LinkedIn.
