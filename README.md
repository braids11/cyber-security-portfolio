# detection-engineering-portfolio
My MITRE ATT&amp;CK Detection Strategies Portfolio

# Detection Engineering Portfolio  
*A hands-on lab-driven exploration of MITRE ATT&CK and MITRE CAR analytics.*

This repository contains my personal detection engineering lab, where I:
- Build and run a virtual detection lab
- Reproduce adversary behavior from MITRE ATT&CK
- Implement and document MITRE CAR analytics
- Capture and analyze network/host telemetry
- Develop detection logic (Sigma, KQL, SPL, EQL, Zeek scripts)
- Produce detailed writeups, evidence, and tuning notes

---

## 🔬 Lab Overview

I am building a full detection lab using:
- Mac Mini 2018 running ESXi
- Windows 10 endpoint
- Windows Server
- Kali Linux attacker
- Sysmon + Windows Event Logging
- (Optional) Zeek, Elastic, or Splunk

The lab will evolve as I complete more analytics and experiments.

---

## 📂 Repository Structure
00-lab-architecture/ → Lab diagrams & host details
01-car-analytics/ → MITRE CAR challenges + full writeups
02-attack-simulations/ → MITRE ATT&CK technique reproduction
03-detection-rules/ → Sigma, KQL, SPL, EQL, Zeek
04-telemetry-experiments/→ Sysmon, Event Logs, Zeek logs
05-writeups/ → General detection engineering articles


---

## 📘 MITRE CAR Analytics Progress

| CAR ID | Analytic Name | Status |
|-------|---------------|--------|
| CAR-2013-09-003 | SMB Session Setups | 🔜 Planned |
| CAR-2014-04-001 | Suspicious Process Injection | 🔜 Planned |
| CAR-2016-03-001 | Registry Persistence | 🔜 Planned |

I will update this table as I complete each challenge.

---

## 🎯 Goals

- Practice hands-on detection engineering  
- Produce unique, original lab data and analysis  
- Build a strong portfolio for SOC / Threat Hunting / Detection Engineering roles  

---
