# Detection Engineering Portfolio Overview

This document summarizes the scope and goals of my detection engineering portfolio, focused on MITRE ATT&CK and MITRE CAR.

---

## Objectives

- Build practical, hands-on experience in detection engineering.
- Demonstrate the ability to:
  - Design and run a lab environment.
  - Reproduce adversary behaviors from ATT&CK.
  - Capture and analyze telemetry (network + host).
  - Develop and tune detection logic for multiple tools.
  - Communicate clearly through structured writeups.

---

## Lab Summary

- **Platform:** Mac Mini 2018 running ESXi  
- **Core VMs:**
  - Kali Linux – attacker
  - Windows 10 – endpoint
  - Windows Server – SMB/file server / optional DC
  - Optional: Zeek sensor and/or Elastic Stack

Telemetry sources:

- Windows Event Logs (Security, System, etc.)
- Sysmon
- Network captures (pcap)
- Zeek logs (conn.log, smb_cmd.log, etc.)

---

## Work Streams

### 1. MITRE CAR Analytics

Each CAR analytic is treated as a “challenge”:

1. Understand the analytic and mapped ATT&CK techniques.
2. Reproduce relevant behaviors in my lab.
3. Capture network and host telemetry.
4. Implement detection logic in one or more formats:
   - Sigma
   - Splunk SPL
   - Sentinel KQL
   - Elastic EQL
   - Zeek scripts
5. Document analysis, limitations, and improvements.

See: `01-car-analytics/`.

---

### 2. ATT&CK Technique Simulations

Independently of CAR, I simulate specific ATT&CK techniques to understand:

- What they look like on the wire.
- How they appear in logs.
- How to detect and hunt for them.

See: `02-attack-simulations/`.

---

### 3. Detection Rules Library

Reusable detection logic, organized by format:

- Sigma rules (tool-agnostic)
- Splunk queries
- Sentinel KQL queries
- Elastic EQL queries
- Zeek scripts

See: `03-detection-rules/`.

---

### 4. Telemetry Experiments

Experiments around:

- Sysmon configuration and coverage.
- Windows Event ID behaviors.
- Zeek log fields and protocol coverage.

See: `04-telemetry-experiments/`.

---

## Target Roles

This portfolio is designed to support roles such as:

- Detection Engineer  
- Threat Hunter  
- SOC Analyst (Tier 2/3)  
- Security Engineer with a focus on logging/detections  

---

## Future Plans

- Expand coverage across more CAR analytics.
- Add ATT&CK Navigator layer representing my coverage.
- Integrate SIEM dashboards and example alerts.
- Explore cloud-native and identity-centric detections (Azure AD/Entra, O365, etc.).

