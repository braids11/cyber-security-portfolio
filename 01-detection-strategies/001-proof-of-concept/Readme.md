# Detecting PowerShell Payload Staging via Web Protocols

> **Estimated Read Time:** ~3 minutes 

## Summary

This proof-of-concept detection identifies PowerShell commands launched from
`cmd.exe` that stage payloads by retrieving content over web protocols and
writing it to disk. It is based on Sysmon process creation telemetry collected
from a Windows 11 endpoint in a self-hosted Elastic Stack lab and is intended
to demonstrate practical detection engineering workflows rather than
production-ready coverage.


## Inspiration & Context

This detection engineering exercise was inspired by a talk at ATT&CKcon titled “What the Adversary Taught Me: Using MITRE ATT&CK to Identify TTP Trends and Prioritize Detections” by Krysta Horocofsky and Connor Kovacs from Recorded Future’s Insikt Group.

During the [presentation](https://mitre.app.box.com/s/3lynwg8ebc80lolprvz144ev8n04p19v/file/2025241729734), they demonstrated how their intelligence analysis identified [Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1544) and [Application Layer Protocol: Web Protocols (T1071.001)](https://attack.mitre.org/techniques/T1071/001/) as two techniques that frequently appear together across real world threat activity. 

Motivated by this example, I selected this technique pairing as a starting point to evaluate my detection engineering approach by building and validating a behavior-based detection rule in a controlled home lab using the Elastic Stack. The detection focuses on PowerShell-based payload staging over web protocols and is mapped to MITRE ATT&CK techniques.

## MITRE ATT&CK Mapping

[Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1544)

[Application Layer Protocol: Web Protocols (T1071.001)](https://attack.mitre.org/techniques/T1071/001/)

## Threat Context


## Data Sources

- Sysmon Event ID 1 (Process Create)
- Telemetry collected via Filebeat -> Logstash -> Elasticsearch

## Detection Logic (KQL)
Detects Sysmon process creation events where PowerShell is launched
from cmd.exe and executes a web request that writes a file to disk.
```kql
channel: "Microsoft-Windows-Sysmon/Operational"
and event_id: "1"
and winlog.event_data.ParentImage: "*\\cmd.exe"
and winlog.event_data.CommandLine: "*powershell*"
and winlog.event_data.CommandLine: "*Invoke-WebRequest*"
and winlog.event_data.CommandLine: "*OutFile*"
```

## Implementation


## Validation

The detection was validated by executing the following PowerShell command
on the Windows endpoint, which successfully triggered an alert:

```cmd
powershell -Command Invoke-WebRequest -Uri 'https://github.com/…' `
-OutFile 'C:/Users/LabUser/Desktop/readme.txt'; `
Start-Process -FilePath 'C:/Users/LabUser/Desktop/readme.txt'

```

## False Positives & Limitations
- Legitimate administrative PowerShell usage may trigger this detection.
- No allowlisting or user-based filtering is applied.
- Detection is limited to process creation telemetry.

## Future Improvements
- Introduce allowlisting for known administrative scripts.
- Correlate with network telemetry for destination validation.
- Normalize to ECS process fields.

## Lab Setup & Execution

![PowerShell web download execution](evidence/powershell_execution.png)

![ELK Rule](evidence/001-Rule.png)

[Document Value](evidence/ElasticDocument.md)


## References 
