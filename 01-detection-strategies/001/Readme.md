# Detecting Prevelant Techniques

## Inspiration & Context

This detection engineering exercise was inspired by a talk at ATT&CKcon titled “What the Adversary Taught Me: Using MITRE ATT&CK to Identify TTP Trends and Prioritize Detections” by Krysta Horocofsky and Connor Kovacs from Recorded Future’s Insikt Group. Link to [Presentation](https://mitre.app.box.com/s/3lynwg8ebc80lolprvz144ev8n04p19v/file/2025241729734).

During the presentation, they demonstrated how their intelligence analysis identified **Ingress Tool Transfer** (T1105) and ****Application Layer Protocol: Web Protocols** (T1071.001)** as two techniques that frequently appear together across real-world threat activity. 

Motivated by this example, I wanted to test my detection engineering ability by building and validating a behavioral detection rule in my home lab using ELK, focusing on PowerShell based payload staging over web protocols and mapping the detection directly to MITRE ATT&CK techniques.
