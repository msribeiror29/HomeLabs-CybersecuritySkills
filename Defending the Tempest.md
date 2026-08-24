#1. Introduction

Report Introduction - Defending the Tempest: SOC Log Analysis and Incident Response.

This report documents the investigation and forensic analysis conducted in the Tempest challenge, part of the SOC Level 1 Capstone Challenges module of TryHackMe. The main objective of this exercise is to simulate a real Incident Response (IR) investigation, analyzing the complete attack chain executed against a compromised workstation.
As a member of the Incident Response team, the mission consisted of examining the artifacts collected from the affected asset—including endpoint logs and network traffic captures—in order to reconstruct the chronology of events, identify the origin of the threat, the vectors of compromise, and the extent of the malicious actions performed by the attacker.


1.1 Scope and Environment of Investigation
The analysis was conducted directly in a controlled environment based on the meticulously correlated examination of network and system data.
Affected Asset: Tempest workstation (Windows operating system).
Scope of Analysis: Forensic investigation of endpoint logs and network traffic logs generated during the incident.


1.2 Tools and Technologies Applied.
Endpoint Log Analysis: Windows Event Logs and Sysmon (for identifying process creation, persistence, and suspicious connections).
Network Traffic Analysis: Wireshark (operations and detailed packet inspection) and Brim (rapid triage of data flows and network alerts).



2. Development.

2.1 Preparation - Tools and artefacts.
Task 1: Artefact Preparation and Integrity Verification

Before launching the investigation, it is critical in digital forensics to prepare the environment and verify the integrity of all collected evidence. Verifying files via cryptographic hashes ensures the artefacts have not been altered or corrupted during acquisition or analysis, guaranteeing data authenticity throughout the Incident Response lifecycle.

Artefact Hash Verification: Using PowerShell, SHA-256 hashes were generated for all evidence files stored in C:\Users\user\Desktop\Incident Files\ via the Get-FileHash cmdlet:
Command Executed: Get-FileHash -Algorithm SHA256 .\*.*
Objective: Establish a baseline hash for each artefact to guarantee data integrity prior to analysis.

Artefact File: capture.pcapng
Type / Description: Network Packet Capture
SHA-256 Hash Value:
CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6

Artefact File: sysmon.evtx
Type Description: Sysmon Event Logs
SHA-256 Hash Value:
665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F

Artefact File: windows.evtx
Type Description: Windows Event Logs
SHA-256 Hash Value:
D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60

<img width="603" height="244" alt="Screen Shot 2026-08-24 at 17 14 09" src="https://github.com/user-attachments/assets/844ba6d9-100a-4b36-b1d4-c975702e9417" />

2.2 Toolset Overview & Log Parsing Execution.
To process the forensic evidence effectively, a dedicated suite of endpoint and network analysis tools was deployed. Specialized utilities from Eric Zimmerman's EZTools suite were leveraged to convert raw Event Logs into easily filterable structured data.
Endpoint Analysis Suite: EvtxEcmd, Timeline Explorer, SysmonView, Event Viewer.
Network Analysis Suite: Wireshark, Brim.
EVTX Log Parsing with EvtxEcmd & Timeline Explorer
Raw Windows Event Logs (.evtx) were parsed into CSV format to enable rapid filtering, sorting, and timeline analysis within Timeline Explorer.
EvtxEcmd Execution:
Command Executed: .\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
Result: Successfully parsed 2,559 event log records from sysmon.evtx into sysmon.csv in 14.52 seconds.

Parsed Event Metrics:
Event ID 1 (Process Creation): 238
Event ID 3 (Network Connection): 92
Event ID 11 (File Created): 1,024
Event ID 12/13 (Registry Object/Value Modifications): 1,055
Event ID 22 (DNSEvent): 136

<img width="603" height="415" alt="Screen Shot 2026-08-24 at 17 21 17" src="https://github.com/user-attachments/assets/b7dc4322-b047-4ad3-9bcb-d1eb7b792e28" />



