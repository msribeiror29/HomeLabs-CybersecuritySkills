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

##2.1 Preparation - Tools and artefacts.
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

###Artefact File: windows.evtx
Type Description: Windows Event Logs
SHA-256 Hash Value:
D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60

