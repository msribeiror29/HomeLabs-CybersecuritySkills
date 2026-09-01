
1.Introduction

#Report Introduction - Boogeyman 1, Threat Investigation

This investigation report documents the analysis of a multi-stage intrusion executed by an emerging threat actor group known as Boogeyman. targeting an enterprise workstation. The objective of this investigation is to trace the complete cyber kill chain—from initial access via targeted spear-phishing to post-exploitation actions, command-and-control (C2) communication, and data exfiltration.

Through detailed forensic analysis of email message files, Windows PowerShell Event Logs, and network packet captures, this report provides a comprehensive breakdown of the threat actor’s Tactics, Techniques, and Procedures (TTPs) aligned with the MITRE ATT&CK framework.

#1.1 Scope and Environment of Investigation

The investigation was conducted within an isolated analysis virtual machine (/home/ubuntu/Desktop/artefacts) simulating a Security Operations Center (SOC) Level 1 triage workstation. The investigation was focused on the endpoint assigned to user Julianne Westcott (julianne.westcott@hotmail.com) following a suspicious email receipt.

#Forensic Artifacts Analyzed

dump.eml: Raw RFC 822 formatted phishing email containing original headers and a Base64-encoded encrypted attachment.
powershell.json: JSON-formatted log collection extracted from Windows PowerShell Event Logs (Event ID 4104 - Script Block Logging) via evtx2json.
capture.pcapng: Complete network traffic capture recorded from the victim workstation during the active compromise window.


#1.2.1 Tools and Technologies Applied.

The analysis relied on a combination of dedicated forensic tools and core Linux command-line utilities:


#Primary Analysis Tools

Thunderbird: Graphical email client used for inspecting structured MIME components, message headers, and initial payload extraction.
LNKParse3: Forensic Python package used to parse and extract metadata, relative paths, and embedded command-line arguments from Windows shortcut (.lnk) binary files.
Wireshark & Tshark: GUI and CLI packet analysis engines used to inspect network streams, reconstruct HTTP/C2 transactions, and carve exfiltrated payloads.
jq: Lightweight command-line JSON processor used to query, filter, sort, and parse structured log entries within powershell.json.
Supporting Command-Line Utilities
grep / sed / awk: Used for rapid string searching, text manipulation, and filtering noisy execution logs.
base64: Used to decode embedded payloads from email attachments and obfuscated PowerShell commands.


#2. Development.

#2.1 Email Analysis & Initial Access Investigation
Task 1 - The Boogeyman is here!
Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from a business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation. The security team flagged the suspicious execution of the attachment alongside reports from other finance department employees, indicating a targeted spear-phishing attack.

