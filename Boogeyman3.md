

1. Introduction

Report Introduction - Boogeyman 3, Introduction to the Investigation 

Following consecutive security breaches, Quick Logistics LLC outsourced its security operations to a Managed Security Service Provider (MSSP)
to enhance overall threat detection and response capabilities. Despite these elevated security controls, the threat actor Boogeyman has re-emerged, 
executing an updated operational playbook with modified Tactics, Techniques, and Procedures (TTPs) targeting the organization's infrastructure.

This investigation leverages centralized enterprise security telemetry collected within an Elastic Stack (SIEM) instance to trace the attacker's
multi-stage footprint, uncover post-exploitation activities, and analyze advanced persistence mechanisms.


1. Prerequisites & Knowledge Base


To conduct an effective investigation across this room, familiarity with the following core concepts and previous incident history is required:

Elastic Stack Querying (KQL): Navigating indices, filtering log sources (Sysmon, Windows Event Logs, Network traffic), and constructing searches
in Kibana/Elastic SIEM.

Incident History (Boogeyman 1 & 2): Context on the threat actor's preference for spear-phishing initial access vectors, Living-off-the-Land Binaries
(LolBins), scheduled task persistence, and custom C2 staging.

SOC Analyst Methodology: Correlating event IDs, process lineage (ParentImage / Image), and network connections across host and network telemetry.


1.2 Investigation Platform & Log Sources

The deployed lab environment provides browser-based access to an Elastic Stack instance containing ingested host and network telemetry from the
target domain.


Primary SIEM Interface: Kibana (Discover & SIEM modules)

Log Types Ingested:
Sysmon Logs: Process creation (Event ID 1), Network connections (Event ID 3), File creation (Event ID 11), and Registry modifications (Event IDs 12/13/14).
Windows Event Logs: Security, System, and PowerShell Operational logs (Event ID 4104).
Network Telemetry: Web/HTTP proxy logs and DNS query logs.


1.3 Analytical Objectives

Identify Initial Vector: Determine how the threat actor bypassed MSSP monitoring to re-establish access.

Trace Execution & Lateral Movement: Map process execution hierarchies, PowerShell invocation, and internal discovery commands.

Analyze C2 & Exfiltration: Identify C2 domains, IP addresses, custom protocols, or staging methods used for data egress.
Uncover Persistence Mechanisms: Locate modified startup routines, registry run keys, or scheduled tasks set up by the attacker.


2. Development

The initial findings indicate an escalation in the threat actor's tactics, moving from standard malicious macros to container-based evasion mechanisms.

Overview of Initial Artifacts

Spear-Phishing Vector: The attacker leveraged an internal compromised account (allie.sierra@quicklogistics.org) to send a high-priority phishing 
email directly to CEO Evan Hutchinson, requesting an urgent financial review.

<img width="1269" height="490" alt="Screen Shot 2026-09-16 at 19 16 01" src="https://github.com/user-attachments/assets/0cef0126-247e-49b3-9ac2-7668512ec5a0" />

Payload Container Analysis: The attached file ProjectFinancialSummary_Q3.pdf is not an actual PDF, but a disguised Disc Image File (.ISO) designed to bypass 
Mark-of-the-Web (MOTW) security controls upon execution.

<img width="621" height="121" alt="Screen Shot 2026-09-17 at 16 56 26" src="https://github.com/user-attachments/assets/8cf074a7-f3d5-4d1e-80ac-5cff91245058" />

Embedded Payload: Inside the mounted ISO image (DVD Drive (D:)), a disguised executable named ProjectFinancialSummary_Q3.pdf is stored as an HTML Application (.HTA), 
which executes code via mshta.exe when opened.

<img width="621" height="228" alt="Screen Shot 2026-09-17 at 16 56 38" src="https://github.com/user-attachments/assets/4db39e25-6a5c-4839-8358-34c690f9ea6f" />

Task 2 - Initial Access & Execution Analysis

The Boogeyman threat group initiated contact via internal email spoofing/compromise on August 23, 2023, masquerading as CFO Allie Sierra. The target—CEO 
Evan Hutchinson—downloaded and mounted the attached ISO payload on August 29, 2023. Upon double-clicking the file inside the container, double-extension
obfuscation disguised an HTML Application as a legitimate PDF, triggering living-off-the-land execution binaries on the endpoint.

Key Evidence & Visual Artifacts:

    Figure 1: Phishing Email Targeting the CEO
    The email sent from allie.sierra@quicklogistics.org lures the target with an urgent financial document review request.
    
    Figure 2: Downloaded ISO File in Victim's Downloads Folder
    The downloaded file ProjectFinancialSummary_Q3.pdf is identified by Windows as a Disc Image File (.ISO) with a size of 2,208 KB.
    
    Figure 3: Mounted ISO Contents Containing the HTA File
    When mounted as a virtual drive (D:), the container reveals ProjectFinancialSummary_Q3.pdf, which is actually an HTML Application (.HTA).

What is the PID of the process that executed the initial stage 1 payload?

    Objective: Identify the Process Identifier (PID) responsible for spawning the execution of the Stage 1 HTA payload (ProjectFinancialSummary_Q3.pdf.hta).
    Tool Used: Elastic SIEM / Kibana file:(winlogbeat-*).
    Procedure / Executed Steps: Applied KQL search query ProjectFinancialSummary_Q3.pdf to locate all related execution logs within the August 29–30, 
    2023 timeframe. Located the process creation event for mshta.exe executing D:\ProjectFinancialSummary_Q3.pdf.hta. Inspected the parent process 
    fields to identify the parent process ID that spawned the execution from Windows Explorer (explorer.exe).
    Response: 6392

<img width="621" height="217" alt="Screen Shot 2026-09-17 at 16 59 10" src="https://github.com/user-attachments/assets/19f3fca6-8f28-446b-b1c4-c7ac5d0f4aa2" />

<img width="621" height="223" alt="Screen Shot 2026-09-17 at 16 59 48" src="https://github.com/user-attachments/assets/7916febc-932e-4d29-94d4-391ec686a3b2" />

<img width="621" height="291" alt="Screen Shot 2026-09-17 at 17 00 07" src="https://github.com/user-attachments/assets/81416eaf-13f6-405a-a9b4-530678850199" />


The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

    Objective: Extract the complete command line executed by the stage 1 script to copy/implant a payload file into a local temporary folder.
    Tool Used: Elastic SIEM / Kibana, File (winlogbeat-*).
    Procedure / Executed Steps: Filtered logs for process execution events under user evan.hutchinson triggered immediately following the 
    initial mshta.exe execution at 23:51:16. Identified an xcopy.exe execution copying review.dat from the mounted virtual drive D:\ to the user's 
    local AppData\Local\Temp directory.
    Response: "C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

<img width="621" height="291" alt="Screen Shot 2026-09-17 at 17 00 47" src="https://github.com/user-attachments/assets/ec282927-84d0-4b71-a0d4-78f4515be9d9" />

The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

    Objective: Determine the full command line used to execute the implanted review.dat file via a Living-off-the-Land binary.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Inspected process creation logs occurring right after the xcopy.exe file copy action. Located a rundll32.exe 
    execution invoked directly by mshta.exe to register and run D:\review.dat via DllRegisterServer.
    Response: "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

<img width="621" height="266" alt="Screen Shot 2026-09-17 at 17 01 39" src="https://github.com/user-attachments/assets/84af8d7f-5ee8-4a5b-8dae-d1da9afa93bf" />

The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

    Objective: Identify the specific task name assigned to the scheduled task created by the malicious script for persistent execution.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Analyzed PowerShell process creation logs (powershell.exe) executing scheduled task cmdlet syntax (Register-ScheduledTask). Identified the -TaskName parameter value passed to Register-ScheduledTask within the PowerShell command line.
    Response: Review

<img width="621" height="248" alt="Screen Shot 2026-09-17 at 17 02 21" src="https://github.com/user-attachments/assets/3cdaf6ad-9045-4938-a76f-3917a47370f5" />

The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? 
(format: IP:port)

    Objective: Extract the remote C2 IPv4 address and target port associated with the outbound network activity initiated post-exploitation.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered Sysmon network connection events (Event ID 3) using KQL query event.provider: "Microsoft-Windows-Sysmon" 
    and event.code: "3" and user.name: "evan.hutchinson". Isolated outbound HTTP/TCP traffic establishing continuous outbound sockets to remote 
    IP 165.232.170.151 on port 80.
    Result / Answer: 165.232.170.151:80

<img width="621" height="288" alt="Screen Shot 2026-09-17 at 17 08 04" src="https://github.com/user-attachments/assets/464d73a8-876f-4002-8deb-8441a3a92dfd" />

The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

    Objective: Identify the process binary leveraged to bypass User Account Control (UAC) to elevate execution privileges.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Analyzed execution events triggered right after DLL registration via rundll32.exe. Observed process creation logs running 
    fodhelper.exe auto-elevated by rundll32.exe, taking advantage of the Windows fodhelper UAC bypass technique (ATT&CK T1548.002).
    Response: fodhelper.exe

<img width="621" height="306" alt="Screen Shot 2026-09-17 at 17 09 04" src="https://github.com/user-attachments/assets/8d65df01-a1c6-4c80-ba98-d5fbb3063876" />

<img width="621" height="292" alt="Screen Shot 2026-09-17 at 17 09 20" src="https://github.com/user-attachments/assets/e6fb3ba2-98f1-49fa-bf2e-7cd000127a22" />

Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker 
to download a tool for credential dumping?

    Objective: Retrieve the exact GitHub download URL specified in the malicious command line used to pull the credential dumper onto the host.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered PowerShell command-line events searching for string pattern github.com. Located an Invoke-WebRequest (iwr) 
    <img width="620" height="203" alt="Screen Shot 2026-09-17 at 17 21 44" src="https://github.com/user-attachments/assets/ed546f08-eb0d-4400-8afb-a7dfdecd5303" />
cmdlet invocation downloading a Mimikatz release package directly into mimikatz_trunk.zip.
    Response: https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

<img width="621" height="292" alt="Screen Shot 2026-09-17 at 17 10 47" src="https://github.com/user-attachments/assets/34b9cda2-abe7-4b77-b27f-d0fb70e412fb" />

After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. 
What is the username and hash of the new credential pair? (format: username:hash)

    Objective: Identify the domain user account and corresponding NTLM hash extracted via Mimikatz pass-the-hash (sekurlsa::pth).
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered process command-line logs for executions of mimikatz.exe. Inspected the command arguments for sekurlsa::pth, 
    extracting the target account /user: and NTLM hash /ntlm:.
    Response: itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

<img width="621" height="245" alt="Screen Shot 2026-09-17 at 17 11 33" src="https://github.com/user-attachments/assets/625b6054-2b25-4294-85a1-d0c35c05cc55" />

Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a 
remote share?

    Objective: Determine the specific file retrieved/read by the attacker across network file shares.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Executed search query host.name: "WKSTN-0051.quicklogistics.org" and powershell.exe and *File*. Found Get-Content (cat) 
    executions accessing the remote file share path \\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1.
    Response: IT_Automation.ps1

<img width="624" height="292" alt="Screen Shot 2026-09-17 at 17 12 32" src="https://github.com/user-attachments/assets/4a76bde1-7730-45cc-b757-d5d82028f743" />

After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered 
by the attacker? (format: username:password)

    Objective: Identify the cleartext credentials embedded within the scripts/files retrieved by the attacker and subsequently used to instantiate 
    PSCredential objects.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Searched logs for query host.name: "WKSTN-0051.quicklogistics.org" and powershell.exe and *credential*. Located 
    PowerShell execution establishing a $Credential object with domain user QUICKLOGISTICS\allan.smith and cleartext password 'Tr!ckyP@ssw0rd987'.
    Response: allan.smith:Tr!ckyP@ssw0rd987

<img width="624" height="292" alt="Screen Shot 2026-09-17 at 17 13 12" src="https://github.com/user-attachments/assets/5c6376f7-8d3b-4c0c-88fb-9fa70643de26" />

What is the hostname of the attacker's lab machine for its lateral movement attempt?

    Objective: Extract the remote destination hostname targeted by the attacker during the lateral movement execution.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Inspected the -ComputerName parameter specified inside the Invoke-Command execution string. Identified the target remote
    system name passed to the cmdlet.
    Response: WKSTN-1327

<img width="624" height="292" alt="Screen Shot 2026-09-17 at 17 13 47" src="https://github.com/user-attachments/assets/e33d488a-0d3e-4d40-974f-0d22ae577306" />

Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command 
executed on the second compromised machine?

    Objective: Identify the parent process name handling remote PowerShell execution (Invoke-Command / WinRM) on the target host WKSTN-1327.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered Sysmon Event ID 1 (Process Creation) logs on host WKSTN-1327.quicklogistics.org. Inspected the process 
    tree attributes for the incoming remote command to find process.parent.name.
    Response: wsmprovhost.exe

<img width="620" height="203" alt="Screen Shot 2026-09-17 at 17 22 22" src="https://github.com/user-attachments/assets/23845224-9586-461f-b2aa-2f0ed2ed82de" />

<img width="624" height="295" alt="Screen Shot 2026-09-17 at 17 22 45" src="https://github.com/user-attachments/assets/20801353-a081-41b6-9ecb-7cf783a3055b" />

<img width="624" height="252" alt="Screen Shot 2026-09-17 at 17 23 04" src="https://github.com/user-attachments/assets/4a0eb381-cfd9-443f-855c-89dec4bef4f6" />

The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

    Objective: Extract the username and NTLM hash targeted during pass-the-hash or credential extraction on host WKSTN-1327.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered Sysmon process creation logs on WKSTN-1327.quicklogistics.org for mimikatz.exe. Analyzed 
    the command line arguments passed to sekurlsa::pth to capture /user: and /ntlm:.
    Response: administrator:00f80f2538dcb54e7adc715c0e7091ec

<img width="624" height="285" alt="Screen Shot 2026-09-17 at 17 24 04" src="https://github.com/user-attachments/assets/95417e85-2bbd-4df7-ae14-ed2e20eb9d22" />

After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, 
what account did the attacker dump?

    Objective: Identify the secondary account targeted via lsadump::dcsync on DC01.quicklogistics.org.
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Filtered process logs on DC01.quicklogistics.org containing mimikatz.exe. Inspected the /user: parameter associated with lsadump::dcsync commands.
    Response: backupda

<img width="624" height="279" alt="Screen Shot 2026-09-17 at 17 50 00" src="https://github.com/user-attachments/assets/7a6a5b7a-cd16-4992-8c39-0fa57e60f1c6" />

<img width="624" height="245" alt="Screen Shot 2026-09-17 at 17 50 29" src="https://github.com/user-attachments/assets/c9485a4d-5fd5-4a02-926c-aba98ff8d9b2" />

After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

    Objective: Locate the direct URL utilized in the PowerShell download command (iwr) for fetching the ransomware payload (ransomboogey.exe).
    Tool Used: Elastic SIEM / Kibana (winlogbeat-*).
    Procedure / Executed Steps: Executed a KQL query on host DC01.quicklogistics.org filtering for Sysmon Event ID 1 and powershell.exe. Extracted the
    full download link specified inside the iwr (Invoke-WebRequest) cmdlet argument.
    Response: http://ff.sillytechninja.io/ransomboogey.exe


<img width="624" height="268" alt="Screen Shot 2026-09-17 at 17 51 14" src="https://github.com/user-attachments/assets/f0373f36-b501-475c-8316-910ee273f3ec" />

3. Conclusion
   
   
Incident Summary & Investigation Conclusion

The Boogeyman 3 incident investigation details a full kill-chain execution—from initial access via drive-by/social engineering through local elevation, 
credential harvesting, lateral movement, domain compromise, and final stage ransomware deployment.

3.1 Key Attack Stages & Findings

Initial Access & Staging:
The compromise originated via explorer.exe executing an initial HTA payload (ProjectFinancialSummary_Q3.pdf.hta under PID 6392). The script implanted a 
malicious dynamic-link library (review.dat) into AppData\Local\Temp using xcopy.exe before executing it through rundll32.exe (DllRegisterServer). 
Persistence was immediately maintained via a scheduled task named Review.

Command & Control (C2) & Defense Evasion:

An outbound C2 channel was established to 165.232.170.151:80. Recognizing local administrator privileges, the attacker executed a UAC bypass leveraging 
fodhelper.exe to elevate execution context.

Credential Harvesting & Initial Lateral Movement:
Using elevated privileges, the attacker downloaded Mimikatz from GitHub https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip 
and performed pass-the-hash (sekurlsa::pth) using the itadmin hash (F84769D250EB95EB2D7D8B4A1C5613F2). They enumerated network file shares, retrieved \\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1,
and uncovered plain-text credentials for allan.smith:Tr!ckyP@ssw0rd987.

Lateral Movement & Domain Escalation:
The attacker leveraged PowerShell WinRM (Invoke-Command) to move laterally to host WKSTN-1327 (where remote commands ran under the parent process
wsmprovhost.exe). On WKSTN-1327, Mimikatz was re-executed to extract domain administrator hashes Administrator: 00f80f2538dcb54e7adc715c0e7091ec.

Domain Compromise & Final Impact:
With Domain Admin context established on DC01.quicklogistics.org, a DCSync attack (lsadump::dcsync) was launched to dump active domain credentials,
explicitly targeting the backupda account. Finally, the attacker downloaded and prepared to execute the ransomware binary from 
http://ff.sillytechninja.io/ransomboogey.exe.


3.2 Recommended Remediation Steps

Host Isolation & Eradication: Immediately isolate affected hosts (WKSTN-0051, WKSTN-1327, and DC01) from the network. Terminate active remote management
sessions and remove the scheduled task Review.

Credential Revocation: Perform an immediate domain-wide password reset for all compromised accounts (itadmin, allan.smith, administrator, and backupda). 
Rotate the krbtgt account password twice.

Network & Domain Hardening: Block network communication to remote indicators (165.232.170.151 and ff.sillytechninja.io). Restrict WinRM/PSRemoting access
between workstations, enforce LAPS for local administrator accounts, and restrict UAC auto-elevation capabilities.



































