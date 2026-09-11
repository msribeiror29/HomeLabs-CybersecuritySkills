1.Introduction


Report Introduction - Boogeyman 2, Introduction to the Incident Investigation


   Following previous security incidents, Quick Logistics LLC updated its security posture to defend against known threat vectors. 
 However, the threat actor designated as Boogeyman has returned, employing refined Tactics, Techniques, and Procedures (TTPs) to 
 breach the organization's environment.
   This investigation focuses on analyzing memory volatile artifacts and initial delivery mechanisms to reconstruct the attack 
   execution chain, identify staging infrastructure, and extract technical indicators of compromise (IOCs).

1.1 Scope & Available Artifacts


      The digital forensics and incident response (DFIR) investigation utilizes raw artifacts retrieved from the compromised workstation,
      located within the /home/ubuntu/Desktop/Artefacts directory:
      
      Phishing Artifact: Copy of the malicious email delivered to the victim.
      Memory Image: Volatile memory (RAM) dump extracted from the victim's workstation.


1.2 Analytical Toolset


    The following forensic utilities are deployed to analyze the provided evidence:
    
    Volatility 3: Advanced memory forensics framework used to extract running processes, active network sockets, injected code blocks, and command-line arguments from the RAM image.
    Olevba (Oletools): Static analysis tool leveraged to inspect, extract, and analyze Visual Basic for Applications (VBA) macro scripts embedded within Microsoft Office attachments.


1.3 Investigation Objectives


     - Perform static analysis on the initial email vector and associated attachments.
     - Analyze volatile memory to trace process creation hierarchies, Living-off-the-Land execution, and lateral/C2 network connections.
    Extract inline scripts, secondary payloads, and persistent mechanisms.
     - Synthesize findings into a structured technical report detailing the complete Cyber Kill Chain.

2. Development.

2.1 Spear Phishing Human Resources
Task1 - The Boogeyman is back!


This phase of the investigation focuses on the initial access vector used by the threat actor Boogeyman against Quick Logistics LLC. By targeting Maxine, a Human Resource Specialist, 
the attacker leveraged social engineering disguised as a job application for an open position.
Initial Vector Analysis: Identify the source email address, targeted recipient, and details of the delivery mechanism.
Payload Identification: Inspect the malicious Word attachment (.doc) and calculate its cryptographic hash for threat tracking.
Macro Deobfuscation: Analyze the embedded VBA macro script to locate the initial execution commands and stage 2 download URL.
Volatile Memory Correlation: Trace process creation hierarchies (WINWORD.EXE → wscript.exe → updater.exe) within the RAM memory dump
(WKSTN-2961.raw) to map payload execution in real time.


What email was used to send the phishing email?

      Objective: Identify the sender's email address used by the attacker in the spear-phishing attempt.
      Tool Used: Thunderbird / Email Preview Tool.
      Analysis & Methodology: Opened the provided email file (Resume - Application for Junior IT Analyst Role.eml)
      located in /home/ubuntu/Desktop/Artefacts. Inspected the header fields to analyze the sender's address in the From: line.
      Response: westaylor23@outlook.com 
    
<img width="1126" height="557" alt="Screen Shot 2026-09-09 at 16 29 03" src="https://github.com/user-attachments/assets/2efbfef2-791a-4e42-889f-d8ced71b6563" />

What is the email of the victim employee?

      Objective: Identify the target recipient's email address within the organisation.
      Tool Used: Thunderbird / Email Preview Tool.
      Analysis & Methodology: Inspected the To: header field in the .eml file preview. 
      Identified the Human Resources recipient address targeted by the phishing campaign.
      Response: maxine.beck@quicklogisticsorg.onmicrosoft.com

<img width="690" height="446" alt="Screen Shot 2026-09-09 at 16 30 30" src="https://github.com/user-attachments/assets/6841587f-2052-48d3-9413-44a4dcff3cd5" />

What is the name of the attached malicious document?

      Objective: Determine the filename of the malicious Microsoft Word attachment included with the phishing email.
      Tool Used: Thunderbird / Email Preview Tool.
      Analysis & Methodology: Scrolled to the attachment pane at the bottom of the email preview. Identified the attached .doc file named as a resume.
      Response: Resume_WesleyTaylor.doc

<img width="690" height="446" alt="Screen Shot 2026-09-09 at 16 31 39" src="https://github.com/user-attachments/assets/3aff043b-256e-46a4-ae04-3320ba071cf1" />

What is the MD5 hash of the malicious attachment?

      Objective: Calculate the MD5 cryptographic hash of the extracted malicious attachment for threat intelligence and verification.
      Tool Used: Terminal (md5sum).
      Analysis & Methodology: Navigated to the directory /home/ubuntu/Desktop/Artefacts. Executed md5sum Resume_WesleyTaylor.doc to generate the file digest.
      Response: 52c4384a0b9e248b95804352ebec6c5b

<img width="1143" height="306" alt="Screen Shot 2026-09-09 at 16 37 50" src="https://github.com/user-attachments/assets/75c54ca2-77f7-49ed-a646-bc7f2d899bdc" />

What URL is used to download the stage 2 payload based on the document's macro?

      Objective: Extract and analyze the embedded VBA macro to locate the second-stage download URL.
      Tool Used: olevba (oletools) / Terminal.
      Analysis & Methodology: Ran olevba Resume_WesleyTaylor.doc to inspect embedded macros. Analyzed the extracted Visual Basic script to locate the xHttp.Open "GET", ... network request targeting the payload server.
      Response: https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png

<img width="1006" height="246" alt="Screen Shot 2026-09-09 at 16 43 38" src="https://github.com/user-attachments/assets/313ffd15-2f46-4c52-911d-ad941f22acd7" />

<img width="621" height="150" alt="Screen Shot 2026-09-11 at 20 07 54" src="https://github.com/user-attachments/assets/abdf1bcf-1576-4d23-98e9-f28332cb31c8" />

What is the name of the process that executed the newly downloaded stage 2 payload?

      Objective: Identify the Windows binary responsible for interpreting and executing the downloaded JavaScript stage 2 script (update.js).
      Tool Used: olevba / Volatility 3 (windows.pstree.PsTree).
      Analysis & Methodology:  Examined the script execution code in the macro: shell_object.Exec("wscript.exe C:\ProgramData\update.js"). Confirmed process execution in memory using Volatility process tree output.
      Response: wscript.exe

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 07 02" src="https://github.com/user-attachments/assets/9a733eae-6365-4b9a-8653-62136ecea0db" />

<img width="623" height="51" alt="Screen Shot 2026-09-11 at 20 10 19" src="https://github.com/user-attachments/assets/2d56cb56-6395-4a25-8eee-304f95dfac6d" />

What is the full file path of the malicious stage 2 payload?

      Objective: Determine where the downloaded stage 2 file was written on the target system.
      Tool Used: olevba.
      Analysis & Methodology: Inspected the variable assignment in the macro code: spath = "C:\ProgramData\" and .savetofile spath & "\update.js". Combining the directory path and target filename to establish the full path.
      Response: C:\ProgramData\update.js

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 07 02" src="https://github.com/user-attachments/assets/d5ace5bb-7681-4d84-8d07-949147f5e298" />

<img width="1006" height="246" alt="Screen Shot 2026-09-09 at 16 46 54" src="https://github.com/user-attachments/assets/f817fb42-89d6-4999-803f-59bb4a84fa82" />

What is the PID of the process that executed the stage 2 payload?

      Objective: Identify the Process Identifier (PID) associated with the active wscript.exe instance running update.js.
      Tool Used: Volatility 3 (windows.pstree.PsTree).
      Analysis & Methodology: Executed vol -f WKSTN-2961.raw windows.pstree.PsTree on the memory dump. Located the entry 
      for wscript.exe spawned following Microsoft Word execution.
      Response: 4260

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 07 02" src="https://github.com/user-attachments/assets/199f29ee-672e-4550-9ce1-d750bb6276f7" />

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 09 11" src="https://github.com/user-attachments/assets/87145f95-e9bf-4001-bc01-79deeb0d418c" />

What is the parent PID of the process that executed the stage 2 payload?

      Objective: Identify the Parent Process Identifier (PPID) of wscript.exe (PID 4260).
      Tool Used: Volatility 3 (windows.pstree.PsTree).
      Analysis & Methodology:  Analyzed the process hierarchy generated by windows.pstree.PsTree. Traced wscript.exe (PID 4260) back to its parent process WINWORD.EXE (PID 1124).
      Response: 1124

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 07 02" src="https://github.com/user-attachments/assets/3a8819d5-3438-4fa7-97f8-c6c542d10235" />

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 09 11" src="https://github.com/user-attachments/assets/32bc15f8-b7a7-42ba-b2fe-6129bb048a54" />

What URL is used to download the malicious binary executed by the stage 2 payload?

      Objective: Retrieve the remote download location of the third-stage payload binary initiated by update.js.
      Tool Used: Terminal (strings / grep).
      Analysis & Methodology: Extracted printable strings from the raw memory image matching the attacker domain: strings WKSTN-2961.raw | grep "boogeymanisback". Inspected the full URL path pointing to the executable artifact hosted on the C2 infrastructure.
      Response: https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/updater.exe

<img width="1044" height="84" alt="Screen Shot 2026-09-09 at 17 21 28" src="https://github.com/user-attachments/assets/1ca74d96-dda0-43dd-b0da-c16e76a0456a" />

<img width="1044" height="167" alt="Screen Shot 2026-09-09 at 17 22 07" src="https://github.com/user-attachments/assets/25cb48b4-6d1f-4ea0-ae13-4258b48f6f1a" />

What is the PID of the malicious process used to establish the C2 connection?

      Objective: Identify the process identifier (PID) of the executable responsible for initiating the active network connection to the command-and-control server.
      Tool Used: Volatility 3 (windows.netscan.NetScan).
      Analysis & Methodology: Executed vol -f WKSTN-2961.raw windows.netscan.NetScan to list all network sockets in memory. Located the entry pointing to the C2 server port 8080 associated with updater.exe.
      Response: 6216

<img width="1037" height="134" alt="Screen Shot 2026-09-09 at 17 27 50" src="https://github.com/user-attachments/assets/68a956af-63f8-453f-a580-b861bf84bdec" />

<img width="1129" height="102" alt="Screen Shot 2026-09-09 at 17 32 45" src="https://github.com/user-attachments/assets/f1661c31-2575-4fe5-ae2d-086343d54ed3" />

What is the full file path of the malicious process used to establish the C2 connection?

      Objective: Determine the exact on-disk directory location where the malicious process updater.exe was written and executed.
      Tool Used: Terminal (strings / grep).
      Analysis & Methodology: Ran strings WKSTN-2961.raw | grep "updater.exe" to find host application execution references. Extracted the full directory path C:\Windows\Tasks\updater.exe.
      Response: C:\Windows\Tasks\updater.exe

<img width="1200" height="434" alt="Screen Shot 2026-09-09 at 17 35 01" src="https://github.com/user-attachments/assets/368bd84a-7d55-4afe-8e89-1f0ba8d20bdc" />

What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

      Objective: Extract the destination IP address and remote port of the external Command and Control (C2) node.
      Tool Used: Volatility 3 (windows.netscan.NetScan).
      Analysis & Methodology: Inspected the ForeignAddr and ForeignPort fields corresponding to updater.exe (PID 6216). Identified target IP 128.199.95.189 on port 8080.
      Response: 128.199.95.189:8080

<img width="1200" height="135" alt="Screen Shot 2026-09-09 at 17 35 59" src="https://github.com/user-attachments/assets/d2024c27-07bb-4e94-8f09-f1b919762d46" />

What is the full file path of the malicious email attachment based on the memory dump?

      Objective: Locate the complete file path where Outlook cached the opening of the malicious Word attachment in memory.
      Tool Used: Volatility 3 (windows.filescan.FileScan).
      Analysis & Methodology: Ran vol -f WKSTN-2961.raw windows.filescan.FileScan | grep "Resume_WesleyTaylor" to search for file object pointers in RAM. Extracted the Outlook INetCache directory path corresponding to the target user.
      Response:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc

<img width="1022" height="58" alt="Screen Shot 2026-09-09 at 17 44 17" src="https://github.com/user-attachments/assets/631d82b5-e3e7-4210-b602-f6c7008176dc" />

<img width="1136" height="133" alt="Screen Shot 2026-09-09 at 17 45 38" src="https://github.com/user-attachments/assets/54735151-bea2-440a-af55-67ff65eb7e9b" />

The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

      Objective: Retrieve the complete command executed to schedule a persistent task via PowerShell and schtasks.
      Tool Used: Terminal (strings / grep).
      Analysis & Methodology: Executed strings WKSTN-2961.raw | grep "schtasks /Create" to extract scheduled task creation commands recorded in memory. Isolated the complete command string including parameters for daily execution and encoded payload retrieval.
      Response: schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'

<img width="1192" height="194" alt="Screen Shot 2026-09-09 at 17 52 29" src="https://github.com/user-attachments/assets/f8944be2-064c-4898-a93f-f7bf6b1bb247" />

3. Conclusion

3.1 Incident Investigation Conclusion & Summary


Executive Overview
The forensic analysis of workstation WKSTN-2961 confirms a successful multi-stage compromise initiated via a targeted spear-phishing attack against Quick Logistics LLC's Human Resources department. The threat actor, identified as Boogeyman, weaponized a fake job application email 


targeting HR Specialist Maxine Beck to bypass preliminary perimeter filters and achieve initial code execution.

3.2 Attack Chain Breakdown

<img width="747" height="310" alt="Screen Shot 2026-09-10 at 19 21 30" src="https://github.com/user-attachments/assets/e261f783-67f1-43bf-88f7-496f7ef2857e" />

- Initial Access (Phishing): On August 20, 2023, the attacker sent a spear-phishing email from westaylor23@outlook.com carrying a malicious Word attachment (Resume_WesleyTaylor.doc, MD5: 52c4384a0b9e248b95804352ebec6c5b).


- Execution & Staging: Upon opening the document, embedded VBA macros executed wscript.exe (PID 4260) under WINWORD.EXE (PID 1124). The script retrieved a second-stage JavaScript payload (update.js) saved to C:\ProgramData\update.js.


- Payload Delivery: The stage-2 script fetched the primary C2 binary (updater.exe) from [https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/updater.exe](https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/updater.exe) and wrote it to C:\Windows\Tasks\updater.exe.


- Command & Control (C2): Executed as PID 6216, updater.exe established an active outbound C2 channel to 128.199.95.189:8080.


- Persistence: Following C2 setup, the attacker established persistent access via a daily scheduled task named Updater configured to run an obfuscated PowerShell payload stored within the Windows Registry (HKCU:\Software\Microsoft\Windows\CurrentVersion debug).



3.3 Key Indicators of Compromise (IOCs)

Network IOCs:
- Domain: files.boogeymanisback.lol
- C2 IP Address & Port: 128.199.95.189:8080
- Staging URL: [https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png](https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png)
- Binary URL: [https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/updater.exe](https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/updater.exe)

Host & File IOCs:
- Sender Email: westaylor23@outlook.com
- File Name / MD5: Resume_WesleyTaylor.doc (52c4384a0b9e248b95804352ebec6c5b)
- File Paths: C:\ProgramData\update.js, C:\Windows\Tasks\updater.exe
- Registry Key: HKCU:\Software\Microsoft\Windows\CurrentVersion debug
- Scheduled Task: Updater


3.4 Remediation & Mitigation Recommendations
- Containment: Immediately isolate host WKSTN-2961 from the internal network and revoke credentials for user maxine.beck.


- Remediation: Remove the scheduled task Updater, delete the registry value under HKCU:\Software\Microsoft\Windows\CurrentVersion debug, and purge updater.exe and update.js from system directories.


- Defensive Enhancements: Block outbound TCP connections to 128.199.95.189:8080 and domain *.boogeymanisback.lol at the perimeter firewall/DNS level. Restrict VBA macro execution across Office applications via Group Policy (GPO).
