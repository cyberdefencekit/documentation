# Splunk Cheat Sheet

## **About this Cheat Sheet**

This cheat sheet is aimed at **beginner-level users** and covers **common detection use cases and queries** in Splunk. It’s designed to help you get started with threat hunting and understand how to search for suspicious activity using log data.

## **Note on Indexes:**

The example queries use `index=windows`, but the actual index name in your environment may be different.

If you are unsure, try running:

```
index=*
```

This will search across all indexes and help you identify the correct one. Once confirmed, update your queries accordingly.

## Authentication & Access

### **Successful RDP Login**

*This looks for successful Remote Desktop (RDP) logins.*

**Logon_Type=10** means the login came from a remote computer.

You can track who logged in, from where, and when.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count by _time, user, host, src_ip
```

### **Failed Logons (Brute-force Detection)**

*Finds users or IPs trying to log in multiple times and failing.*

If someone fails to log in over 5 times, it might be a brute-force attempt.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by user, src_ip, host
| where count > 5
```

### **Pass-the-Hash or Lateral Movement**

*Searches for logins that may come from other computers on the network.*

**Logon_Type=3** is a network logon (e.g. file share), **Logon_Type=9** is for using stored credentials.

Useful for spotting movement between systems by attackers.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4624
| search Logon_Type=3 OR Logon_Type=9
| table _time, user, Logon_Type, src_ip, host
```

## Execution

### **Suspicious Process Creation (cmd, powershell)**

*Looks for command-line tools like PowerShell or cmd.exe being used.*

These tools are often abused by attackers to run scripts or commands silently.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe" OR Image="*cmd.exe"
| stats count by user, host, Image, CommandLine
```

### **Encoded PowerShell Execution**

*Detects when PowerShell scripts are run with encoded commands.*

This is commonly used to hide what the script is really doing.

```
index=windows EventCode=4104
| search Message="*EncodedCommand*"
| table _time, Message, host
```

### **UAC Bypass Attempt**

*Searches for command lines that mention "bypass".*

**UAC (User Account Control)** is a Windows security feature.

Attackers try to bypass it to run admin-level commands without warning the user.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*bypass*"
| table _time, host, Image, CommandLine
```

## File Activity

### **File Drop Detection**

*Tracks when files are created on the system.*

Useful for spotting malware being dropped in user folders.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| table _time, host, user, TargetFilename, Image
```

### **Executable Run from Temp Directory**

*Looks for programs being run from temporary folders.*

Legitimate software doesn’t usually run from these locations which is a common red flag.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\AppData\\Local\\Temp\\*" OR Image="*\\Temp\\*"
| table _time, Image, CommandLine, user, host
```

## Network Connections

### **Network Connections (Sysmon)**

*Shows what network connections are being made.*

Great for spotting suspicious outbound connections to strange IPs or ports.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by _time, SourceIp, DestinationIp, DestinationPort, host, Image
```

## Privilege Escalation & Persistence

### **Privilege Escalation - SeDebugPrivilege**

*Detects when a user gets a special permission called SeDebugPrivilege.*

This allows someone to inspect or control other processes which is often abused by attackers.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4672
| search privilege_list="SeDebugPrivilege"
| table _time, user, host, privilege_list
```

### **New Local Admin Account Created**

*Looks for new user accounts that are added to the Administrators group.*

Attackers often create their own admin users to keep access.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4720
| search "Account Name"="*" AND "Account Domain"="*Administrators*"
| table _time, host, "Account Name", user
```

### **Registry Autoruns Modified**

*Checks if anything was added to registry keys that auto-run programs on startup.*

A common way malware sets itself to run every time the computer boots.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 OR EventCode=14
| search TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*"
| table _time, Image, TargetObject, host
```

### **Remote Scheduled Task Created**

*Finds when someone creates a scheduled task remotely.*

Attackers use this to run malware or scripts at set times on target systems.

```
index=windows sourcetype="WinEventLog:Security" EventCode=4698
| table _time, user, host, TaskName, Command
```

## Lateral Movement & LOLBAS

### **PsExec or Remote Admin Tool Usage**

*Detects use of PsExec or similar tools that let someone run commands on another computer.*

Often used by IT staff or attackers once inside the network.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*psexec*" OR CommandLine="*\\\\*\\\\ADMIN$*"
| table _time, user, host, CommandLine
```

### **Living Off The Land Binaries (LOLBAS)**

*Looks for built-in Windows programs like rundll32, regsvr32, and mshta being used.*

**LOLBAS (Living Off the Land Binaries and Scripts)** are legitimate tools abused by attackers to avoid detection.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*mshta.exe"
| table _time, Image, CommandLine, user, host
```

## Anomaly Detection

### **Rare Parent-Child Process Pair**

*Finds uncommon combinations of parent and child processes.*

For example, if Notepad.exe launches PowerShell, that is suspicious.

Low-frequency pairs often point to unusual activity worth checking out.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by ParentImage, Image
| where count < 3
```

## Credential Access

### **Cleartext Passwords in Command Line**

*Detects PowerShell or scripts that include the word “password”.*

Attackers sometimes use scripts that include credentials, especially during testing or automation.

```
index=windows EventCode=4104
| search CommandLine="*password*"
| table _time, host, user, CommandLine
```

### **Suspicious Access to LSASS Process (Mimikatz)**

*Checks if a process is trying to access LSASS, which stores Windows credentials.*

Tools like Mimikatz do this to extract passwords from memory.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search TargetImage="*lsass.exe"
```

## Defense Evasion

### **Suspicious DLL or Image Loaded**

*Looks for programs loading DLLs from temporary or user folders.*

This is unusual for legitimate software and often used to hide malicious code.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| search ImageLoaded="*\\temp\\*" OR ImageLoaded="*\\AppData\\*"
```

## Exfiltration

### **Unusual Data Transfer Tools in Use**

*Detects signs of data being transferred or uploaded via tools like certutil.*

Attackers sometimes use built-in tools to send stolen data out.

```
index=windows EventCode=4104
| search CommandLine="*certutil*" OR CommandLine="*upload*"
```

## Phishing or Document-Based Attacks

### **Microsoft Word Launching PowerShell**

*Looks for suspicious process chains like Word starting PowerShell.*

This often means a malicious macro or document is being used in a phishing attack.

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search ParentImage="*winword.exe" AND Image="*powershell.exe"
```