# Velociraptor Cheat Sheet

## **About this Cheat Sheet**

This cheat sheet is aimed at **beginner-level users** and covers **common use cases and artifacts in Velociraptor**. It’s designed to help you get started with threat hunting and understand how to collect evidence and investigate suspicious activity on endpoints.

## **Note on Parameters**

Many Velociraptor artifacts include parameters like `TargetGlob`, `Path`, or `Hash`. These need to be adjusted to suit your environment. For example:

```
TargetGlob: C:/Users/**/*.exe
```

This pattern tells Velociraptor to search for any `.exe` files inside all user folders. Be sure to update paths and filters based on what you're looking for.

## Endpoint Visibility and Forensics

### **List Running Processes**

*Shows which programs and background tasks are currently running on a system.*

This helps identify suspicious tools or malware that may be active in memory.

```
Artifact: Windows.System.Pslist
Parameters: None
```

### **Browse the File System**

*Lets you explore folders and files on an endpoint, similar to File Explorer.*

This is useful when you want to manually check for suspicious files or collect samples.

```
Artifact: Windows.FileSystem.ListDirectory
Parameters:
- Path: e.g. C:\Users\Public\Downloads
```

### **View Prefetch Files**

*Displays a list of programs that were run recently, even if they were deleted.*

Windows automatically creates small files called **Prefetch** files to help programs start faster. These files can be helpful in showing what the attacker executed.

```
Artifact: Windows.Executables.Prefetch
Parameters: None
```

## File and IOC Hunting

### **Search for a File by Name**

*Finds files across the system based on a name or file path pattern.*

Use this to locate dropped malware or attacker tools (e.g. anything ending in `.exe` or `.ps1`).

```
Artifact: Generic.Files.Search
Parameters:
- TargetGlob: C:/Users/**/*.exe
```

### **Search by File Hash**

*Checks if a file on the system matches a known bad file by its hash value.*

A **hash** is like a fingerprint of a file. You can get known bad hashes from threat intel sites like VirusTotal.

```
Artifact: Generic.Files.Hash
Parameters:
- TargetGlob: C:/Users/**/*
- Hash: paste in a known SHA256 or MD5 hash
```

### **Scan Files with YARA Rules**

*Looks for suspicious files based on patterns written in a tool called YARA.*

**YARA** is used by malware analysts to create rules that detect known malware behaviour inside files, even when names and hashes change.

```
Artifact: Windows.Detection.Malware.Yara
Parameters:
- FileGlob: C:/Users/**/*
- Upload or select a YARA rule
```

## Registry and Persistence

### **Check Registry Autoruns**

*Finds programs that are set to run automatically when the system starts.*

Malware often adds itself to **registry keys** to make sure it runs every time the computer boots.

```
Artifact: Windows.Registry.Keys
Parameters:
- KeyGlob: HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Run
```

## Network and DNS

### **List Active Network Connections**

*Shows which programs are making network connections, and to which IP addresses or ports.*

This can help identify suspicious communication with attacker-controlled infrastructure.

```
Artifact: Windows.Network.Netstat
Parameters: None
```

### **Check DNS Cache**

*Displays a list of domains or websites the system recently looked up.*

This can help you spot connections to suspicious command-and-control servers or phishing domains.

```
Artifact: Windows.DNS.ClientCache
Parameters: None
```

## User and Browser Activity

### **Collect Browser History**

*Shows websites visited by the user in browsers like Chrome or Firefox.*

Useful in phishing investigations or if you suspect the user downloaded malware.

```
Artifact: Windows.Programs.Browsers.History
Parameters:
- Time range: e.g. Last 7 days
```

### **Review File Activity Timeline**

*Tracks when files were opened, created, modified, or executed on the system.*

Helps build a timeline of what happened on the endpoint.

```
Artifact: Windows.Timeline
Parameters:
- File Extension: .exe or .ps1
- Time Range: e.g. Last 24 hours
```

## Memory and Credential Access

### **Collect LSASS Memory Dump**

*Captures the memory of the LSASS process, which stores login credentials.*

Used during incident response to check if an attacker tried to extract passwords. **LSASS** is a sensitive Windows process, and dumping it may trigger antivirus or cause system instability.

```
Artifact: Windows.Memory.Lsass
Parameters:
- LiveDump: true
- OutputFile: C:\Temp\lsass.dmp
```

## Process and Execution Monitoring

### **List Injected Threads**

*Checks for suspicious code injected into running processes.*

Attackers often use **process injection** to hide malicious actions inside trusted programs.

```
Artifact: Windows.Detection.RemoteThreads
Parameters: None
```

### **Scan for Suspicious Command Line Patterns**

*Searches command lines for suspicious keywords like `base64`, `bypass`, or `encoded`.*

Useful for detecting obfuscated scripts or abuse of trusted tools.

```
Artifact: Windows.Detection.SuspiciousCommandLine
Parameters: None
```

### **Detect Suspicious Parent-Child Process Chains**

*Finds unusual process relationships such as Microsoft Word or Excel launching PowerShell.*

This is a common phishing method where a macro in a document runs a malicious script.

```
Artifact: Windows.System.Pstree
Parameters:
- IncludeProcessList: powershell.exe, cmd.exe, wscript.exe
```

## Scheduled Task Monitoring

### **List Scheduled Tasks**

*Shows all scheduled tasks on the machine, including hidden or attacker-created ones.*

Attackers use this to maintain persistence or schedule repeated attacks.

```
Artifact: Windows.System.ScheduledTasks
Parameters: None
```