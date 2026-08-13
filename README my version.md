# windows-dfir-lab49-suspicious-windows-explorer-activity
## Overview

explorer.exe is a legitimate Windows process that acts as the Windows graphical shell.

It is responsible for things such as:

Desktop
Taskbar
Start Menu
File Explorer
Folder navigation
Opening files
Launching applications through the GUI
Accessing removable drives
Accessing network shares

Normally, you will see something like:

explorer.exe
    ├── application.exe
    ├── notepad.exe
    └── other user-launched programs

So seeing explorer.exe in logs is completely normal.

The DFIR problem is determining when Explorer is being used in a suspicious execution chain.

An attacker doesn't necessarily need to execute malware directly from PowerShell or CMD.

They can sometimes rely on normal user interaction.

For example:

User
  ↓
Windows Explorer
  ↓
Downloads
  ↓
malicious.exe
  ↓
PowerShell
  ↓
Network connection

From the operating system's perspective, Explorer may simply appear to be launching a program.

Therefore, the investigation isn't:

"Did explorer.exe run?"

It is:

"What did explorer.exe launch, from where, under which user, and what happened afterward?"

That is the key idea of this lab.

What makes Explorer activity suspicious?

We are mainly looking for contextual anomalies.

Suspicious executable location

For example:

C:\Users\abhin\Downloads\setup.exe

or:

C:\Users\abhin\AppData\Local\Temp\update.exe

An executable launched from a user-writable directory deserves more attention than:

C:\Windows\System32\notepad.exe

Location is an indicator, not proof of malware.

Suspicious child process

For example:

explorer.exe
      ↓
powershell.exe

or:

explorer.exe
      ↓
cmd.exe

or:

explorer.exe
      ↓
rundll32.exe

These aren't automatically malicious, but they provide useful investigative leads.

Suspicious command line

For example:

powershell.exe -EncodedCommand ...

or:

cmd.exe /c powershell ...

would be much more interesting than:

notepad.exe

Another important artifact for this lab is UserAssist.

UserAssist is a Windows Registry artifact associated with applications launched through the Windows graphical user interface.

The location is generally under:

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

UserAssist contains GUID-named subkeys, so you normally won't see a friendly key called simply UserAssist\Applications.

This is important because UserAssist can provide supporting evidence of GUI-based application execution.

However:

UserAssist should not be treated as standalone proof of execution.

We correlate it with process creation and other artifacts.

Windows also maintains artifacts associated with recently accessed files.

These can help answer questions such as:

Did the user recently interact with this suspicious document or executable?

For example:

User
 ↓
Explorer
 ↓
Downloads\Invoice.pdf

Recent Items may provide supporting evidence that the file was accessed.

Again, this does not automatically prove that the file executed.

Sysmon Event ID 1 — Process Creation will be one of our most important data sources.

It can provide information such as:

Process name
Process path
Command line
Process ID
Parent Process ID
Parent image
User
Creation time
Hashes

The critical fields for our investigation are:

Image
ParentImage
CommandLine
ParentProcessId
ProcessId
User
UtcTime

We can also use Windows Security Event ID 4688 — A new process has been created.

This gives us another source of process creation evidence.

Conceptually:

Sysmon Event ID 1
        +
Security Event ID 4688
        ↓
Process Creation Correlation

If both sources show the same suspicious process around the same time, confidence in the process creation event increases.

We will also examine Sysmon Event ID 3 — Network Connection.

Suppose we find:

explorer.exe
      ↓
SuspiciousApp.exe

and shortly afterward:

SuspiciousApp.exe
      ↓
10.10.10.50:443

That doesn't automatically prove malicious activity, but it creates an interesting timeline:

User interaction
      ↓
Explorer
      ↓
Suspicious application
      ↓
Network connection

This is exactly the type of correlation a SOC analyst should perform.

In this hands-on DFIR lab, controlled user activity was performed through Windows Explorer to understand how GUI-based file interaction can lead to process creation and other observable Windows telemetry. Sysmon, Windows Security Event ID 4688, Event Viewer, UserAssist, Recent Items, PowerShell, file metadata, hashing, and digital-signature validation were used to investigate the resulting activity.

---

# Executive Summary

This investigation examined Windows Explorer as a potential source of suspicious application activity. A controlled test artifact was accessed through File Explorer, after which process creation and supporting endpoint telemetry were reviewed to understand the resulting execution chain.

---

# Investigation Objectives

The investigation was designed to determine whether normal Windows Explorer activity could be associated with unusual or potentially risky user-driven execution.

The key objectives were:

- Establish a normal baseline for explorer.exe and its role in the Windows user session.
- Reconstruct the sequence of actions that occurred after the user interacted with the test artifact.
- Determine whether the observed process was directly or indirectly associated with Explorer.
- Examine the parent-child relationship between processes instead of relying on process names alone.
- Correlate process activity across Sysmon and Windows Security telemetry.
- Review available network activity occurring around the same execution window.
- Determine whether the accessed file generated supporting Windows artifacts.
- Evaluate the file's location and metadata for contextual risk indicators.
- Verify the file's SHA-256 hash for reliable artifact identification.
- Investigate the meaning of the observed Unknown digital-signature status.
- Distinguish evidence of file access from evidence of actual execution.
- Determine whether the collected evidence supports a suspicious-activity hypothesis or a benign explanation.
- Identify gaps in telemetry that could limit the confidence of the investigation.
- Produce an evidence-based conclusion without treating a single event or indicator as proof of compromise.

---

# Tools Used

- Windows
- PowerShell
- Windows Event Viewer
- Sysmon
- Registry
- File Explorer

---

# Lab Environment

| Component | Details |
| --- | --- |
| Operating System | Windows |
| Investigation Type | Host-Based DFIR |
| Primary Process | `explorer.exe` |
| Primary Telemetry | Sysmon Event ID 1 |
| Supporting Telemetry | Sysmon Event ID 3 |
| Windows Security Event | 4688 |
| Investigation Method | Native Windows Tools |
| Test Workspace | `C:\ExplorerActivityLab\` |

---

# Investigation Workflow

1. Validate Sysmon.
2. Identify available Sysmon event types.
3. Identify the running `explorer.exe` process.
4. Record Explorer process information.
5. Create the investigation workspace.
6. Create a harmless controlled test artifact.
7. Access the artifact through File Explorer.
8. Identify resulting process activity.
9. Investigate Sysmon Event ID 1.
10. Investigate Explorer-related process creation.
11. Examine UserAssist.
12. Examine Recent Items.
13. Investigate Windows Security Event ID 4688.
14. Review Sysmon Event ID 3 through Event Viewer.
15. Examine the process tree.
16. Collect file metadata.
17. Calculate SHA-256.
18. Validate the digital signature.

---



# Sysmon Event ID 1

Sysmon Event ID 1 was used to investigate process creation.

Important fields included:

- `Image`
- `ParentImage`
- `ProcessId`
- `ParentProcessId`
- `CommandLine`
- `User`
- `UtcTime`

The purpose was to determine whether Explorer was associated with the creation of another process.

A process chain can be represented as:

    explorer.exe
        |
        +---- suspicious.exe
                  |
                  +---- powershell.exe

The actual process relationship was determined from telemetry rather than assumed.

---

# Sysmon Event ID 3

Sysmon Event ID 3 was reviewed as supporting network telemetry.

The event can provide information such as:

- Source IP
- Destination IP
- Destination Port
- Protocol
- Process ID
- Timestamp

Sysmon Event ID 3 activity was observed through Event Viewer during the investigation.

Network telemetry was treated as supporting evidence and was not independently interpreted as proof of malicious activity.

---

# Windows Security Event ID 4688

Windows Security Event ID 4688 was investigated as an independent process-creation source.

The event can provide supporting information about:

- New process creation
- Process name
- Process ID
- Parent process
- Command line
- Account information
- Timestamp

Event ID 4688 was observed through Event Viewer and was used to support process-creation investigation.

---

# UserAssist

UserAssist was examined as a supporting Windows Registry artifact associated with GUI-based application activity.

The primary Registry location examined was:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

UserAssist contains GUID-based structures and encoded application information, so the raw Registry representation is not always directly readable.

UserAssist was treated as supporting evidence rather than standalone proof of execution.

---

# Recent Items

Recent Items were examined as supporting evidence of user interaction with files.

The relevant user directory was:

    %APPDATA%\Microsoft\Windows\Recent

The investigation looked for artifacts associated with the controlled Explorer activity.

Recent Items can support the conclusion that a file was accessed through the Windows user environment, but file access should not automatically be interpreted as executable execution.

---

# File Analysis

The controlled investigation artifact was examined using native Windows tools.

The following categories of evidence were considered:

- Filename
- Full path
- File size
- Creation time
- Last write time
- Last access time
- SHA-256 hash
- Digital-signature status

The SHA-256 hash was generated using PowerShell:

    Get-FileHash "<path-to-file>" -Algorithm SHA256

---

# Digital Signature Analysis

The artifact's Authenticode signature was checked using:

    Get-AuthenticodeSignature "<path-to-file>"

The observed signature status was:

    Unknown

The result was recorded as observed.

The investigation did not automatically interpret `Unknown` as proof that the artifact was malicious.

Digital-signature status must be interpreted together with file type, location, hash, process behavior, and other endpoint evidence.

---

# MITRE ATT&CK Mapping

| Technique | Description |
| --- | --- |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1083 | File and Directory Discovery |

The MITRE ATT&CK mappings represent techniques that may become relevant when suspicious processes are launched through Explorer. The controlled lab itself did not establish malicious use of these techniques.

---

