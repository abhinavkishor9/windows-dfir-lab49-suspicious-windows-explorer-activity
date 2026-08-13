# windows-dfir-lab49-suspicious-windows-explorer-activity

## Overview

Windows Explorer (`explorer.exe`) is a legitimate Windows shell process responsible for desktop interaction, file browsing, folder navigation, and launching applications through the graphical interface. Because Explorer normally runs on every interactive Windows session, its presence alone is not an indicator of malicious activity.

In this hands-on DFIR lab, controlled user activity was performed through Windows Explorer to understand how GUI-based file interaction can lead to process creation and other observable Windows telemetry. Sysmon, Windows Security Event ID 4688, Event Viewer, UserAssist, Recent Items, PowerShell, file metadata, hashing, and digital-signature validation were used to investigate the resulting activity.

---

# Executive Summary

This investigation examined Windows Explorer as a potential source of suspicious application activity. A controlled test artifact was accessed through File Explorer, after which process creation and supporting endpoint telemetry were reviewed to understand the resulting execution chain.

Windows Security Event ID 4688 and Sysmon telemetry were available for investigation, while Sysmon Event ID 3 network telemetry was also observed through Event Viewer. The test artifact's digital-signature status was identified as `Unknown`. The investigation demonstrated that Explorer activity must be analyzed through process relationships, file locations, command lines, timestamps, and supporting artifacts rather than treating `explorer.exe` itself as suspicious.

---

# Investigation Objectives

- Determine how Windows Explorer activity appears in endpoint telemetry.
- Identify processes created as a result of GUI-based user interaction.
- Examine parent-child process relationships involving Explorer.
- Investigate process creation using Sysmon Event ID 1.
- Correlate process activity with Windows Security Event ID 4688.
- Examine available Sysmon Event ID 3 network telemetry.
- Investigate Recent Items as supporting evidence of file interaction.
- Examine UserAssist as supporting GUI execution evidence.
- Collect metadata from files involved in the investigation.
- Generate a SHA-256 hash for the investigation artifact.
- Validate the digital-signature status of the artifact.
- Distinguish normal Explorer activity from potentially suspicious execution patterns.
- Build a timeline from multiple endpoint artifacts.
- Document telemetry limitations and evidence gaps.
- Reach an evidence-supported DFIR conclusion.

---

# Skills Demonstrated

- Windows Explorer Activity Investigation
- Windows Process Tree Analysis
- Sysmon Event ID 1 Analysis
- Sysmon Event ID 3 Analysis
- Windows Security Event ID 4688 Analysis
- Parent-Child Process Correlation
- UserAssist Investigation
- Recent Items Investigation
- File Metadata Analysis
- SHA-256 Hashing
- Digital Signature Validation
- Event Viewer Investigation
- Host-Based DFIR
- Evidence Correlation
- Timeline Construction
- Forensic Documentation

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
19. Correlate the evidence.
20. Build the investigation timeline.
21. Assess whether suspicious execution can be confirmed.
22. Document findings and limitations.

---

# Primary Investigation Question

The investigation was centered around the following question:

> Did Windows Explorer launch or interact with an unusual application in a way that could indicate suspicious execution?

The investigation did not treat the presence of `explorer.exe` as malicious by itself.

Instead, the analysis focused on:

- Parent process
- Child process
- Process path
- Command line
- User
- File location
- File metadata
- Digital signature
- Hash
- Network activity
- Timestamps
- Supporting Registry artifacts

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

# Evidence Correlation

The investigation correlated several evidence sources:

    User interaction
          |
          v
    Windows Explorer
          |
          v
    File interaction
          |
          v
    Process creation
          |
          +---- Sysmon Event ID 1
          |
          +---- Security Event ID 4688
          |
          v
    Process tree
          |
          +---- Command line
          |
          +---- Parent process
          |
          +---- Child process
          |
          v
    Supporting artifacts
          |
          +---- UserAssist
          +---- Recent Items
          +---- File metadata
          +---- SHA-256
          +---- Digital signature
          +---- Sysmon Event ID 3

This approach prevents a single artifact from being treated as conclusive evidence.

---

# Investigation Findings

The investigation confirmed that Windows Explorer can be used as the starting point for GUI-driven file and application activity.

Sysmon process telemetry and Windows Security Event ID 4688 provided process-creation evidence, while Sysmon Event ID 3 network telemetry was available for supporting analysis and was observed through Event Viewer.

The controlled artifact's digital-signature status was observed as `Unknown`. This result was documented without automatically classifying the artifact as malicious.

The investigation demonstrated that suspicious Explorer activity must be evaluated using process lineage, file location, command line, timestamps, signature information, and supporting artifacts.

---

# Indicators That Would Increase Suspicion

During a real investigation, the following Explorer-related patterns would deserve additional analysis:

    explorer.exe
        |
        +---- powershell.exe

    explorer.exe
        |
        +---- cmd.exe

    explorer.exe
        |
        +---- rundll32.exe

    explorer.exe
        |
        +---- C:\Users\<user>\Downloads\unknown.exe

    explorer.exe
        |
        +---- C:\Users\<user>\AppData\Local\Temp\update.exe

These process relationships are investigation leads, not automatic proof of malicious activity.

Additional evidence would be required before declaring an incident.

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

# Evidence Collected

- Windows Explorer process information
- Sysmon Event ID 1
- Sysmon Event ID 3
- Windows Security Event ID 4688
- Event Viewer observations
- UserAssist Registry information
- Recent Items artifacts
- Test artifact
- File metadata
- SHA-256 hash
- Digital-signature status
- Investigation timeline

---

# Limitations

The investigation was performed using controlled benign activity.

The test artifact was not treated as malware.

The presence of Explorer, Event ID 4688, or Sysmon Event ID 3 does not independently establish malicious behavior.

Similarly, an `Unknown` digital-signature status does not by itself prove that the file is malicious.

A real-world investigation would require additional evidence such as:

- Malware analysis
- Prefetch
- Amcache
- ShimCache
- Defender alerts
- EDR telemetry
- Network evidence
- Persistence artifacts
- Process command lines
- User activity
- File reputation
- Threat intelligence

---

# Key Takeaway

Windows Explorer is a trusted Windows component and is normally present during interactive user sessions.

Therefore, the important DFIR question is not whether `explorer.exe` exists, but what it launched, what files were accessed, where those files were located, what command lines were used, and what happened afterward.

Reliable investigation requires correlation between process creation, process lineage, file artifacts, Registry artifacts, network telemetry, timestamps, and signature information.

The investigation demonstrated how normal Explorer activity can be transformed into a useful DFIR timeline when multiple endpoint evidence sources are correlated.
