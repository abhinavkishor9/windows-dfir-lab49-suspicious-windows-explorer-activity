# Investigation Notes — Lab 49: Suspicious Windows Explorer Activity Investigation

## Investigation Scenario

A Windows user interacts with a file through Windows Explorer. The activity results in observable process creation and supporting endpoint telemetry. The objective is to determine whether the Explorer-driven activity represents normal user behavior or a potentially suspicious execution chain.

The investigation focuses on process lineage, file location, command-line activity, Windows Security Event ID 4688, Sysmon Event IDs 1 and 3, UserAssist, Recent Items, file metadata, hashing, and digital-signature information.

---

# Initial Hypothesis

The initial hypothesis was that suspicious activity might be hidden behind a legitimate Windows process.

Because `explorer.exe` is a trusted and normally running Windows process, the investigation could not classify it as suspicious simply because it appeared in telemetry.

The investigation therefore focused on identifying what Explorer interacted with or launched and whether the resulting behavior was unusual.

---

# Investigation Approach

The investigation followed this sequence:

    Explorer
       |
       v
    File Interaction
       |
       v
    Process Creation
       |
       v
    Parent-Child Relationship
       |
       v
    Supporting Telemetry
       |
       +---- Security 4688
       +---- Sysmon Event ID 3
       +---- UserAssist
       +---- Recent Items
       |
       v
    File Analysis
       |
       +---- Metadata
       +---- SHA-256
       +---- Digital Signature
       |
       v
    Evidence Correlation
       |
       v
    Final Assessment

---

# Explorer Baseline

The running Explorer process was examined using PowerShell.

Command:

    Get-Process explorer | Select-Object Id, ProcessName, Path

The purpose was to establish:

- Explorer PID
- Process name
- Executable path

Explorer was treated as a normal baseline process.

---

# Sysmon Validation

Sysmon was validated before investigation.

The available Sysmon telemetry was reviewed to determine which event types could be used.

The investigation focused primarily on:

    Event ID 1
    Event ID 3

Event ID 1 was used for process creation.

Event ID 3 was used for supporting network activity.

---

# Controlled Test Activity

A controlled investigation workspace was created:

    C:\ExplorerActivityLab\

A harmless test artifact was created for the investigation.

The artifact was accessed through File Explorer rather than being directly launched from PowerShell.

This was important because the lab was designed to simulate GUI-driven user activity.

---

# Process Creation Investigation

Sysmon Event ID 1 was investigated to identify process creation associated with the controlled activity.

Command:

    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1
    } -MaxEvents 100 |
    Select-Object TimeCreated, Message

The investigation focused on:

- Process image
- Parent image
- Process ID
- Parent process ID
- Command line
- User
- Timestamp

The observed process relationships were treated as authoritative rather than assuming that Explorer must always be the immediate parent.

---

# Windows Security Event 4688

Windows Security Event ID 4688 was observed through Event Viewer.

The event was used as an independent source of process creation evidence.

The investigation considered:

- Process name
- Process ID
- Parent process
- Command line
- Account
- Timestamp

The purpose was to correlate Windows Security process creation information with Sysmon process telemetry.

---

# Sysmon Event ID 3

Sysmon Event ID 3 network telemetry was observed through Event Viewer.

The investigation considered:

- Process
- Source address
- Destination address
- Destination port
- Protocol
- Timestamp

Network telemetry was treated as supporting evidence.

The presence of a network event alone was not considered sufficient evidence of malicious activity.

---

# UserAssist Investigation

UserAssist was examined as a supporting artifact for GUI-based activity.

Registry location:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

UserAssist was not treated as standalone proof that a specific file was executed.

The artifact was considered in combination with process creation and other evidence.

---

# Recent Items Investigation

Recent Items were examined from:

    %APPDATA%\Microsoft\Windows\Recent

The purpose was to determine whether the controlled activity resulted in supporting evidence of file interaction.

Recent Items were considered supporting evidence of user interaction rather than definitive proof of execution.

---

# File Metadata

The investigation examined the test artifact's:

- Name
- Full path
- File size
- Creation time
- Last write time
- Last access time

Filesystem timestamps were considered useful for constructing the investigation timeline.

---

# SHA-256 Analysis

A SHA-256 hash was generated using:

    Get-FileHash "<path-to-file>" -Algorithm SHA256

The hash provides a deterministic identifier for the artifact and can be used for:

- Evidence tracking
- Correlation
- Malware analysis
- Threat intelligence
- Future comparison

---

# Digital Signature Analysis

The file was checked using:

    Get-AuthenticodeSignature "<path-to-file>"

Observed result:

    Status: Unknown

The result was documented exactly as observed.

The `Unknown` result was not treated as automatic evidence of maliciousness.

Signature status must be interpreted with:

- File type
- File location
- Hash
- Process behavior
- Parent process
- Command line
- Network activity

---

# Process Tree Analysis

The investigation attempted to reconstruct the execution chain.

The general analytical model was:

    explorer.exe
        |
        +---- Test Artifact / Application
                  |
                  +---- Child Process
                          |
                          +---- Network Activity

The actual process tree was based on observed telemetry.

The investigation did not assume that a process launched through the GUI would necessarily have Explorer as its immediate parent.

---

# Evidence Correlation

The following evidence sources were correlated:

| Evidence | Investigation Value |
| --- | --- |
| Explorer process | Establishes Windows shell context |
| Sysmon Event ID 1 | Process creation |
| Security Event ID 4688 | Independent process creation evidence |
| Sysmon Event ID 3 | Network activity |
| UserAssist | Supporting GUI execution evidence |
| Recent Items | Supporting file-access evidence |
| File metadata | Filesystem timeline |
| SHA-256 | Artifact identification |
| Digital signature | File trust information |
| Event Viewer | Manual telemetry validation |

---

# Suspicion Assessment

The investigation considered the following factors:

### Process Name

Was the process expected and legitimate?

### Parent Process

Was the parent process consistent with normal user activity?

### File Location

Was the executable located in:

- Downloads
- Temp
- AppData
- Public
- Other user-writable directories

### Command Line

Did the process contain:

- Encoded PowerShell
- Script execution
- Suspicious arguments
- LOLBin usage

### Network Activity

Did the process initiate unexpected connections?

### Digital Signature

Was the file signed and could the signer be trusted?

### Timeline

Did multiple suspicious events occur within a short period?

---

# Findings

The investigation demonstrated that Windows Explorer activity can be investigated through multiple endpoint evidence sources.

Windows Security Event ID 4688 and Sysmon process telemetry provided process-creation evidence.

Sysmon Event ID 3 network telemetry was also observed through Event Viewer.

The controlled artifact returned an `Unknown` digital-signature status.

No single observation was treated as sufficient to establish malicious activity.

---

# Investigation Assessment

The evidence supported investigation of Explorer-driven activity, but the presence of Explorer activity alone did not establish malicious execution.

The digital-signature result of `Unknown` was recorded as an artifact property rather than being interpreted as a malicious verdict.

The investigation therefore emphasized evidence correlation and process lineage.

---

# DFIR Conclusion

The investigation demonstrated how a trusted Windows process can become an important starting point for endpoint investigation.

The correct investigative approach is to determine what Explorer interacted with, what process was created, what the parent-child relationship was, what command line was used, whether network activity followed, and whether supporting artifacts corroborate the activity.

The final assessment should always be based on the complete evidence chain rather than on the presence of `explorer.exe` or a single suspicious indicator.
