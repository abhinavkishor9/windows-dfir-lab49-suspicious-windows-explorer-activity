# Investigation Notes — Lab 49: Suspicious Windows Explorer Activity Investigation

## Investigation Scenario

A user opens an unfamiliar file through Windows File Explorer. Shortly afterward, Windows records process and network activity, creating a potential lead for the SOC analyst.

The analyst needs to determine:

- What file the user accessed.
- What process was launched.
- Whether explorer.exe was involved in the process chain.
- Whether Security Event ID 4688 and Sysmon Event ID 1 support the activity.
- Whether Sysmon Event ID 3 shows related network activity.
- Why the file's digital signature returned Unknown.

The investigation then correlates these findings with other Windows artifacts to determine whether the activity was normal user behavior or potentially suspicious execution. The conclusion should be based on the overall evidence rather than any single event or indicator.

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

