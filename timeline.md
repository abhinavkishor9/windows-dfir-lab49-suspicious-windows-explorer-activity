# Timeline — Lab 49: Suspicious Windows Explorer Activity Investigation

## Investigation Timeline

| Step | Activity | Evidence / Result |
| --- | --- | --- |
| 1 | Investigation initiated | Suspicious Windows Explorer activity investigation started |
| 2 | Explorer validated | `explorer.exe` confirmed as a normal active Windows process |
| 3 | Sysmon validated | Sysmon telemetry available for investigation |
| 4 | Sysmon Event ID 1 reviewed | Process creation telemetry identified |
| 5 | Sysmon Event ID 3 reviewed | Network telemetry available |
| 6 | Explorer PID identified | Explorer process information collected |
| 7 | Explorer process context examined | Process ID and parent process information reviewed |
| 8 | Investigation workspace created | `C:\ExplorerActivityLab\` created |
| 9 | Controlled test artifact created | Harmless test artifact created |
| 10 | Test artifact accessed through File Explorer | GUI-driven activity generated |
| 11 | Resulting process activity investigated | Process creation telemetry reviewed |
| 12 | Sysmon Event ID 1 analyzed | Process image, parent image, PID and command line examined |
| 13 | Explorer-related activity searched | Explorer references and parent relationships investigated |
| 14 | UserAssist examined | GUI activity artifact reviewed |
| 15 | Recent Items examined | File interaction artifacts reviewed |
| 16 | Security Event ID 4688 reviewed | Process creation evidence observed in Event Viewer |
| 17 | Sysmon Event ID 3 reviewed | Network activity observed in Event Viewer |
| 18 | File metadata collected | File path, size and timestamps examined |
| 19 | SHA-256 generated | Cryptographic hash calculated |
| 20 | Digital signature checked | Status observed as `Unknown` |
| 21 | Process tree reconstructed | Explorer-related execution chain analyzed |
| 22 | Evidence correlated | Process, file, Registry, security and network evidence compared |
| 23 | Suspicion assessment performed | Activity evaluated using contextual indicators |
| 24 | Investigation completed | Evidence-supported findings and limitations documented |

---

# Detailed Timeline

## Phase 1 — Baseline and Telemetry Validation

### T+00 — Investigation Started

The Suspicious Windows Explorer Activity Investigation was initiated.

The objective was to determine whether normal Windows Explorer activity could be associated with suspicious process execution.

### T+05 — Explorer Validated

The running Explorer process was identified.

Command:

    Get-Process explorer | Select-Object Id, ProcessName, Path

Explorer was treated as the baseline Windows shell process.

### T+10 — Sysmon Telemetry Validated

Available Sysmon events were reviewed.

The investigation focused on:

    Event ID 1 — Process Creation
    Event ID 3 — Network Connection

---

# Phase 2 — Controlled Explorer Activity

### T+15 — Explorer Process Context Examined

Explorer process information was collected.

The investigation recorded:

- Process ID
- Process name
- Executable path
- Parent process information

### T+20 — Investigation Workspace Created

The investigation workspace was created:

    C:\ExplorerActivityLab\

### T+25 — Controlled Artifact Created

A harmless test artifact was created inside the investigation workspace.

The artifact was intended to simulate a file that a user might interact with through Windows Explorer.

### T+30 — Artifact Accessed Through File Explorer

The test artifact was accessed through the graphical File Explorer interface.

This simulated:

    User
        |
        v
    Windows Explorer
        |
        v
    File interaction
        |
        v
    Process activity

---

# Phase 3 — Process Investigation

### T+35 — Resulting Process Activity Checked

The resulting process activity was examined using PowerShell.

The investigation focused on the processes created around the time of the controlled activity.

### T+40 — Sysmon Event ID 1 Investigated

Sysmon Event ID 1 was queried for process creation evidence.

The following fields were considered:

    Image
    ParentImage
    ProcessId
    ParentProcessId
    CommandLine
    User
    UtcTime

### T+45 — Explorer-Related Process Creation Investigated

Process creation events were examined for relationships involving:

    explorer.exe

The investigation focused on whether Explorer was the actual parent process rather than assuming that it was.

---

# Phase 4 — Supporting Artifact Investigation

### T+50 — UserAssist Examined

The UserAssist Registry location was reviewed:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

The artifact was treated as supporting evidence of GUI-based application activity.

### T+55 — Recent Items Examined

Recent Items were reviewed:

    %APPDATA%\Microsoft\Windows\Recent

The investigation looked for evidence associated with the controlled Explorer activity.

Recent Items were treated as supporting evidence of file interaction.

---

# Phase 5 — Windows Security Investigation

### T+60 — Security Event ID 4688 Observed

Windows Security Event ID 4688 was observed through Event Viewer.

The event was used to investigate process creation independently from Sysmon.

Relevant information included:

- Process
- Process ID
- Parent process
- Command line
- Account
- Timestamp

### T+65 — Event Viewer Correlation

Security Event ID 4688 was compared conceptually with Sysmon process-creation telemetry.

The objective was to determine whether multiple telemetry sources supported the same process activity.

---

# Phase 6 — Network Investigation

### T+70 — Sysmon Event ID 3 Observed

Sysmon Event ID 3 network telemetry was observed through Event Viewer.

The investigation considered:

- Process
- Source address
- Destination address
- Destination port
- Protocol
- Timestamp

### T+75 — Network Context Evaluated

Network telemetry was considered supporting evidence.

The presence of a network event was not automatically interpreted as malicious.

---

# Phase 7 — File Investigation

### T+80 — File Metadata Collected

The investigation artifact was examined for:

- Filename
- Full path
- File size
- Creation time
- Last write time
- Last access time

These values were considered when constructing the timeline.

### T+85 — SHA-256 Calculated

The artifact hash was generated using:

    Get-FileHash "<path-to-file>" -Algorithm SHA256

The SHA-256 value was recorded as an artifact identifier.

### T+90 — Digital Signature Checked

The artifact was checked using:

    Get-AuthenticodeSignature "<path-to-file>"

Observed result:

    Unknown

The status was documented exactly as observed.

---

# Phase 8 — Evidence Correlation

### T+95 — Process Tree Reconstructed

The investigation attempted to reconstruct the observed process chain.

The analytical model was:

    explorer.exe
        |
        +---- Test Activity
                  |
                  +---- Child Process
                          |
                          +---- Network Activity

The actual process lineage was determined from available telemetry.

### T+100 — Evidence Correlated

The following evidence was correlated:

    Explorer
       |
       +---- Sysmon Event ID 1
       |
       +---- Security Event ID 4688
       |
       +---- Sysmon Event ID 3
       |
       +---- UserAssist
       |
       +---- Recent Items
       |
       +---- File Metadata
       |
       +---- SHA-256
       |
       +---- Digital Signature

---

# Phase 9 — Final Assessment

### T+105 — Suspicious Indicators Reviewed

The investigation evaluated:

- Process name
- Parent process
- Child process
- File location
- Command line
- User
- Timestamp
- Network activity
- Digital signature
- Supporting Registry artifacts

### T+110 — Signature Result Documented

The digital-signature result was recorded as:

    Unknown

No automatic malicious classification was made.

### T+115 — Explorer Activity Assessed

Explorer activity was evaluated in context rather than being classified as suspicious solely because `explorer.exe` appeared in the telemetry.

### T+120 — Investigation Completed

The investigation concluded after evidence correlation and documentation of the observed telemetry and limitations.

---

# Final Timeline Summary

| Phase | Key Activity | Result |
| --- | --- | --- |
| 1 | Explorer baseline | Normal Windows shell process established |
| 2 | Sysmon validation | Event IDs 1 and 3 available |
| 3 | Controlled artifact creation | Harmless test artifact created |
| 4 | Explorer interaction | Artifact accessed through File Explorer |
| 5 | Process investigation | Sysmon Event ID 1 reviewed |
| 6 | UserAssist | Supporting GUI activity artifact examined |
| 7 | Recent Items | Supporting file interaction evidence examined |
| 8 | Security Event 4688 | Process creation evidence observed |
| 9 | Sysmon Event 3 | Network telemetry observed through Event Viewer |
| 10 | File analysis | Metadata and SHA-256 collected |
| 11 | Signature analysis | Status observed as `Unknown` |
| 12 | Evidence correlation | Multiple endpoint sources compared |
| 13 | Final assessment | Explorer activity evaluated in context |
| 14 | Investigation complete | Findings and limitations documented |

---

# Investigation Conclusion

The timeline demonstrated how a normal Windows Explorer session can be reconstructed into a useful DFIR investigation by correlating process creation, Windows Security Event 4688, Sysmon Event ID 3, UserAssist, Recent Items, filesystem metadata, hashing, and digital-signature information.

The investigation confirmed the availability of process and network telemetry and observed an `Unknown` digital-signature status for the investigated artifact. The final assessment was based on the combined evidence rather than treating Explorer activity or a single telemetry event as proof of malicious execution.
