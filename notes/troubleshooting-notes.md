# Troubleshooting Notes — Lab 49: Suspicious Windows Explorer Activity Investigation

## Purpose

This document records the technical issues, observations, and investigative decisions encountered while performing the Suspicious Windows Explorer Activity Investigation.

The goal was to ensure that the final investigation reflected the telemetry actually available on the Windows endpoint.

---

# 1. Explorer Is a Normal Windows Process

## Observation

`explorer.exe` was present as an active Windows process.

## Potential Misinterpretation

It would be incorrect to classify Explorer as suspicious simply because it appeared in process telemetry.

## Resolution

Explorer was treated as a baseline process.

The investigation focused on:

- What Explorer launched
- What files were accessed
- Parent-child relationships
- Command lines
- File locations
- Subsequent network activity

## DFIR Lesson

A trusted process should be investigated based on behavior and context rather than process name alone.

---

# 2. Process Parent Was Not Assumed

## Problem

It is tempting to assume that every GUI-launched process has:

    explorer.exe

as its immediate parent.

## Resolution

The actual parent process was investigated using process information and Sysmon Event ID 1.

Important fields included:

    ParentImage
    ParentProcessId
    Image
    ProcessId

## DFIR Lesson

Process lineage should always be verified from telemetry.

Never assume the parent process based only on how the application was launched.

---

# 3. Sysmon Event ID 1 Was Used as Primary Process Telemetry

## Observation

Sysmon Event ID 1 was available for process creation investigation.

## Resolution

Event ID 1 was used to examine:

- Process image
- Parent image
- Command line
- PID
- Parent PID
- User
- Timestamp

## DFIR Lesson

Process creation telemetry is one of the strongest starting points for reconstructing suspicious execution chains.

---

# 4. Windows Security Event ID 4688 Was Observed in Event Viewer

## Observation

Windows Security Event ID 4688 was observed through Event Viewer.

## Resolution

The event was treated as an independent source of process creation evidence.

It was used to support correlation with Sysmon process telemetry.

## DFIR Lesson

Multiple process-creation sources can improve confidence when investigating endpoint activity.

---

# 5. Sysmon Event ID 3 Was Observed in Event Viewer

## Observation

Sysmon Event ID 3 network activity was visible through Event Viewer.

## Resolution

The event was treated as supporting network telemetry.

The investigation considered:

- Source address
- Destination address
- Destination port
- Protocol
- Process
- Timestamp

## DFIR Lesson

Network telemetry becomes more valuable when correlated with process creation.

For example:

    explorer.exe
        |
        +---- suspicious.exe
                  |
                  +---- outbound network connection

would provide a stronger investigative lead than either event alone.

---

# 6. Digital Signature Returned Unknown

## Observation

The test artifact was checked using:

    Get-AuthenticodeSignature "<path-to-file>"

The observed result was:

    Unknown

## Potential Mistake

It would be incorrect to automatically replace this result with:

    NotSigned

or:

    Malicious

## Resolution

The exact observed status was recorded as:

    Unknown

The result was treated as supporting file-trust information.

## DFIR Lesson

Unexpected signature results must be documented accurately.

Digital-signature status alone does not determine whether a file is malicious.

---

# 7. Recent Items Were Treated as Supporting Evidence

## Observation

Recent Items were examined for evidence of file interaction.

Location:

    %APPDATA%\Microsoft\Windows\Recent

## Resolution

Recent Items were not treated as definitive proof of execution.

They were used to support the broader timeline.

## DFIR Lesson

File access and file execution are separate forensic claims.

---

# 8. UserAssist Was Treated as Supporting Evidence

## Observation

UserAssist was examined under:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

## Problem

UserAssist contains GUID-based and encoded Registry structures.

## Resolution

The artifact was treated as supporting evidence rather than attempting to force a direct execution conclusion from raw Registry output.

## DFIR Lesson

A forensic artifact should be interpreted according to what it can actually prove.

---

# 9. Network Activity Was Not Automatically Considered Malicious

## Observation

Sysmon Event ID 3 was available.

## Potential Misinterpretation

A process connecting to a network destination does not automatically mean the process is malicious.

## Resolution

Network activity was correlated with:

- Process
- Destination
- Port
- Timestamp
- Parent process
- File
- User

## DFIR Lesson

Network events require context.

---

# 10. Explorer Activity Was Not Automatically Classified as Suspicious

The investigation deliberately avoided using the following logic:

    explorer.exe = suspicious

Instead, the analysis followed:

    explorer.exe
        |
        v
    Child process
        |
        v
    File
        |
        v
    Command line
        |
        v
    Network activity
        |
        v
    Evidence correlation

This approach reduces false positives.

---

# 11. Controlled Activity Was Used Instead of Malware

The investigation used a harmless controlled artifact.

This allowed process and endpoint telemetry to be studied without executing actual malware.

The purpose was to understand:

- GUI-driven execution
- Explorer process relationships
- Sysmon telemetry
- Windows Security telemetry
- Supporting artifacts

## DFIR Lesson

Controlled simulations are useful for learning how endpoint telemetry behaves before investigating real incidents.

---

# 12. Event Viewer Was Used for Validation

Event Viewer was used to manually inspect:

    Windows Logs
        |
        +---- Security

and:

    Applications and Services Logs
        |
        +---- Microsoft
              |
              +---- Windows
                    |
                    +---- Sysmon
                          |
                          +---- Operational

This helped validate the availability of:

- Security Event ID 4688
- Sysmon Event ID 3
- Other endpoint telemetry

---

# Final Troubleshooting Summary

| Issue / Observation | Resolution |
| --- | --- |
| Explorer is always running | Treated as normal baseline process |
| Parent process could be assumed incorrectly | Verified using process telemetry |
| Sysmon Event ID 1 available | Used for process creation analysis |
| Security Event ID 4688 observed | Used as independent process evidence |
| Sysmon Event ID 3 observed | Used as supporting network evidence |
| Digital signature returned `Unknown` | Recorded exact observed result |
| Recent Items could be misinterpreted | Treated as supporting file-access evidence |
| UserAssist data is complex | Treated as supporting evidence |
| Network activity could be overinterpreted | Correlated with process and timeline |
| Explorer activity could create false positives | Investigated process context instead |
| Need for telemetry validation | Used Event Viewer |

---

# Key Troubleshooting Lessons

## 1. Start With a Baseline

Explorer is a normal Windows process.

The investigation must establish what is normal before identifying anomalies.

## 2. Verify Process Lineage

Always inspect:

    ParentImage
    ParentProcessId
    Image
    ProcessId

Do not assume the process tree.

## 3. Correlate Independent Evidence

Sysmon Event ID 1 and Windows Security Event ID 4688 can provide complementary process-creation evidence.

## 4. Treat Network Events as Context

Sysmon Event ID 3 becomes more meaningful when correlated with the process responsible for the connection.

## 5. Record Exact Tool Output

An `Unknown` digital-signature status should remain `Unknown`.

Do not convert unexpected output into a preferred classification.

## 6. Separate Access From Execution

Recent Items may demonstrate file interaction but do not automatically prove execution.

## 7. Avoid Explorer-Based False Positives

The presence of `explorer.exe` is not suspicious by itself.

The investigation should focus on what Explorer did and what happened afterward.

---

# Final Lesson

The main troubleshooting lesson from Lab 49 was that suspicious Windows Explorer activity must be investigated through context.

Explorer is a trusted Windows component, so the analyst must reconstruct the surrounding activity using process creation, parent-child relationships, Security Event 4688, Sysmon Event ID 3, file artifacts, Registry artifacts, timestamps, and signature information.

The investigation therefore follows:

    Baseline
        ↓
    Observe
        ↓
    Correlate
        ↓
    Validate
        ↓
    Assess
        ↓
    Document

This approach helps reduce false positives while producing a defensible DFIR conclusion.
