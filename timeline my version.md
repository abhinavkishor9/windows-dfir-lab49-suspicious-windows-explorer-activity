# Timeline — Lab 49: Suspicious Windows Explorer Activity Investigation


| Step | Key Activity | Result |
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

---

