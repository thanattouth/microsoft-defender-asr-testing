# ASR validation worklog

| Rule | Implementation | Windows validation | Notes |
|---|---|---|---|
| 01 - Block Adobe Reader from creating child processes | Ready | Inconclusive / Deferred | Test flow completed, but no block notification, incident, or alert was observed. Local Event 1121/1122 and JSON evidence remain to be checked when this rule is revisited. |
| 02 - Block process creations originating from PsExec and WMI commands | Ready | Validated locally / Portal pending | Block notification appeared, the runner returned `Blocked`, and a detailed local Defender event was recorded. Waiting for Defender portal telemetry. |
| 03 - Block execution of potentially obfuscated scripts | Ready | Validated locally / Portal pending | The pinned Microsoft sample returned `Blocked`, produced target-rule Event 1121, and showed a block notification. The protected Notepad action did not start; `MarkerCreated = False` is expected for this trigger. |

## Working convention

Each row advances from `Planned` to `Ready` to `Validated`. A rule is `Validated` only after its expected Windows Defender evidence has been observed on a test endpoint.
