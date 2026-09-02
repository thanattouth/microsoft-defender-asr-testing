# ASR validation worklog

| Rule | Implementation | Windows validation | Notes |
|---|---|---|---|
| 01 - Block Adobe Reader from creating child processes | Ready | Inconclusive / Deferred | Test flow completed, but no block notification, incident, or alert was observed. Local Event 1121/1122 and JSON evidence remain to be checked when this rule is revisited. |
| 02 - Block process creations originating from PsExec and WMI commands | Ready | Pending | Benign WMI marker test, optional PsExec fallback, local event collection, and XDR query added. This rule isn't expected to create an EDR alert. |

## Working convention

Each row advances from `Planned` to `Ready` to `Validated`. A rule is `Validated` only after its expected Windows Defender evidence has been observed on a test endpoint.
