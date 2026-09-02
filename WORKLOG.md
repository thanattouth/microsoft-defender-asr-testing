# ASR validation worklog

| Rule | Implementation | Windows validation | Notes |
|---|---|---|---|
| 01 - Block Adobe Reader from creating child processes | Ready | Pending | Benign Notepad launch test, browser URI fallback, local event collection, and XDR query added. |

## Working convention

Each row advances from `Planned` to `Ready` to `Validated`. A rule is `Validated` only after its expected Windows Defender evidence has been observed on a test endpoint.
