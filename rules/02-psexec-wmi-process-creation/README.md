# Rule 02 - Block process creations originating from PsExec and WMI commands

## Rule identity

- Rule: `Block process creations originating from PSExec and WMI commands`
- GUID: `d1e49aac-8f56-4280-b9ba-993a6d77406c`
- Configured baseline: `Block`
- Dependency: Microsoft Defender Antivirus
- Supported client baseline: Windows 10 version 1803 or later
- Advanced Hunting actions: `AsrPsexecWmiChildProcessBlocked`, `AsrPsexecWmiChildProcessAudited`
- EDR alert expected: No
- User notification supported: Yes

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, dependency, Advanced Hunting action types, limited exclusion support, and that the rule blocks processes created through PsExec and WMI.
- The same reference states that this rule does not generate an EDR alert, although it supports a user notification. An absent Incident or Alert is therefore expected and is not the success criterion.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event ID 1121 as Block, 1122 as Audit, and 1129 as Warn override in the Windows Defender Operational log.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) provides an official VBS sample for this rule, but warns that its samples intentionally resemble malware and can be detected or quarantined. This project instead uses an inert local marker.
- [Microsoft Sysinternals PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) is an optional fallback. The runner never downloads it automatically.

> [!IMPORTANT]
> Microsoft warns that Configuration Manager relies heavily on WMI. On Configuration Manager-managed devices, do not enable this rule through a different deployment method. This test only reads the effective rule state and does not change it.

## Test design

The runner asks WMI `Win32_Process.Create` to start `cmd.exe`, which performs only one action: write a text marker beneath `%TEMP%\DefenderASRLab`. The protected child-process path is exercised without persistence, remote movement, downloads, credential access, or security-policy changes.

### Primary plan - WMI

1. Read the effective ASR action and Defender Antivirus health.
2. Delete only a marker left by an earlier run.
3. Request a local `cmd.exe` child through `Win32_Process.Create`.
4. Wait five seconds and correlate Event 1121/1122 by rule GUID.
5. Save the return values, marker state, and Defender evidence as JSON.

### Fallback plan - PsExec

If the WMI provider fails before process creation, rerun with Microsoft Sysinternals PsExec. The fallback starts the same harmless marker command as Local System. It requires an elevated PowerShell window and a separately obtained PsExec executable.

If both paths return no marker and no matching Defender event, classify the run as `Inconclusive`. Review the WMI return value, PsExec output, WMI service health, permissions, and effective ASR state before changing security policy.

## Run on Windows

Prerequisites:

- Windows 10 version 1803 or later, Windows 11, or a supported Windows Server
- Microsoft Defender Antivirus active with real-time protection
- Target rule deployed in Block mode
- Local WMI service available
- Elevated PowerShell for the PsExec fallback

From the cloned repository, run the primary WMI test:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\02-psexec-wmi-process-creation\Invoke-ASRPsexecWmiProcessTest.ps1"
```

The execution-policy override applies only to that PowerShell process. The runner does not modify Defender or tenant policy.

PsExec fallback:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\02-psexec-wmi-process-creation\Invoke-ASRPsexecWmiProcessTest.ps1" `
  -Trigger PsExec `
  -PsExecPath 'C:\Tools\PsExec64.exe'
```

## Success evidence

A successful Block validation requires both:

1. `Result` is `Blocked` and `MarkerCreated` is `False`.
2. Event ID `1121` exists after the test start time and contains GUID `d1e49aac-8f56-4280-b9ba-993a6d77406c`.

Evidence is saved to:

```text
%TEMP%\DefenderASRLab\02-psexec-wmi-process-creation\result-WMI.json
```

Manual local check:

```powershell
$rule = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1121, 1122, 1129
  StartTime = (Get-Date).AddHours(-1)
} | Where-Object { $_.ToXml() -match $rule } |
  Select-Object TimeCreated, Id, RecordId, Message
```

Event Viewer path:

```text
Applications and Services Logs
  > Microsoft
  > Windows
  > Windows Defender
  > Operational
```

Filter for Event ID `1121` and confirm the rule GUID in the event details.

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). Look for `AsrPsexecWmiChildProcessBlocked`. This rule is documented as not generating an EDR alert, so no Incident or Alert is required for a successful result.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Event 1121 + marker absent | Block succeeded | Preserve JSON and Advanced Hunting evidence. |
| Event 1122 + marker exists | Endpoint is auditing | Check policy assignment and conflicts. |
| No event + marker exists | Protected process creation was not blocked | Verify effective rule mode, Defender active mode, and exclusions. |
| No event + marker absent + WMI error | Trigger failed before ASR evaluation | Check `TriggerError`, WMI service health, and permissions; then use PsExec. |
| Local Event 1121 + no Incident/Alert | Expected for this rule | Confirm Advanced Hunting telemetry instead. |
| Event 1121 + no notification | Enforcement evidence is still valid | Record notification behavior separately; do not downgrade the block result. |
| PsExec reports access denied | PsExec did not reach the protected behavior | Run PowerShell elevated and confirm PsExec EULA/endpoint controls. |

## Optional Microsoft sample

If both inert triggers remain inconclusive, Microsoft publishes `TestFile_PsexecAndWMICreateProcess_D1E49AAC-8F56-4280-B9BA-993A6D77406C.vbs` in its ASR demonstration. Treat it as a final comparison test only: Microsoft states that demo samples can be detected as malware, quarantined, or require exclusions. Do not run Microsoft's setup or cleanup scripts without first recording all Defender and Controlled Folder Access settings because those scripts change multiple controls.

## Cleanup

The runner removes an old marker before each run. To remove all generated evidence after saving what you need:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\02-psexec-wmi-process-creation" -Recurse
```
