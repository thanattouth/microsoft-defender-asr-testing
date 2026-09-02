# Rule 03 - Block execution of potentially obfuscated scripts

## Rule identity

- Rule: `Block execution of potentially obfuscated scripts`
- GUID: `5beb7efe-fd9a-4556-801d-275e5ffc04cc`
- Configured baseline: `Block`
- Dependencies: Microsoft Defender Antivirus, AMSI, and cloud-delivered protection
- Supported client baseline: Windows 10 version 1709 or later
- Advanced Hunting actions: `AsrObfuscatedScriptBlocked`, `AsrObfuscatedScriptAudited`
- EDR alert expected: Yes
- User notification supported: Yes

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, dependencies, Advanced Hunting actions, PowerShell support, and the requirement to enable cloud-delivered protection.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event ID 1121 as Block, 1122 as Audit, and 1129 as Warn override in the Windows Defender Operational log.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) publishes an official obfuscated JScript sample but warns that demonstration files can be detected as malware, quarantined, or blocked before the intended ASR test.

## Observed test runs

### 2026-09-02 - Runner error / Retest required

The first Windows run reached evidence collection but stopped with `The property 'Count' cannot be found on this object`. PowerShell had unrolled a zero- or one-item event array into `$null` or a scalar while `Set-StrictMode` was active. No ASR conclusion was assigned to this run.

The collector now wraps both ASR and Antivirus event results with `@(...)`, guaranteeing an array for zero, one, or many events. Retest with the same command after pulling this fix.

### 2026-09-02 - JScript v1 not triggered

The corrected runner completed with `MarkerCreated = True`, `Result = Not triggered`, and no target-rule event. This proves that the short percent-encoded script ran, but its obfuscation and direct file-write behavior did not cross the Defender heuristic.

Review of Microsoft's official sample showed a much larger obfuscated data structure followed by process launch behavior. The local primary trigger is now `xor-hex-child-process-v2`: it XOR-hex encodes a large deterministic blob and decodes it through `eval()`. The decoded behavior starts `cmd.exe` only to write the same marker. It performs no download, persistence, credential access, or security change.

### 2026-09-02 - Synthetic triggers remain inconclusive

- JScript v2 did not create its marker, but a matching Event 1121 was not reported, so the run cannot be credited as an ASR block.
- The PowerShell fallback created its marker and returned `Not triggered`, confirming that the nested Base64 marker command did not cross the target rule's heuristic.

Synthetic obfuscation is therefore retained only for diagnostics. The new primary path is Microsoft's official 63,501-byte JScript sample. The runner accepts an operator-provided copy or performs an explicitly authorized download from `demo.wd.microsoft.com`, then requires SHA-256 `cea7dbe4e275f248573c72ba75fff24362eb60143108dd909fb082f0464c70cb` before execution. The pinned sample's benign observable action is launching Notepad.

## Test design

The primary trigger uses the Microsoft-published obfuscated JScript sample referenced by the official ASR demonstration. The runner downloads it only when `-AllowOfficialDownload` is specified and refuses to execute it unless its SHA-256 matches the reviewed value. The expected non-blocked behavior is opening Notepad; the sample contains no destructive payload.

The runner separately collects target-rule Event 1121/1122 and Antivirus detection/remediation Event 1116/1117. This prevents an Antivirus signature block from being incorrectly credited to the ASR rule.

### Primary plan - Microsoft sample

1. Confirm effective rule mode, Defender health, cloud protection, script scanning, and AMSI presence.
2. Download the official sample only with explicit operator authorization, or use a supplied local copy.
3. Verify its pinned SHA-256 before executing it with `cscript.exe`.
4. Correlate ASR events by GUID and separately record Antivirus events.
5. Confirm whether Notepad started and save JSON evidence.

### Diagnostic fallbacks

The locally generated XOR-hex JScript and nested Base64 PowerShell marker tests remain available as `-Trigger JScript` and `-Trigger PowerShell`. Both failed to trigger on the first test endpoint, so they must not replace the official sample as proof of enforcement.

Microsoft warns that Defender Antivirus can detect or quarantine demonstration files before the intended ASR rule evaluates them. The runner does not create exclusions. Event 1116/1117 without the target Event 1121 remains `Inconclusive` for this rule.

## Run on Windows

Prerequisites:

- Windows 10 version 1709 or later, Windows 11, or a supported Windows Server
- Microsoft Defender Antivirus active with real-time protection
- Cloud-delivered protection enabled
- AMSI and Defender script scanning active
- Target ASR rule deployed in Block mode
- All Notepad windows closed, so the runner can reliably detect whether the sample starts it

Run the primary official-sample test from the cloned repository:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\03-obfuscated-scripts\Invoke-ASRObfuscatedScriptTest.ps1" `
  -Trigger MicrosoftSample `
  -AllowOfficialDownload
```

To use a copy downloaded manually from Microsoft's documented URL:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\03-obfuscated-scripts\Invoke-ASRObfuscatedScriptTest.ps1" `
  -Trigger MicrosoftSample `
  -MicrosoftSamplePath 'C:\Lab\TestFile_ScriptObfuscatedContent_5BEB7EFE-FD9A-4556-801D-275E5FFC04CC.js'
```

The execution-policy override applies only to the test runner process. The script does not modify Defender or tenant policy.

## Success evidence

A successful Block validation requires both:

1. `Result` is `Blocked` and `NotepadStarted` is `False`.
2. Event ID `1121` exists after the test start time and contains GUID `5beb7efe-fd9a-4556-801d-275e5ffc04cc`.

Primary evidence is saved to:

```text
%TEMP%\DefenderASRLab\03-obfuscated-scripts\result-MicrosoftSample.json
```

Manual local check:

```powershell
$rule = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
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

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). Look for `AsrObfuscatedScriptBlocked`. This rule supports EDR alerts, but portal telemetry can arrive after the local Event 1121.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Event 1121 + Notepad absent | Target ASR rule blocked the official sample | Preserve JSON, notification, and portal evidence. |
| Event 1122 + Notepad starts | Endpoint is auditing | Check effective policy assignment and conflicts. |
| Event 1116/1117 but no Event 1121 | Antivirus preempted the target ASR rule | Preserve the run as `Inconclusive`; review Protection History and do not create an exclusion merely to force the test. |
| Official sample hash mismatch | Published content changed or the file is not the reviewed sample | Do not execute it; re-download and review before updating the pinned hash. |
| `TriggerError` asks you to close Notepad | The runner cannot reliably measure the official sample's visible action | Close every Notepad window and rerun. |
| No event + Notepad starts | Target ASR rule did not trigger | Confirm effective rule state, cloud protection, AMSI, and exclusions. |
| No event + Notepad absent | Download, Antivirus, WSH, or another control stopped the sample first | Review `TriggerError`, Event 1116/1117, Protection History, and application-control policy. |
| `CloudProtectionEnabled` is `False` | Required dependency is missing | Correct tenant/device configuration before retesting. |
| Local Event 1121 but portal is empty | Local enforcement succeeded; ingestion is pending or onboarding needs review | Wait, then run Advanced Hunting and check device onboarding. |
| Synthetic PowerShell marker exists with `Not triggered` | Expected observed limitation of the diagnostic fallback | Use the verified Microsoft sample instead. |

## Cleanup

Save required evidence first, then remove generated artifacts and markers:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\03-obfuscated-scripts" -Recurse
```
