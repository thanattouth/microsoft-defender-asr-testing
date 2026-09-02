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

## Test design

The primary trigger generates a JScript whose readable source is percent-encoded and executed through `eval(unescape())`. After decoding, the script performs only one action: use `Scripting.FileSystemObject` to write a marker under `%TEMP%\DefenderASRLab`. It launches no child process, downloads nothing, and changes no persistence or security settings.

The runner separately collects target-rule Event 1121/1122 and Antivirus detection/remediation Event 1116/1117. This prevents an Antivirus signature block from being incorrectly credited to the ASR rule.

### Primary plan - JScript

1. Confirm effective rule mode, Defender health, cloud protection, script scanning, and AMSI presence.
2. Generate the harmless percent-encoded `.js` artifact locally without Mark of the Web.
3. Execute it with `cscript.exe` and wait for Defender evaluation.
4. Correlate ASR events by GUID and separately record Antivirus events.
5. Confirm whether the decoded script created its marker and save JSON evidence.

### Fallback plan - PowerShell

If Windows Script Host is disabled or the JScript heuristic does not trigger, use the PowerShell fallback. It starts Windows PowerShell with an `EncodedCommand` containing a second Base64 layer. The decoded command only writes the same benign marker.

If both local triggers are inconclusive, compare with Microsoft's official `TestFile_ScriptObfuscatedContent_5BEB7EFE-FD9A-4556-801D-275E5FFC04CC.js`. Use it only on the test endpoint and account for Antivirus quarantine or Protection History entries before concluding that ASR fired.

## Run on Windows

Prerequisites:

- Windows 10 version 1709 or later, Windows 11, or a supported Windows Server
- Microsoft Defender Antivirus active with real-time protection
- Cloud-delivered protection enabled
- AMSI and Defender script scanning active
- Target ASR rule deployed in Block mode

Run the primary JScript test from the cloned repository:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\03-obfuscated-scripts\Invoke-ASRObfuscatedScriptTest.ps1"
```

PowerShell fallback:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\03-obfuscated-scripts\Invoke-ASRObfuscatedScriptTest.ps1" -Trigger PowerShell
```

The execution-policy override applies only to the test runner process. The script does not modify Defender or tenant policy.

## Success evidence

A successful Block validation requires both:

1. `Result` is `Blocked` and `MarkerCreated` is `False`.
2. Event ID `1121` exists after the test start time and contains GUID `5beb7efe-fd9a-4556-801d-275e5ffc04cc`.

Primary evidence is saved to:

```text
%TEMP%\DefenderASRLab\03-obfuscated-scripts\result-JScript.json
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
| Event 1121 + marker absent | Target ASR rule blocked execution | Preserve JSON, notification, and portal evidence. |
| Event 1122 + marker exists | Endpoint is auditing | Check effective policy assignment and conflicts. |
| Event 1116/1117 but no Event 1121 | Antivirus preempted the target ASR rule | Review Protection History and use the alternate local trigger. |
| No event + marker exists | Obfuscation heuristic did not trigger | Confirm cloud protection and use the PowerShell fallback. |
| No event + marker absent | Trigger failed before conclusive evaluation | Review `TriggerError`, `ProcessExitCode`, script scanning, and application-control policy. |
| `CloudProtectionEnabled` is `False` | Required dependency is missing | Correct tenant/device configuration before retesting. |
| Local Event 1121 but portal is empty | Local enforcement succeeded; ingestion is pending or onboarding needs review | Wait, then run Advanced Hunting and check device onboarding. |

## Cleanup

Save required evidence first, then remove generated artifacts and markers:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\03-obfuscated-scripts" -Recurse
```
