# Rule 01 - Block Adobe Reader from creating child processes

## Rule identity

- Rule: `Block Adobe Reader from creating child processes`
- GUID: `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c`
- Configured baseline: `Block`
- Dependency: Microsoft Defender Antivirus
- Supported client baseline: Windows 10 version 1809 or later
- Advanced Hunting actions: `AsrAdobeReaderChildProcessBlocked`, `AsrAdobeReaderChildProcessAudited`

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, dependency, action types, limited exclusion support, and cloud protection caveats.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event ID 1121 as Block, 1122 as Audit, and 1129 as Warn override in the Windows Defender Operational log.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) does not include a sample for this Adobe rule, so this project generates its own inert PDF.
- [Adobe security warning guidance](https://helpx.adobe.com/acrobat/desktop/protect-documents/mitigate-security-risks/respond-warnings.html) explains that Acrobat can display its own warning before an embedded action runs.

Microsoft documents extra cloud protection requirements for this rule: EDR alerts require cloud protection level `High plus` or `Zero tolerance`, while user notifications require `High`, `High plus`, or `Zero tolerance`. Local enforcement and Event 1121 are therefore the primary test oracle; absence of a portal alert alone is not a failed block.

## Test design

The PowerShell runner generates a PDF with a visible link annotation. The primary `Notepad` trigger asks Adobe to launch the harmless Windows Notepad executable. In Block mode, Notepad should not start and Windows Defender should log Event 1121 containing the rule GUID.

The script changes no Defender, Adobe, Intune, or tenant settings. It writes only a generated PDF and JSON evidence under `%TEMP%\DefenderASRLab`.

### Primary plan

1. Preflight Microsoft Defender state and the configured ASR action.
2. Generate the benign Notepad-launch PDF.
3. Start the PDF explicitly with Adobe Acrobat or Reader.
4. Let the operator click the test box and accept Adobe's warning for this known lab file.
5. Correlate Defender events created after the test start time by Rule GUID.
6. Save a machine-readable result in JSON.

### Fallback plan

If Adobe blocks the Launch action before it reaches Defender, rerun with `-Trigger Browser`. This PDF uses a normal HTTPS URI to `example.com`. Close browser windows first so Adobe must attempt a new process.

If neither trigger produces a Defender event, confirm in Task Manager, Process Explorer, or the Defender device timeline whether Adobe actually attempted to create a child. No attempted child means `Inconclusive`, not an ASR failure. Do not disable Enhanced Security as the first troubleshooting step.

## Run on Windows

Prerequisites:

- Windows 10 1809 or later, or a supported Windows 11 build
- Microsoft Defender Antivirus active with real-time protection
- Adobe Acrobat or Acrobat Reader installed locally
- The ASR rule deployed in Block mode

Open Windows PowerShell in the cloned repository. Administrator rights are useful for consistent event-log access but the script does not change policy.

```powershell
.\rules\01-adobe-reader-child-process\Invoke-ASRAdobeReaderChildProcessTest.ps1
```

In Adobe, click `RUN HARMLESS ASR TEST`, approve Adobe's external-application prompt for this lab PDF if shown, wait about 10 seconds, then return to PowerShell and press Enter.

If Adobe is installed in a nonstandard location:

```powershell
.\rules\01-adobe-reader-child-process\Invoke-ASRAdobeReaderChildProcessTest.ps1 `
  -AdobePath 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'
```

Fallback:

```powershell
.\rules\01-adobe-reader-child-process\Invoke-ASRAdobeReaderChildProcessTest.ps1 -Trigger Browser
```

## Success evidence

A successful Block validation requires both:

1. Notepad does not open.
2. Event ID `1121` exists after the test start time and contains Rule GUID `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c`.

The runner reports `Blocked` only when those conditions are met. It saves evidence to:

```text
%TEMP%\DefenderASRLab\01-adobe-reader-child-process\result-Notepad.json
```

Manual local check:

```powershell
$rule = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
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

Filter for Event ID `1121`, open the event, and confirm the Adobe rule GUID in the details.

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). Portal telemetry can arrive later than the local event.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Event 1121 + Notepad absent | Block succeeded | Preserve JSON and portal evidence. |
| Event 1122 + Notepad opens | Rule is auditing on the endpoint | Check policy assignment and conflicts. |
| No event + Notepad opens | Protected behavior was not blocked | Verify rule state, Defender active mode, exclusions, and policy refresh. |
| No event + Notepad absent | Adobe likely stopped the action first | Use the Browser fallback and verify the real process tree. |
| Local Event 1121 but no portal alert | Local block succeeded; alert prerequisites or ingestion may differ | Run the hunting query and check cloud protection level/onboarding. |
| PDF opens in Edge/Chrome | Wrong PDF handler; test is invalid | Use `-AdobePath` and rerun. |

## Cleanup

Close Adobe and any Notepad/browser window created during a non-blocking control. The generated files are disposable:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\01-adobe-reader-child-process" -Recurse
```
