# Rule 05 - Block Win32 API calls from Office macros

## Rule identity

- Rule: `Block Win32 API calls from Office macros`
- GUID: `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b`
- Configured baseline: `Block`
- Dependencies: Microsoft Defender Antivirus and Antimalware Scan Interface (AMSI)
- Supported clients: Windows 10 version 1709 or later and Windows 11
- Windows Server support: Not applicable
- Advanced Hunting actions: `AsrOfficeMacroWin32ApiCallsBlocked`, `AsrOfficeMacroWin32ApiCallsAudited`
- EDR alert expected: Yes
- Windows user notification supported: No

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, dependencies, operating-system support, Advanced Hunting actions, EDR alert support, and lack of user-notification support.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) publishes the direct `.docm` sample used by this test and says a sample can trigger more than one rule. The runner therefore accepts only Event 1121/1122 containing this rule's GUID.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event 1121 as Block, 1122 as Audit, and 1129 as Warn override.

The reviewed official sample is 170,427 bytes with SHA-256:

```text
f0a906263537453e7860bb5fc0663eadd7e1f83f51b1290c473b069dc198d42c
```

## Observed validation

### 2026-09-02 - Official sample validated locally

The operator selected `B` after Word displayed a privilege-related message and Windows displayed a block notification. The runner then recorded Event 1121 with the exact target Rule ID `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b`. The matching Event 1121 is the decisive evidence and satisfies the local Block criteria. A notification appeared on this endpoint even though Microsoft's support table doesn't require one for this rule. Microsoft Defender XDR portal ingestion remains pending.

## Objective and safety boundary

The primary path downloads Microsoft's official demonstration document only when `-AllowOfficialDownload` is provided. Before Word opens it, the runner requires the pinned SHA-256. The document demonstrates an Office VBA macro attempting a Win32 API call; it is used only on the disposable test endpoint.

The runner does not enable macros globally, change Trust Center, create Defender exclusions, or modify Defender/tenant policy. Office interaction remains manual. Antivirus quarantine, Protected View, Mark of the Web, or an Office macro policy that stops the macro before the API call produces `Inconclusive`, not an ASR success.

## Test plan

### Primary - official Microsoft sample

1. Confirm effective rule state, Defender AV, script scanning, AMSI, and Word availability.
2. Download the official sample only with explicit authorization and verify its pinned hash.
3. Open a clean Word instance and ask the operator to enable editing/content only for this reviewed test document.
4. Correlate Event 1121/1122 by the target GUID and record Antivirus Event 1116/1117 separately.
5. Save the operator observation and JSON evidence without changing security policy.

### Fallbacks

1. If download is unavailable, manually obtain the same Microsoft sample and pass `-MicrosoftSamplePath`. The hash requirement remains identical.
2. If Word is installed in a nonstandard location, provide the full `WINWORD.EXE` path with `-WordPath`.
3. If the verified file has Mark of the Web and Office refuses to offer a safe one-file Enable Content flow, rerun with `-AllowUnblockSample`. This removes the zone marker only from the hash-verified test file; it does not change Office macro policy. Do not disable Trust Center protections globally.

## Run on Windows

Prerequisites:

- Disposable Windows 10 1709+ or Windows 11 test endpoint
- Microsoft Word desktop application installed
- All Word windows closed before starting
- Defender Antivirus, real-time protection, AMSI, and script scanning active
- Target rule deployed in Block mode
- Test location not covered by a Defender or ASR exclusion

Primary command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\05-office-macro-win32-api\Invoke-ASROfficeMacroWin32ApiTest.ps1" `
  -AllowOfficialDownload
```

When Word opens:

1. Select **Enable Editing** if shown.
2. Enable the macro/content for this reviewed test document if Word offers that option.
3. Observe the Word result, then close the test document without saving.
4. Return to PowerShell and enter `B`, `R`, `O`, or `U` as described by the runner.

Manual-file fallback:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\05-office-macro-win32-api\Invoke-ASROfficeMacroWin32ApiTest.ps1" `
  -MicrosoftSamplePath 'C:\Lab\Block_Win32_imports_from_Macro_code_in_Office_92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b.docm'
```

Mark-of-the-Web fallback, only when the primary run reports that Office preempted the macro. The runner verifies the hash before removing the one-file zone marker:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\05-office-macro-win32-api\Invoke-ASROfficeMacroWin32ApiTest.ps1" `
  -AllowOfficialDownload `
  -AllowUnblockSample
```

## Success evidence

A successful Block validation requires:

1. `Result = Blocked`.
2. `ActualSampleSha256` equals the pinned hash.
3. `AsrEvents` contains Event 1121 with GUID `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b`.

This rule supports EDR alerts but not Windows user-notification popups. Absence of a notification does not invalidate a matching local Event 1121.

Evidence is saved to:

```text
%TEMP%\DefenderASRLab\05-office-macro-win32-api\result-MicrosoftSample.json
```

Manual local check:

```powershell
$rule = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1121, 1122, 1129
  StartTime = (Get-Date).AddHours(-1)
} | Where-Object { $_.ToXml() -match $rule } |
  Select-Object TimeCreated, Id, RecordId, Message
```

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). A successful portal result uses `AsrOfficeMacroWin32ApiCallsBlocked`.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Event 1121 for target GUID | Target ASR rule blocked the Win32 API call | Preserve JSON and portal evidence; notification is not expected. |
| Event 1122 for target GUID | Endpoint is auditing | Check effective rule assignment and policy conflicts. |
| Event 1116/1117 without target Event 1121 | Antivirus preempted the macro test | Preserve as `Inconclusive`; do not add an exclusion merely to force the test. |
| Word says macros from the internet are blocked | Mark of the Web or Office policy stopped the macro first | Confirm the pinned hash, then consider the one-file `-AllowUnblockSample` fallback. |
| Office policy disables all macros | Macro never reached AMSI or the Win32 API | Preserve as `Inconclusive`; do not weaken tenant policy for this test. |
| Operator reports macro ran + no target event | Rule did not trigger | Verify effective GUID/action, Defender health, AMSI, script scanning, and exclusions. |
| Block-like Word error + no target event | Cause is not attributable to this ASR rule | Preserve as `Inconclusive` and review `TriggerError` plus Defender events. |
| Local Event 1121 but portal is empty | Local enforcement succeeded; ingestion may be pending | Wait, rerun Advanced Hunting, and verify endpoint onboarding. |

## Cleanup

Close Word and preserve the JSON evidence first. If the runner downloaded the sample, remove its output folder:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\05-office-macro-win32-api" -Recurse
```

If `-MicrosoftSamplePath` was used, delete that manually downloaded file separately when testing is complete. No policy rollback is required because the runner changes no Defender or Office settings.
