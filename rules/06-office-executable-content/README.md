# Rule 06 - Block Office applications from creating executable content

## Rule identity

- Rule: `Block Office applications from creating executable content`
- GUID: `3b576869-a4ec-4529-8536-b80a7769e899`
- Configured baseline: `Block`
- Dependencies: Microsoft Defender Antivirus and RPC
- Supported clients: Windows 10 version 1709 or later, Windows 11, and supported Windows Server versions
- Advanced Hunting actions: `AsrExecutableOfficeContentBlocked`, `AsrExecutableOfficeContentAudited`
- EDR alert expected: No
- User notification supported: Yes

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the rule identity, dependencies, supported platforms, reporting actions, and notification behavior.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) publishes the DOCM used here, warns that demonstration files intentionally simulate malicious behavior, and states that some samples can trigger multiple ASR rules.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event 1121 as Block, 1122 as Audit, and 1129 as Warn override.

Official sample URL:

```text
https://demo.wd.microsoft.com/Content/TestFile_Block_Office_applications_from_creating_executable_content_3b576869-a4ec-4529-8536-b80a7769e899.docm
```

Reviewed sample size: 276,775 bytes. Pinned SHA-256:

```text
785b85b4206a1bff7555df66850309e366d76951e037fe1a8d4f50caa5c424a0
```

## Observed validation

### 2026-09-02 - Antivirus preempted the official sample

The first official-sample run displayed a Windows notification and returned `Inconclusive`. Defender recorded Antivirus Event 1116, but no Event 1121 containing the target Rule ID. This proves that Antivirus detected the sample or its payload first; it does not validate Rule 06.

Before selecting a fallback, identify whether Event 1116 names the DOCM or `%TEMP%\lockysample.exe`:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1116
  StartTime = (Get-Date).AddHours(-1)
} | Select-Object -First 3 TimeCreated, Id, Message | Format-List
```

Microsoft's demonstration guidance uses an Antivirus-excluded staging folder for downloading, then runs the copied test file from a nonexcluded folder. Microsoft's ASR exclusion table also states that Rule 06 does not honor Defender Antivirus file/folder exclusions. Any diagnostic exclusion must still be temporary, exact-path only, explicitly authorized, and removed after the run.

## Objective and safety boundary

The primary test downloads Microsoft's official Rule 06 DOCM, verifies the pinned SHA-256, opens it in Word, and correlates Defender events using only the target GUID. The binary sample is not committed to this repository.

The document warns that it can download and attempt to run `lockysample.exe`, which can operate on document and media files if the ASR protection does not stop it. Consequently, the runner refuses to open it unless all of these conditions are true:

1. The operator supplies `-AcknowledgeOfficialSampleRisk`.
2. The effective target rule reports `Block`.
3. Defender Antivirus and real-time protection are active.
4. RPC is running.
5. `%TEMP%\lockysample.exe` did not exist before the run.
6. No Word process is already open.

The runner creates no Defender exclusion and changes no Defender, Office, Trust Center, or tenant policy. It tracks and removes only the copy it downloaded and `%TEMP%\lockysample.exe` when that file did not exist before the test. A cleanup manifest supports recovery after an interruption.

Use only on the disposable test endpoint. Do not select a folder containing real data if the demonstration asks for a target folder.

## Test plan

### Primary - official Microsoft download

1. Enforce the safety preflight and record Defender state.
2. Download the official DOCM and require the pinned SHA-256.
3. Open the verified document in a clean Word process.
4. Enable content only for that document and observe the result.
5. Correlate Event 1121/1122 by exact target GUID and record competing ASR or Antivirus events separately.
6. Delete runner-created artifacts and save JSON evidence.

### Fallbacks

1. If PowerShell or Defender prevents the download, manually download the same Microsoft file and provide `-MicrosoftSamplePath`; the hash requirement remains unchanged.
2. If Mark of the Web prevents the verified document from running, use `-AllowUnblockSample`. This removes the zone marker only from the hash-verified DOCM and does not weaken Office globally.
3. If Word is installed in a nonstandard location, provide its complete path with `-WordPath`.

Protected View, Office macro policy, Antivirus-only detection, or an event from only a different ASR rule is `Inconclusive`, not a successful Rule 06 block.

## Run on Windows

Prerequisites:

- Disposable Windows test endpoint with desktop Word
- Target Rule 06 deployed in Block mode
- Defender Antivirus and real-time protection active
- RPC running
- All Word windows closed
- No real data stored under the test context or `C:\demo`
- Test path not covered by Defender or ASR exclusions

Primary command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" `
  -AllowOfficialDownload `
  -AcknowledgeOfficialSampleRisk
```

When Word opens:

1. Select **Enable Editing** if shown.
2. Enable macro/content only for this verified document if Word offers the option.
3. Do not select a real data folder if prompted.
4. Observe Word and Windows Security, then close Word without saving.
5. Return to PowerShell and enter `B`, `R`, `O`, or `U` as described by the runner.

Manual-file fallback:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" `
  -MicrosoftSamplePath 'C:\Lab\TestFile_Block_Office_applications_from_creating_executable_content_3b576869-a4ec-4529-8536-b80a7769e899.docm' `
  -AcknowledgeOfficialSampleRisk
```

Mark-of-the-Web fallback, only after the normal attempt is preempted by Office:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" `
  -AllowOfficialDownload `
  -AllowUnblockSample `
  -AcknowledgeOfficialSampleRisk
```

## Success evidence

A successful Block validation requires:

1. `Result = Blocked`.
2. `ActualSampleSha256` equals the pinned hash.
3. `AsrEvents` contains Event 1121 with GUID `3b576869-a4ec-4529-8536-b80a7769e899`.
4. `CleanupSucceeded = True` and `RemainingTrackedArtifacts` is empty.

A block notification is expected, but matching Event 1121 is the decisive local evidence. This rule does not generate an EDR alert, so absence of an incident is expected.

Evidence is saved to:

```text
%TEMP%\DefenderASRLab\06-office-executable-content\result-MicrosoftSample.json
```

Manual local check:

```powershell
$rule = '3b576869-a4ec-4529-8536-b80a7769e899'
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1121, 1122, 1129
  StartTime = (Get-Date).AddHours(-1)
} | Where-Object { $_.ToXml() -match $rule } |
  Select-Object TimeCreated, Id, RecordId, Message
```

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). A successful portal result uses `AsrExecutableOfficeContentBlocked`.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Target Event 1121 | Rule 06 blocked the official demonstration | Preserve JSON, notification, and hunting evidence. |
| Target Event 1122 | Endpoint is auditing | Stop testing and check effective policy assignment. |
| Safety stop reports target rule is not Block | Running the official sample is not permitted by this runner | Correct policy deployment before retrying. |
| Download or hash validation fails | Sample was blocked, quarantined, changed, or incomplete | Do not open it; use the exact manual-file fallback or revalidate the current Microsoft hash. |
| Only another ASR rule fires | Another enabled rule preempted Rule 06 | Preserve as `Inconclusive`; inspect `OtherAsrEvents`. |
| Antivirus Event 1116/1117 without target Event 1121 | Antivirus preempted the macro | Preserve as `Inconclusive`; do not create an exclusion. |
| Office blocks macros from the internet | Mark of the Web stopped the sample first | Retry once with `-AllowUnblockSample` after confirming the pinned hash. |
| `R` selected and no target event | The protected behavior was not blocked | Close Word immediately, confirm cleanup, and investigate policy before another run. |
| `CleanupSucceeded = False` | A tracked artifact remains or Word still holds it open | Close Word and run `-CleanupOnly` immediately. |
| Local Event 1121 but portal is empty | Local enforcement succeeded; ingestion can be delayed | Retry Advanced Hunting later and verify endpoint onboarding. |

## Emergency cleanup

Close Word first, then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" -CleanupOnly
```

The command uses the cleanup manifest to avoid deleting a pre-existing `%TEMP%\lockysample.exe`. After preserving JSON evidence and confirming tracked artifacts are absent, the remaining evidence folder can be removed manually.
