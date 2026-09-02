# Rule 06 - Block Office applications from creating executable content

## Rule identity

- Rule: `Block Office applications from creating executable content`
- GUID: `3b576869-a4ec-4529-8536-b80a7769e899`
- Configured baseline: `Block`
- Dependencies: Microsoft Defender Antivirus and RPC
- Supported clients: Windows 10 version 1709 or later and Windows 11
- Advanced Hunting actions: `AsrExecutableOfficeContentBlocked`, `AsrExecutableOfficeContentAudited`
- EDR alert expected: No
- User notification supported: Yes

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, dependencies, supported platforms, Advanced Hunting actions, alert behavior, and that the rule blocks access to or execution of untrusted executable files saved by Office macros.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) publishes a Rule 06 DOCM but warns that demonstration files intentionally simulate malicious behavior and can trigger multiple rules.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event 1121 as Block, 1122 as Audit, and 1129 as Warn override.
- [Microsoft ADO `SaveToFile` reference](https://learn.microsoft.com/en-us/office/client-developer/access/desktop-database-reference/savetofile-method-ado) documents the binary stream operation used by the primary benign macro.

### Why the official DOCM is not used

The official Rule 06 document was inspected during research. Its visible warning states that its dropped executable attempts to encrypt `.docx`, `.xlsx`, `.pptx`, `.bmp`, `.jpg`, `.txt`, `.wav`, and `.pdf` files under a selected folder or `C:\demo` by default. It is intentionally excluded from this repository and runner. This project does not create a Defender exclusion or execute an encryption demonstration.

## Objective and safety boundary

The runner compiles a local .NET executable whose only behavior is writing `payload-ran.txt` under `%TEMP%\DefenderASRLab\06-office-executable-content`. It never reads, modifies, encrypts, or deletes user files. The runner does not execute it directly.

The generated VBA module copies that marker-only executable to a second lab path and asks Office to launch the copy. The primary macro uses `ADODB.Stream`; the fallback uses VBA binary file I/O. The runner correlates only the target GUID and records other ASR events separately because Rule 08, Rule 09, or Rule 13 might preempt execution. Both executable files are deleted after evidence collection.

The runner changes no Defender, Office, Trust Center, or tenant policy. VBA import and execution remain manual, and the blank Word document must be closed without saving.

## Test plan

### Primary - ADODB.Stream

1. Confirm effective rule state, Defender health, RPC, and Word availability.
2. Compile the marker-only executable locally and generate a path-specific `.bas` module.
3. Open a blank Word instance and manually import the module.
4. Run `RunRule06Test`, then correlate Event 1121/1122 by target GUID.
5. Record any competing ASR or Antivirus events, delete both executable artifacts, and save JSON evidence.

### Fallback - VBA binary I/O

If `CreateObject("ADODB.Stream")` fails without a target ASR event, rerun with `-Trigger VbaBinary`. The fallback reads and writes the same marker-only executable using native VBA binary file operations. Its execution, evidence, and cleanup boundaries are identical.

An Office policy block, VBA import restriction, or event from only a different ASR rule is `Inconclusive`, not proof that Rule 06 fired.

## Run on Windows

Prerequisites:

- Disposable Windows 10 1709+, Windows 11, or supported Windows device with desktop Word
- All Word windows closed before starting
- Microsoft Defender Antivirus and real-time protection active
- RPC service running
- Target Rule 06 deployed in Block mode
- VBA editor and manual macro execution allowed on the test endpoint

Primary command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1"
```

When blank Word opens:

1. Press `Alt+F11`.
2. In the VBA editor, select **File > Import File**.
3. Import the exact `.bas` path printed by the runner.
4. Place the cursor inside `RunRule06Test` and press `F5`.
5. Observe the result, close Word without saving, then answer the PowerShell prompt.

Fallback after an ADODB-specific error without target Event 1121:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" -Trigger VbaBinary
```

## Success evidence

A successful Block validation requires all of the following:

1. `Result = Blocked`.
2. `PayloadRan = False`.
3. `AsrEvents` contains Event 1121 with GUID `3b576869-a4ec-4529-8536-b80a7769e899`.
4. `CleanupSucceeded = True` and `RemainingExecutableArtifacts` is empty.

`DroppedPayloadCreatedBeforeCleanup` can be either `True` or `False`; this rule can block access to or execution of executable content after Office writes it. A user notification is supported, but the target Event 1121 remains the decisive evidence. This rule doesn't generate an EDR alert; use Advanced Hunting/ASR reporting rather than waiting for an incident.

Evidence is saved to:

```text
%TEMP%\DefenderASRLab\06-office-executable-content\result-AdodbStream.json
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

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). A successful result uses `AsrExecutableOfficeContentBlocked`.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Target Event 1121 + payload marker absent | Rule 06 blocked the Office-created executable | Preserve JSON, notification, and hunting evidence. |
| Target Event 1122 | Endpoint is auditing | Check effective policy assignment and policy conflicts. |
| Only another ASR Rule ID appears | Rule 08, 09, or 13 preempted the target behavior | Preserve as `Inconclusive`; do not credit Rule 06. |
| ADODB object error + no target event | Primary method did not reach the protected behavior | Rerun with `-Trigger VbaBinary`. |
| VBA editor/import is blocked | Office policy stopped the macro first | Preserve as `Inconclusive`; do not weaken tenant policy for this test. |
| `PayloadRan = True` + no target event | Marker-only executable ran | Rule 06 did not trigger; verify effective rule state and exclusions. |
| `CleanupSucceeded = False` | A generated executable remains | Run `-CleanupOnly` immediately. |
| Local target Event 1121 but portal is empty | Local enforcement succeeded; telemetry may be delayed | Run Advanced Hunting later and verify endpoint onboarding. |

## Emergency cleanup

The runner deletes both executable files automatically. If interrupted, close Word and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\06-office-executable-content\Invoke-ASROfficeExecutableContentTest.ps1" -CleanupOnly
```

After preserving JSON evidence, remove the remaining macro source, marker, and output directory:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\06-office-executable-content" -Recurse
```
