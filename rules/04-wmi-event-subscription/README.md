# Rule 04 - Block persistence through WMI event subscription

## Rule identity

- Rule: `Block persistence through WMI event subscription`
- GUID: `e6db77e5-3df2-4cf1-b95a-636979351e5b`
- Configured baseline: `Block`
- Dependencies: Microsoft Defender Antivirus and RPC
- Supported clients: Windows 10 version 1903 or later and Windows 11
- Supported servers: Windows Server version 1903 SAC or later; not Windows Server 2012 R2 or 2016 through the modern unified solution
- Advanced Hunting actions: `AsrPersistenceThroughWmiBlocked`, `AsrPersistenceThroughWmiAudited`
- EDR alert expected: Yes
- User notification supported: Yes

## Research notes

Reviewed on 2026-09-02:

- [Microsoft ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) confirms the GUID, platform support, dependencies, notification behavior, and Advanced Hunting actions. Microsoft also warns that Configuration Manager relies heavily on WMI and recommends extensive Audit-mode testing before Block deployment in that environment.
- [Microsoft ASR events reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events) defines Event 1121 as Block, 1122 as Audit, and 1129 as Warn override.
- [Microsoft ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules) explicitly lists this rule among those not tested by Microsoft's downloadable sample files.
- [Microsoft WMI binding reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/binding-an-event-filter-with-a-logical-consumer) documents that a permanent subscription is registered by linking a filter and consumer with `__FilterToConsumerBinding`, and that removing the binding deactivates the registration.
- [Microsoft command-line consumer reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/running-a-program-from-the-command-line-based-on-an-event) documents `CommandLineEventConsumer` and its local-administrator requirement.

## Objective and safety boundary

The test attempts to register one temporary permanent WMI event subscription in `root\subscription`. It uses the exact object name `DefenderASRLab_Rule04` and consists of:

1. An `__EventFilter` watching for creation of a randomized process name that does not exist.
2. A `CommandLineEventConsumer` whose only possible action is asking the system `cmd.exe` to write a harmless marker under `%TEMP%`.
3. An `__FilterToConsumerBinding` connecting them.

The runner never creates the randomized process, so the consumer is never invoked. It changes no security policy and uses no network connection. The subscription exists only long enough to measure enforcement. A `finally` block removes the binding, consumer, and filter in that order and verifies that no test objects remain.

## Observed validation

### 2026-09-02 - Primary trigger validated locally

The PowerShell WMI test returned `Result = Blocked`, recorded a matching target-rule Event 1121, displayed a Windows block notification, and reported `CleanupSucceeded = True`. This satisfies the documented local success criteria. Microsoft Defender XDR portal ingestion remains pending.

## Test plan

### Primary - PowerShell WMI API

1. Confirm effective rule state, Defender AV, administrator rights, RPC, and WMI service state.
2. Remove only stale objects with the exact lab name.
3. Create the inert filter, never-triggered command consumer, and binding with Windows PowerShell WMI commands.
4. Correlate Defender Event 1121/1122 by the target GUID and capture matching WMI activity.
5. Remove all exact-name test objects and save JSON evidence.

### Fallback - MOF compiler

If the PowerShell WMI provider returns an unrelated provider or serialization error without a target ASR event, rerun with `-Trigger MofComp`. This generates an equivalent inert MOF file and compiles it using the system `%SystemRoot%\System32\wbem\mofcomp.exe`. Cleanup and success criteria remain identical.

An access-denied result without target Event 1121 is `Inconclusive`, not proof that ASR blocked the attempt.

## Run on Windows

Prerequisites:

- A disposable test endpoint running a supported Windows version
- Target ASR rule deployed in Block mode
- Microsoft Defender Antivirus and real-time protection active
- RPC and Windows Management Instrumentation services running
- Windows PowerShell 5.1 opened with **Run as administrator**
- Avoid running this validation on a Configuration Manager-managed production endpoint

Primary test:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\04-wmi-event-subscription\Invoke-ASRWmiPersistenceTest.ps1"
```

Fallback only after an inconclusive primary run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\04-wmi-event-subscription\Invoke-ASRWmiPersistenceTest.ps1" -Trigger MofComp
```

## Success evidence

A successful Block validation requires all of the following:

1. `Result = Blocked`.
2. A target-rule Event 1121 is included in `AsrEvents`.
3. `SubscriptionCompletedBeforeCleanup = False`.
4. `CleanupSucceeded = True` and `RemainingArtifactsAfterCleanup = 0`.
5. The marker remains absent. A notification and portal alert are expected but can arrive separately from the local event.

Evidence is saved to:

```text
%TEMP%\DefenderASRLab\04-wmi-event-subscription\result-PowerShellWmi.json
```

Manual Defender event check:

```powershell
$rule = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
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

For Microsoft Defender XDR, open **Hunting > Advanced hunting** and run [advanced-hunting.kql](advanced-hunting.kql). A successful portal result uses `AsrPersistenceThroughWmiBlocked`.

## Troubleshooting decisions

| Observation | Interpretation | Next action |
|---|---|---|
| Event 1121 + subscription incomplete + cleanup succeeded | Target ASR rule blocked the registration | Preserve JSON, notification, and portal evidence. |
| Event 1122 + subscription completed | Rule is auditing | Check effective policy assignment and policy conflicts. |
| No target event + subscription completed | Target rule did not trigger | Confirm GUID/action, Defender AV health, OS support, and exclusions. |
| Access denied + no Event 1121 | Session is not elevated or WMI permissions blocked the test first | Open Windows PowerShell as administrator and rerun. |
| RPC or Winmgmt is not running | A dependency stopped the test before ASR evaluation | Restore the test endpoint service state, then rerun. |
| PowerShell WMI provider error + no target event | Primary method was inconclusive | Use `-Trigger MofComp`. |
| `CleanupSucceeded = False` | One or more exact-name test objects remain | Run `-CleanupOnly` immediately and verify zero remaining artifacts. |
| Local Event 1121 but portal is empty | Local enforcement succeeded; ingestion may be pending | Wait, then rerun Advanced Hunting and verify endpoint onboarding. |

## Emergency cleanup and verification

The runner cleans up automatically. If it is interrupted, open elevated Windows PowerShell and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\rules\04-wmi-event-subscription\Invoke-ASRWmiPersistenceTest.ps1" -CleanupOnly
```

The command must report that no objects named `DefenderASRLab_Rule04` remain. After preserving evidence, remove the local output directory:

```powershell
Remove-Item -LiteralPath "$env:TEMP\DefenderASRLab\04-wmi-event-subscription" -Recurse
```
