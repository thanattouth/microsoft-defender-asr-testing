#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('WMI', 'PsExec')]
    [string]$Trigger = 'WMI',

    [string]$PsExecPath,

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\02-psexec-wmi-process-creation')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
$RuleName = 'Block process creations originating from PsExec and WMI commands'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'

function Get-ASRRuleState {
    param([Parameter(Mandatory)][string]$Id)

    $preference = Get-MpPreference
    $ids = @($preference.AttackSurfaceReductionRules_Ids)
    $actions = @($preference.AttackSurfaceReductionRules_Actions)
    $actionNames = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        5 = 'Not configured'
        6 = 'Warn'
    }

    for ($index = 0; $index -lt [Math]::Min($ids.Count, $actions.Count); $index++) {
        if ([string]$ids[$index] -eq $Id) {
            $numericAction = [int]$actions[$index]
            $displayAction = if ($actionNames.ContainsKey($numericAction)) {
                $actionNames[$numericAction]
            }
            else {
                "Unknown ($numericAction)"
            }
            return [pscustomobject]@{
                Id = $Id
                Action = $displayAction
                ActionValue = $numericAction
            }
        }
    }

    return [pscustomobject]@{ Id = $Id; Action = 'Not configured'; ActionValue = 5 }
}

function Get-MatchingASREvents {
    param(
        [Parameter(Mandatory)][datetime]$Since,
        [Parameter(Mandatory)][string]$Id
    )

    $events = Get-WinEvent -FilterHashtable @{
        LogName = $DefenderLog
        Id = 1121, 1122, 1129
        StartTime = $Since.AddSeconds(-2)
    } -ErrorAction SilentlyContinue

    return @($events | Where-Object { $_.ToXml() -match [regex]::Escape($Id) })
}

function Resolve-PsExecExecutable {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (-not (Test-Path -LiteralPath $RequestedPath -PathType Leaf)) {
            throw "PsExec executable was not found at: $RequestedPath"
        }
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    foreach ($name in @('PsExec64.exe', 'PsExec.exe')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    throw 'PsExec was not found. Pass -PsExecPath with the full path to the Microsoft Sysinternals executable.'
}

foreach ($requiredCommand in @('Get-MpPreference', 'Get-MpComputerStatus', 'Get-WinEvent', 'Invoke-CimMethod')) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this test on a supported Windows device with Microsoft Defender Antivirus."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$markerPath = Join-Path $OutputDirectory "marker-$Trigger.txt"
$resultPath = Join-Path $OutputDirectory "result-$Trigger.json"

if (Test-Path -LiteralPath $markerPath) {
    Remove-Item -LiteralPath $markerPath -Force
}

$ruleState = Get-ASRRuleState -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$startedAt = Get-Date
$triggerError = $null
$triggerDetail = $null
$wmiReturnValue = $null
$wmiProcessId = $null
$psExecExitCode = $null
$psExecOutput = @()

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "Trigger: $Trigger"
Write-Host "Marker path: $markerPath"

if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}

$payload = "echo defender-asr-rule-02> `"$markerPath`""

try {
    if ($Trigger -eq 'WMI') {
        $commandLine = '"{0}" /d /c {1}' -f $env:ComSpec, $payload
        $triggerDetail = $commandLine
        $wmiResult = Invoke-CimMethod -Namespace 'root/cimv2' -ClassName 'Win32_Process' -MethodName 'Create' -Arguments @{
            CommandLine = $commandLine
        }
        $wmiReturnValue = [int]$wmiResult.ReturnValue
        $wmiProcessId = [int]$wmiResult.ProcessId
    }
    else {
        $resolvedPsExec = Resolve-PsExecExecutable -RequestedPath $PsExecPath
        $triggerDetail = $resolvedPsExec
        $psExecOutput = @(& $resolvedPsExec -accepteula -nobanner -s $env:ComSpec /d /c $payload 2>&1 | ForEach-Object { $_.ToString() })
        $psExecExitCode = $LASTEXITCODE
    }
}
catch {
    $triggerError = $_.Exception.Message
    Write-Warning "Trigger returned an error: $triggerError"
}

Start-Sleep -Seconds 5

$events = Get-MatchingASREvents -Since $startedAt -Id $RuleId
$blockEvents = @($events | Where-Object Id -eq 1121)
$auditEvents = @($events | Where-Object Id -eq 1122)
$markerCreated = Test-Path -LiteralPath $markerPath

if ($blockEvents.Count -gt 0 -and -not $markerCreated) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for this rule and the benign marker file was not created.'
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for this rule. Audit mode observes but does not block.'
}
elseif ($markerCreated -and $events.Count -eq 0) {
    $resultState = 'Not triggered'
    $explanation = 'The WMI or PsExec child process created the marker and no matching Defender ASR event was found.'
}
else {
    $resultState = 'Inconclusive'
    $explanation = 'The marker and Defender event evidence do not establish a clean block, audit, or non-trigger result. Review the trigger return data.'
}

$eventSummary = @($events | ForEach-Object {
    [pscustomobject]@{
        EventId = $_.Id
        RecordId = $_.RecordId
        TimeCreated = $_.TimeCreated
        Message = $_.Message
    }
})

$result = [pscustomobject]@{
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    RuleId = $RuleId
    RuleName = $RuleName
    ConfiguredAction = $ruleState.Action
    DefenderAntivirusEnabled = $defenderStatus.AntivirusEnabled
    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
    Trigger = $Trigger
    TriggerDetail = $triggerDetail
    TriggerError = $triggerError
    WmiReturnValue = $wmiReturnValue
    WmiProcessId = $wmiProcessId
    PsExecExitCode = $psExecExitCode
    PsExecOutput = $psExecOutput
    MarkerPath = $markerPath
    MarkerCreated = $markerCreated
    Result = $resultState
    Explanation = $explanation
    Events = $eventSummary
}

$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"
