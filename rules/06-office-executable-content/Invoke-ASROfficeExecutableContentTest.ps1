#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('AdodbStream', 'VbaBinary')]
    [string]$Trigger = 'AdodbStream',

    [string]$WordPath,

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\06-office-executable-content'),

    [ValidateRange(1, 60)]
    [int]$WaitSeconds = 10,

    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = '3b576869-a4ec-4529-8536-b80a7769e899'
$RuleName = 'Block Office applications from creating executable content'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'

function Get-ASRRuleState {
    param(
        [Parameter(Mandatory)]$Preference,
        [Parameter(Mandatory)][string]$Id
    )

    $ids = @($Preference.AttackSurfaceReductionRules_Ids)
    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
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

function Get-ASREvents {
    param([Parameter(Mandatory)][datetime]$Since)

    return @(Get-WinEvent -FilterHashtable @{
        LogName = $DefenderLog
        Id = 1121, 1122, 1129
        StartTime = $Since.AddSeconds(-2)
    } -ErrorAction SilentlyContinue)
}

function Get-AntivirusEvents {
    param([Parameter(Mandatory)][datetime]$Since)

    return @(Get-WinEvent -FilterHashtable @{
        LogName = $DefenderLog
        Id = 1116, 1117
        StartTime = $Since.AddSeconds(-2)
    } -ErrorAction SilentlyContinue)
}

function Get-WordExecutablePath {
    param([string]$OverridePath)

    if ($OverridePath) {
        if (Test-Path -LiteralPath $OverridePath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $OverridePath).Path
        }
        return $null
    }

    $command = Get-Command WINWORD.EXE -ErrorAction SilentlyContinue
    if ($command -and (Test-Path -LiteralPath $command.Path -PathType Leaf)) {
        return $command.Path
    }

    foreach ($keyPath in @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE'
    )) {
        $key = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
        if ($key) {
            $candidate = [string]$key.GetValue('')
            if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                return $candidate
            }
        }
    }

    $candidates = @()
    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($programFiles) {
        $candidates += Join-Path $programFiles 'Microsoft Office\root\Office16\WINWORD.EXE'
    }
    if ($programFilesX86) {
        $candidates += Join-Path $programFilesX86 'Microsoft Office\root\Office16\WINWORD.EXE'
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function ConvertTo-VbaStringLiteral {
    param([Parameter(Mandatory)][string]$Value)

    return $Value.Replace('"', '""')
}

function ConvertTo-EventSummary {
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Events)

    return @($Events | ForEach-Object {
        [pscustomobject]@{
            EventId = $_.Id
            RecordId = $_.RecordId
            TimeCreated = $_.TimeCreated
            Message = $_.Message
        }
    })
}

$sourcePayloadPath = Join-Path $OutputDirectory 'source-marker-only.exe'
$droppedPayloadPath = Join-Path $OutputDirectory 'office-created-marker-only.exe'
$markerPath = Join-Path $OutputDirectory 'payload-ran.txt'
$macroPath = Join-Path $OutputDirectory "Rule06-$Trigger.bas"
$resultPath = Join-Path $OutputDirectory "result-$Trigger.json"

if ($CleanupOnly) {
    foreach ($path in @($sourcePayloadPath, $droppedPayloadPath, $markerPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    Write-Host 'Cleanup complete. No generated executable or marker artifact remains.'
    return
}

foreach ($requiredCommand in @(
    'Add-Type',
    'Get-MpPreference',
    'Get-MpComputerStatus',
    'Get-WinEvent',
    'Get-FileHash'
)) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this test with Windows PowerShell 5.1 on a supported Windows device."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

foreach ($path in @($sourcePayloadPath, $droppedPayloadPath, $markerPath)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
}

$preference = Get-MpPreference
$ruleState = Get-ASRRuleState -Preference $preference -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$rpcService = Get-Service -Name RpcSs -ErrorAction SilentlyContinue
$rpcServiceStatus = if ($rpcService) { [string]$rpcService.Status } else { 'Unavailable' }
$resolvedWordPath = Get-WordExecutablePath -OverridePath $WordPath
$existingWordIds = @(Get-Process WINWORD -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$startedAt = Get-Date
$triggerError = $null
$wordProcessId = $null
$wordProcessStarted = $false
$operatorObservation = 'Unknown'
$sourcePayloadSha256 = $null
$droppedPayloadSha256 = $null
$droppedPayloadCreated = $false
$payloadRan = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "RPC service: $rpcServiceStatus"
Write-Host "Word path: $resolvedWordPath"
Write-Host "Trigger: $Trigger"

if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}
if ($null -eq $rpcService -or $rpcService.Status -ne 'Running') {
    Write-Warning 'The RPC service is not running. Microsoft lists RPC as a dependency for this rule.'
}

try {
    if ($existingWordIds.Count -gt 0) {
        throw 'Close every Microsoft Word window before running this test.'
    }
    if (-not $resolvedWordPath) {
        throw 'Microsoft Word was not found. Install desktop Word or provide its full WINWORD.EXE path with -WordPath.'
    }

    $className = "DefenderASRRule06Payload_$([Guid]::NewGuid().ToString('N'))"
    $csharpMarkerPath = $markerPath.Replace('"', '""')
    $sourceCode = @"
using System;
using System.IO;

public static class $className
{
    [STAThread]
    public static void Main()
    {
        File.WriteAllText(@"$csharpMarkerPath", "defender-asr-rule-06-benign-marker");
    }
}
"@
    Add-Type -TypeDefinition $sourceCode -Language CSharp -OutputAssembly $sourcePayloadPath -OutputType WindowsApplication | Out-Null
    if (-not (Test-Path -LiteralPath $sourcePayloadPath -PathType Leaf)) {
        throw 'The marker-only test executable was not generated.'
    }
    $sourcePayloadSha256 = (Get-FileHash -LiteralPath $sourcePayloadPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $vbaSourcePath = ConvertTo-VbaStringLiteral -Value $sourcePayloadPath
    $vbaDroppedPath = ConvertTo-VbaStringLiteral -Value $droppedPayloadPath
    if ($Trigger -eq 'AdodbStream') {
        $macroBody = @"
    Dim binaryStream As Object
    Set binaryStream = CreateObject("ADODB.Stream")
    binaryStream.Type = 1
    binaryStream.Open
    binaryStream.LoadFromFile sourcePath
    binaryStream.SaveToFile droppedPath, 2
    binaryStream.Close
"@
    }
    else {
        $macroBody = @"
    Dim inputHandle As Integer
    Dim outputHandle As Integer
    Dim payload() As Byte
    inputHandle = FreeFile
    Open sourcePath For Binary Access Read As #inputHandle
    ReDim payload(0 To LOF(inputHandle) - 1)
    Get #inputHandle, , payload
    Close #inputHandle
    outputHandle = FreeFile
    Open droppedPath For Binary Access Write As #outputHandle
    Put #outputHandle, , payload
    Close #outputHandle
"@
    }

    $macroContent = @"
Attribute VB_Name = "Rule06BenignTest"
Option Explicit

Public Sub RunRule06Test()
    On Error GoTo TestStopped
    Dim sourcePath As String
    Dim droppedPath As String
    Dim taskId As Variant
    sourcePath = "$vbaSourcePath"
    droppedPath = "$vbaDroppedPath"
$macroBody
    taskId = Shell(Chr`$(34) & droppedPath & Chr`$(34), vbHide)
    MsgBox "The benign marker-only executable was allowed to start.", vbInformation, "ASR Rule 06 Test"
    Exit Sub

TestStopped:
    MsgBox "The test stopped: " & Err.Number & " - " & Err.Description, vbExclamation, "ASR Rule 06 Test"
End Sub
"@
    [IO.File]::WriteAllText($macroPath, $macroContent, [Text.Encoding]::ASCII)

    $wordProcess = Start-Process -FilePath $resolvedWordPath -ArgumentList '/n' -PassThru
    $wordProcessId = $wordProcess.Id
    Start-Sleep -Seconds 2
    $wordProcessStarted = $null -ne (Get-Process -Id $wordProcessId -ErrorAction SilentlyContinue)
    if (-not $wordProcessStarted) {
        throw 'Microsoft Word exited before the macro could be imported.'
    }

    Write-Host ''
    Write-Host 'A blank Word instance is open. Perform these steps without saving the document:' -ForegroundColor Cyan
    Write-Host '  1. Press Alt+F11 to open the VBA editor.'
    Write-Host '  2. Select File > Import File and import:'
    Write-Host "     $macroPath"
    Write-Host '  3. Place the cursor inside RunRule06Test and press F5.'
    Write-Host '  4. Observe the Word/Defender result, then close Word without saving.'
    Write-Host 'Enter one result after closing Word:' -ForegroundColor Cyan
    Write-Host '  B = a block notification or macro error appeared'
    Write-Host '  R = the benign payload ran and created its marker'
    Write-Host '  O = Office policy prevented VBA import or macro execution'
    Write-Host '  U = unsure'
    $operatorInputRaw = Read-Host 'Result [B/R/O/U]'
    $operatorInput = if ($operatorInputRaw) { $operatorInputRaw.Trim().ToUpperInvariant() } else { 'U' }
    $operatorObservation = switch ($operatorInput) {
        'B' { 'BlockObserved' }
        'R' { 'PayloadRan' }
        'O' { 'OfficePreempted' }
        default { 'Unknown' }
    }
}
catch {
    $triggerError = $_.Exception.Message
    Write-Warning "Trigger returned an error: $triggerError"
}

Start-Sleep -Seconds $WaitSeconds
$allAsrEvents = @(Get-ASREvents -Since $startedAt)
$targetAsrEvents = @($allAsrEvents | Where-Object { $_.ToXml() -match [regex]::Escape($RuleId) })
$otherAsrEvents = @($allAsrEvents | Where-Object { $_.ToXml() -notmatch [regex]::Escape($RuleId) })
$antivirusEvents = @(Get-AntivirusEvents -Since $startedAt)
$blockEvents = @($targetAsrEvents | Where-Object Id -eq 1121)
$auditEvents = @($targetAsrEvents | Where-Object Id -eq 1122)
$droppedPayloadCreated = Test-Path -LiteralPath $droppedPayloadPath
$payloadRan = Test-Path -LiteralPath $markerPath
if ($droppedPayloadCreated) {
    try {
        $droppedPayloadSha256 = (Get-FileHash -LiteralPath $droppedPayloadPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    catch {
        $triggerError = "The Office-created executable disappeared before hashing: $($_.Exception.Message)"
        $droppedPayloadCreated = Test-Path -LiteralPath $droppedPayloadPath
    }
}

foreach ($path in @($sourcePayloadPath, $droppedPayloadPath)) {
    if (Test-Path -LiteralPath $path) {
        try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add("$path cleanup failed: $($_.Exception.Message)") }
    }
}
$remainingExecutableArtifacts = @(@($sourcePayloadPath, $droppedPayloadPath) |
    Where-Object { Test-Path -LiteralPath $_ })
$cleanupSucceeded = $remainingExecutableArtifacts.Count -eq 0 -and $cleanupErrors.Count -eq 0

if (-not $cleanupSucceeded) {
    $resultState = 'Inconclusive'
    $explanation = 'Generated executable cleanup is incomplete. Run -CleanupOnly before another test.'
}
elseif ($blockEvents.Count -gt 0 -and -not $payloadRan) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for the target rule and the marker-only payload did not run.'
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for the target rule. The endpoint observed but did not enforce this behavior.'
}
elseif ($targetAsrEvents.Count -eq 0 -and $payloadRan) {
    $resultState = 'Not triggered'
    $explanation = 'The Office-created marker-only executable ran, but no matching target-rule event was found.'
}
else {
    $resultState = 'Inconclusive'
    if ($otherAsrEvents.Count -gt 0) {
        $explanation = 'A different ASR rule fired before the target-rule result could be established. Review OtherAsrEvents.'
    }
    elseif ($antivirusEvents.Count -gt 0) {
        $explanation = 'Antivirus detected or remediated an artifact without a matching target-rule event.'
    }
    elseif ($operatorObservation -eq 'OfficePreempted') {
        $explanation = 'Office policy prevented the macro from reaching the executable-content behavior.'
    }
    elseif ($triggerError) {
        $explanation = "The test did not reach conclusive ASR evaluation: $triggerError"
    }
    elseif ($operatorObservation -eq 'BlockObserved') {
        $explanation = 'A block-like result was observed, but no matching target-rule Event 1121 was found.'
    }
    else {
        $explanation = 'The artifact and event evidence do not establish a clean block, audit, or non-trigger result.'
    }
}

$result = [pscustomobject]@{
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    RuleId = $RuleId
    RuleName = $RuleName
    ConfiguredAction = $ruleState.Action
    DefenderAntivirusEnabled = $defenderStatus.AntivirusEnabled
    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
    RpcServiceStatus = $rpcServiceStatus
    WordPath = $resolvedWordPath
    WordProcessId = $wordProcessId
    WordProcessStarted = $wordProcessStarted
    Trigger = $Trigger
    ArtifactVersion = 'locally-compiled-marker-only-dotnet-v1'
    MacroPath = $macroPath
    SourcePayloadSha256 = $sourcePayloadSha256
    DroppedPayloadCreatedBeforeCleanup = $droppedPayloadCreated
    DroppedPayloadSha256 = $droppedPayloadSha256
    PayloadMarkerPath = $markerPath
    PayloadRan = $payloadRan
    OperatorObservation = $operatorObservation
    TriggerError = $triggerError
    CleanupSucceeded = $cleanupSucceeded
    CleanupErrors = @($cleanupErrors)
    RemainingExecutableArtifacts = $remainingExecutableArtifacts
    Result = $resultState
    Explanation = $explanation
    AsrEvents = ConvertTo-EventSummary -Events $targetAsrEvents
    OtherAsrEvents = ConvertTo-EventSummary -Events $otherAsrEvents
    AntivirusEvents = ConvertTo-EventSummary -Events $antivirusEvents
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"

if (-not $cleanupSucceeded) {
    Write-Warning "Cleanup is incomplete. Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -CleanupOnly"
}
