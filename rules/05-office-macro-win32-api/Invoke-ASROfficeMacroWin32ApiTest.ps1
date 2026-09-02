#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$MicrosoftSamplePath,

    [switch]$AllowOfficialDownload,

    [switch]$AllowUnblockSample,

    [string]$WordPath,

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\05-office-macro-win32-api'),

    [ValidateRange(1, 60)]
    [int]$WaitSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
$RuleName = 'Block Win32 API calls from Office macros'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$OfficialSampleUrl = 'https://demo.wd.microsoft.com/Content/Block_Win32_imports_from_Macro_code_in_Office_92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b.docm'
$OfficialSampleSha256 = 'f0a906263537453e7860bb5fc0663eadd7e1f83f51b1290c473b069dc198d42c'

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

function Get-ASRRuleEvents {
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

function Get-AntivirusEvents {
    param([Parameter(Mandatory)][datetime]$Since)

    return @(Get-WinEvent -FilterHashtable @{
        LogName = $DefenderLog
        Id = 1116, 1117
        StartTime = $Since.AddSeconds(-2)
    } -ErrorAction SilentlyContinue)
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
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
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }

    return $null
}

function Test-MarkOfTheWeb {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $stream = Get-Item -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        return $null -ne $stream
    }
    catch {
        return $false
    }
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

foreach ($requiredCommand in @(
    'Get-MpPreference',
    'Get-MpComputerStatus',
    'Get-WinEvent',
    'Get-FileHash',
    'Invoke-WebRequest'
)) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this test with Windows PowerShell 5.1 on a supported Windows client."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resultPath = Join-Path $OutputDirectory 'result-MicrosoftSample.json'
$artifactPath = $null
$downloadedByRunner = $false
$actualSampleSha256 = $null
$markOfTheWebBefore = $null
$markOfTheWebAfter = $null
$sampleUnblockedByRunner = $false
$triggerError = $null
$wordProcessId = $null
$wordProcessStarted = $false
$operatorObservation = 'Unknown'
$startedAt = Get-Date

$preference = Get-MpPreference
$ruleState = Get-ASRRuleState -Preference $preference -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$disableScriptScanning = Get-OptionalPropertyValue -InputObject $preference -Name 'DisableScriptScanning'
$amsiPath = Join-Path $env:SystemRoot 'System32\amsi.dll'
$amsiPresent = Test-Path -LiteralPath $amsiPath -PathType Leaf
$resolvedWordPath = Get-WordExecutablePath -OverridePath $WordPath
$existingWordIds = @(Get-Process WINWORD -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "Script scanning disabled: $disableScriptScanning"
Write-Host "AMSI present: $amsiPresent"
Write-Host "Word path: $resolvedWordPath"
Write-Host 'User notification expected: No (verify Event 1121 and portal telemetry)'

if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}
if ($disableScriptScanning -eq $true) {
    Write-Warning 'Defender script scanning is disabled; the Office macro might not reach AMSI evaluation.'
}
if (-not $amsiPresent) {
    Write-Warning 'amsi.dll was not found in System32; the target rule dependency is unavailable.'
}

try {
    if ($existingWordIds.Count -gt 0) {
        throw 'Close every Microsoft Word window before this test, then rerun so the runner can identify the test process cleanly.'
    }
    if (-not $resolvedWordPath) {
        throw 'Microsoft Word was not found. Install desktop Word or provide its full WINWORD.EXE path with -WordPath.'
    }

    if ($MicrosoftSamplePath) {
        if (-not (Test-Path -LiteralPath $MicrosoftSamplePath -PathType Leaf)) {
            throw "Microsoft sample was not found at: $MicrosoftSamplePath"
        }
        $artifactPath = (Resolve-Path -LiteralPath $MicrosoftSamplePath).Path
    }
    else {
        if (-not $AllowOfficialDownload) {
            throw 'Specify -AllowOfficialDownload or provide -MicrosoftSamplePath. No download was performed.'
        }
        $artifactPath = Join-Path $OutputDirectory 'Microsoft-official-office-win32-api.docm'
        Invoke-WebRequest -UseBasicParsing -Uri $OfficialSampleUrl -OutFile $artifactPath
        $downloadedByRunner = $true
    }

    $actualSampleSha256 = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSampleSha256 -ne $OfficialSampleSha256) {
        throw "Official sample SHA-256 mismatch. Expected $OfficialSampleSha256 but received $actualSampleSha256. The file was not opened."
    }

    $markOfTheWebBefore = Test-MarkOfTheWeb -Path $artifactPath
    if ($AllowUnblockSample -and $markOfTheWebBefore) {
        if (-not (Get-Command Unblock-File -ErrorAction SilentlyContinue)) {
            throw 'Unblock-File is unavailable, so the Mark of the Web was not removed.'
        }
        Unblock-File -LiteralPath $artifactPath
        $sampleUnblockedByRunner = $true
    }
    $markOfTheWebAfter = Test-MarkOfTheWeb -Path $artifactPath

    $process = Start-Process -FilePath $resolvedWordPath -ArgumentList @('/n', "`"$artifactPath`"") -PassThru
    $wordProcessId = $process.Id
    Start-Sleep -Seconds 2
    $wordProcessStarted = $null -ne (Get-Process -Id $wordProcessId -ErrorAction SilentlyContinue)
    if (-not $wordProcessStarted) {
        throw 'Microsoft Word exited before the operator could run the sample.'
    }

    Write-Host ''
    Write-Host 'In Word, select Enable Editing if shown, then enable the document macro/content.' -ForegroundColor Cyan
    Write-Host 'Do not change Trust Center settings. Observe Word or Windows Security, then close the sample without saving.' -ForegroundColor Cyan
    Write-Host 'Enter one result after closing the sample:' -ForegroundColor Cyan
    Write-Host '  B = a block/error appeared while the macro attempted the API call'
    Write-Host '  R = the macro/API demonstration completed without an ASR block'
    Write-Host '  O = Office, Protected View, or macro policy prevented the macro from starting'
    Write-Host '  U = unsure'
    $operatorInputRaw = Read-Host 'Result [B/R/O/U]'
    $operatorInput = if ($operatorInputRaw) { $operatorInputRaw.Trim().ToUpperInvariant() } else { 'U' }
    $operatorObservation = switch ($operatorInput) {
        'B' { 'BlockObserved' }
        'R' { 'MacroRan' }
        'O' { 'OfficePreempted' }
        default { 'Unknown' }
    }
}
catch {
    $triggerError = $_.Exception.Message
    Write-Warning "Trigger returned an error: $triggerError"
}

Start-Sleep -Seconds $WaitSeconds
$asrEvents = @(Get-ASRRuleEvents -Since $startedAt -Id $RuleId)
$antivirusEvents = @(Get-AntivirusEvents -Since $startedAt)
$blockEvents = @($asrEvents | Where-Object Id -eq 1121)
$auditEvents = @($asrEvents | Where-Object Id -eq 1122)
$artifactPresentAfterRun = if ($artifactPath) { Test-Path -LiteralPath $artifactPath } else { $null }

if ($blockEvents.Count -gt 0) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for the Office macro Win32 API rule. A Windows notification is not required for this rule.'
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for the Office macro Win32 API rule.'
}
elseif ($asrEvents.Count -eq 0 -and $operatorObservation -eq 'MacroRan') {
    $resultState = 'Not triggered'
    $explanation = 'The operator confirmed that the macro/API demonstration ran, but no matching ASR event was found.'
}
else {
    $resultState = 'Inconclusive'
    if ($antivirusEvents.Count -gt 0) {
        $explanation = 'Antivirus detection events occurred without a matching target-rule event; Antivirus might have preempted the Office macro test.'
    }
    elseif ($operatorObservation -eq 'OfficePreempted') {
        $explanation = 'Office, Protected View, Mark of the Web, or macro policy prevented the macro from reaching the protected API call.'
    }
    elseif ($triggerError) {
        $explanation = "The sample did not reach conclusive ASR evaluation: $triggerError"
    }
    elseif ($operatorObservation -eq 'BlockObserved') {
        $explanation = 'A block-like error was observed, but no matching target-rule event was found. Do not credit this run to ASR.'
    }
    else {
        $explanation = 'No matching target-rule event confirms whether the Office macro reached the protected Win32 API call.'
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
    ScriptScanningDisabled = $disableScriptScanning
    AmsiPresent = $amsiPresent
    WordPath = $resolvedWordPath
    WordProcessId = $wordProcessId
    WordProcessStarted = $wordProcessStarted
    ArtifactVersion = 'microsoft-official-docm-sha256-pinned'
    OfficialSampleUrl = $OfficialSampleUrl
    ExpectedSampleSha256 = $OfficialSampleSha256
    ActualSampleSha256 = $actualSampleSha256
    ArtifactPath = $artifactPath
    DownloadedByRunner = $downloadedByRunner
    ArtifactPresentAfterRun = $artifactPresentAfterRun
    MarkOfTheWebBefore = $markOfTheWebBefore
    MarkOfTheWebAfter = $markOfTheWebAfter
    SampleUnblockedByRunner = $sampleUnblockedByRunner
    OperatorObservation = $operatorObservation
    TriggerError = $triggerError
    Result = $resultState
    Explanation = $explanation
    AsrEvents = ConvertTo-EventSummary -Events $asrEvents
    AntivirusEvents = ConvertTo-EventSummary -Events $antivirusEvents
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"
