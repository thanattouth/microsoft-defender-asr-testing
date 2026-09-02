#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$MicrosoftSamplePath,

    [switch]$AllowOfficialDownload,

    [switch]$AllowUnblockSample,

    [switch]$AcknowledgeOfficialSampleRisk,

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
$OfficialSampleUrl = 'https://demo.wd.microsoft.com/Content/TestFile_Block_Office_applications_from_creating_executable_content_3b576869-a4ec-4529-8536-b80a7769e899.docm'
$OfficialSampleSha256 = '785b85b4206a1bff7555df66850309e366d76951e037fe1a8d4f50caa5c424a0'
$DownloadedSamplePath = Join-Path $OutputDirectory 'Microsoft-official-rule06.docm'
$KnownPayloadPath = Join-Path $env:TEMP 'lockysample.exe'
$CleanupManifestPath = Join-Path $OutputDirectory 'cleanup-manifest.json'
$ResultPath = Join-Path $OutputDirectory 'result-MicrosoftSample.json'

function Get-ASRRuleState {
    param(
        [Parameter(Mandatory)]$Preference,
        [Parameter(Mandatory)][string]$Id
    )

    $ids = @($Preference.AttackSurfaceReductionRules_Ids)
    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
    $actionNames = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Not configured'; 6 = 'Warn' }

    for ($index = 0; $index -lt [Math]::Min($ids.Count, $actions.Count); $index++) {
        if ([string]$ids[$index] -eq $Id) {
            $numericAction = [int]$actions[$index]
            $displayAction = if ($actionNames.ContainsKey($numericAction)) {
                $actionNames[$numericAction]
            }
            else {
                "Unknown ($numericAction)"
            }

            return [pscustomobject]@{ Id = $Id; Action = $displayAction; ActionValue = $numericAction }
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

if ($CleanupOnly) {
    $cleanupOnlyErrors = [Collections.Generic.List[string]]::new()
    $cleanupOnlyTargets = @($DownloadedSamplePath)

    if (Test-Path -LiteralPath $CleanupManifestPath -PathType Leaf) {
        try {
            $cleanupManifest = Get-Content -LiteralPath $CleanupManifestPath -Raw | ConvertFrom-Json
            if (-not [bool]$cleanupManifest.KnownPayloadExistedBefore -and $cleanupManifest.KnownPayloadPath) {
                $cleanupOnlyTargets += [string]$cleanupManifest.KnownPayloadPath
            }
        }
        catch {
            $cleanupOnlyErrors.Add("Cleanup manifest could not be read: $($_.Exception.Message)")
        }
    }

    foreach ($path in @($cleanupOnlyTargets | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path) {
            try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
            catch { $cleanupOnlyErrors.Add("$path cleanup failed: $($_.Exception.Message)") }
        }
    }

    if ($cleanupOnlyErrors.Count -eq 0 -and (Test-Path -LiteralPath $CleanupManifestPath)) {
        Remove-Item -LiteralPath $CleanupManifestPath -Force
    }

    if ($cleanupOnlyErrors.Count -gt 0) {
        $cleanupOnlyErrors | ForEach-Object { Write-Warning $_ }
        throw 'Cleanup is incomplete. Close Word and retry -CleanupOnly.'
    }

    Write-Host 'Cleanup complete. Runner-downloaded sample and tracked payload are absent.'
    return
}

foreach ($requiredCommand in @(
    'Get-MpPreference',
    'Get-MpComputerStatus',
    'Get-WinEvent',
    'Get-FileHash',
    'Invoke-WebRequest'
)) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this test with Windows PowerShell 5.1 on a supported Windows device."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

if (Test-Path -LiteralPath $CleanupManifestPath -PathType Leaf) {
    throw "A prior cleanup manifest exists at $CleanupManifestPath. Close Word and run this script with -CleanupOnly before starting another test."
}

$preference = Get-MpPreference
$ruleState = Get-ASRRuleState -Preference $preference -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$rpcService = Get-Service -Name RpcSs -ErrorAction SilentlyContinue
$rpcServiceStatus = if ($rpcService) { [string]$rpcService.Status } else { 'Unavailable' }
$resolvedWordPath = Get-WordExecutablePath -OverridePath $WordPath
$existingWordIds = @(Get-Process WINWORD -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$knownPayloadExistedBefore = Test-Path -LiteralPath $KnownPayloadPath
$startedAt = Get-Date
$artifactPath = $null
$downloadedByRunner = $false
$actualSampleSha256 = $null
$markOfTheWebBefore = $null
$markOfTheWebAfter = $null
$sampleUnblockedByRunner = $false
$wordProcessId = $null
$wordProcessStarted = $false
$operatorObservation = 'Unknown'
$triggerError = $null
$knownPayloadCreated = $false
$knownPayloadSha256 = $null
$artifactPresentBeforeCleanup = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "RPC service: $rpcServiceStatus"
Write-Host "Word path: $resolvedWordPath"
Write-Host "Official sample SHA-256: $OfficialSampleSha256"

try {
    if (-not $AcknowledgeOfficialSampleRisk) {
        throw 'The official document can download and attempt to run lockysample.exe. Rerun with -AcknowledgeOfficialSampleRisk only on the disposable test endpoint.'
    }
    if ($ruleState.Action -ne 'Block') {
        throw "Safety stop: this endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
    }
    if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
        throw 'Safety stop: Microsoft Defender Antivirus and real-time protection must both be active.'
    }
    if ($null -eq $rpcService -or $rpcService.Status -ne 'Running') {
        throw 'Safety stop: RPC must be running because Microsoft lists it as a dependency for this rule.'
    }
    if ($knownPayloadExistedBefore) {
        throw "Safety stop: $KnownPayloadPath existed before this run. The runner will not overwrite or delete a pre-existing file."
    }
    if ($existingWordIds.Count -gt 0) {
        throw 'Close every Microsoft Word window before running this test.'
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
        $artifactPath = $DownloadedSamplePath
        if (Test-Path -LiteralPath $artifactPath) {
            Remove-Item -LiteralPath $artifactPath -Force
        }
        $downloadedByRunner = $true
    }

    $cleanupManifest = [pscustomobject]@{
        CreatedAt = Get-Date
        DownloadedSamplePath = $DownloadedSamplePath
        DownloadedByRunner = $downloadedByRunner
        KnownPayloadPath = $KnownPayloadPath
        KnownPayloadExistedBefore = $knownPayloadExistedBefore
    }
    $cleanupManifest | ConvertTo-Json | Set-Content -LiteralPath $CleanupManifestPath -Encoding utf8

    if ($downloadedByRunner) {
        Invoke-WebRequest -UseBasicParsing -Uri $OfficialSampleUrl -OutFile $artifactPath
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

    $wordProcess = Start-Process -FilePath $resolvedWordPath -ArgumentList @('/n', "`"$artifactPath`"") -PassThru
    $wordProcessId = $wordProcess.Id
    Start-Sleep -Seconds 2
    $wordProcessStarted = $null -ne (Get-Process -Id $wordProcessId -ErrorAction SilentlyContinue)
    if (-not $wordProcessStarted) {
        throw 'Microsoft Word exited before the operator could run the sample.'
    }

    Write-Host ''
    Write-Warning 'This official Microsoft sample can download and attempt to run lockysample.exe if ASR does not block it.'
    Write-Host 'In Word, enable editing/content only for this verified document. Do not select a real data folder if prompted.' -ForegroundColor Cyan
    Write-Host 'Observe the result, close Word without saving, then return here immediately.' -ForegroundColor Cyan
    Write-Host '  B = an Action blocked notification or block/error appeared'
    Write-Host '  R = lockysample.exe started or the demonstration continued without an ASR block'
    Write-Host '  O = Protected View or Office macro policy prevented the macro from starting'
    Write-Host '  U = unsure'
    $operatorInputRaw = Read-Host 'Result [B/R/O/U]'
    $operatorInput = if ($operatorInputRaw) { $operatorInputRaw.Trim().ToUpperInvariant() } else { 'U' }
    $operatorObservation = switch ($operatorInput) {
        'B' { 'BlockObserved' }
        'R' { 'MacroOrPayloadRan' }
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
$artifactPresentBeforeCleanup = if ($artifactPath) { Test-Path -LiteralPath $artifactPath } else { $false }
$knownPayloadCreated = -not $knownPayloadExistedBefore -and (Test-Path -LiteralPath $KnownPayloadPath)

if ($knownPayloadCreated) {
    try {
        $knownPayloadSha256 = (Get-FileHash -LiteralPath $KnownPayloadPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    catch {
        $triggerError = "The tracked payload disappeared before hashing: $($_.Exception.Message)"
        $knownPayloadCreated = Test-Path -LiteralPath $KnownPayloadPath
    }
}

$cleanupTargets = @()
if ($downloadedByRunner) { $cleanupTargets += $DownloadedSamplePath }
if (-not $knownPayloadExistedBefore) { $cleanupTargets += $KnownPayloadPath }

foreach ($path in @($cleanupTargets | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $path) {
        try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add("$path cleanup failed: $($_.Exception.Message)") }
    }
}

$remainingTrackedArtifacts = @($cleanupTargets | Select-Object -Unique | Where-Object {
    Test-Path -LiteralPath $_
})
$cleanupSucceeded = $remainingTrackedArtifacts.Count -eq 0 -and $cleanupErrors.Count -eq 0

if ($cleanupSucceeded -and (Test-Path -LiteralPath $CleanupManifestPath)) {
    Remove-Item -LiteralPath $CleanupManifestPath -Force
}

if (-not $cleanupSucceeded) {
    $resultState = 'Inconclusive'
    $explanation = 'Tracked official-sample artifacts remain. Close Word and run -CleanupOnly immediately.'
}
elseif ($blockEvents.Count -gt 0) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for the target Office executable-content rule.'
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for the target Office executable-content rule.'
}
elseif ($targetAsrEvents.Count -eq 0 -and $operatorObservation -eq 'MacroOrPayloadRan') {
    $resultState = 'Not triggered'
    $explanation = 'The official demonstration continued or its payload started, but no matching target-rule event was found.'
}
else {
    $resultState = 'Inconclusive'
    if ($otherAsrEvents.Count -gt 0) {
        $explanation = 'A different ASR rule fired before the target-rule result could be established. Review OtherAsrEvents.'
    }
    elseif ($antivirusEvents.Count -gt 0) {
        $explanation = 'Antivirus detected or remediated the sample without a matching target-rule event.'
    }
    elseif ($operatorObservation -eq 'OfficePreempted') {
        $explanation = 'Protected View or Office macro policy prevented the macro from reaching the protected behavior.'
    }
    elseif ($triggerError) {
        $explanation = "The official sample did not reach conclusive ASR evaluation: $triggerError"
    }
    elseif ($operatorObservation -eq 'BlockObserved') {
        $explanation = 'A block-like result was observed, but no matching target-rule Event 1121 was found.'
    }
    else {
        $explanation = 'The event and operator evidence do not establish a clean block, audit, or non-trigger result.'
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
    ArtifactVersion = 'microsoft-official-docm-sha256-pinned'
    OfficialSampleUrl = $OfficialSampleUrl
    ExpectedSampleSha256 = $OfficialSampleSha256
    ActualSampleSha256 = $actualSampleSha256
    ArtifactPath = $artifactPath
    DownloadedByRunner = $downloadedByRunner
    ArtifactPresentBeforeCleanup = $artifactPresentBeforeCleanup
    MarkOfTheWebBefore = $markOfTheWebBefore
    MarkOfTheWebAfter = $markOfTheWebAfter
    SampleUnblockedByRunner = $sampleUnblockedByRunner
    KnownPayloadPath = $KnownPayloadPath
    KnownPayloadExistedBefore = $knownPayloadExistedBefore
    KnownPayloadCreated = $knownPayloadCreated
    KnownPayloadSha256 = $knownPayloadSha256
    OperatorObservation = $operatorObservation
    TriggerError = $triggerError
    CleanupSucceeded = $cleanupSucceeded
    CleanupErrors = @($cleanupErrors)
    RemainingTrackedArtifacts = $remainingTrackedArtifacts
    Result = $resultState
    Explanation = $explanation
    AsrEvents = ConvertTo-EventSummary -Events $targetAsrEvents
    OtherAsrEvents = ConvertTo-EventSummary -Events $otherAsrEvents
    AntivirusEvents = ConvertTo-EventSummary -Events $antivirusEvents
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $ResultPath"

if (-not $cleanupSucceeded) {
    Write-Warning "Cleanup is incomplete. Close Word, then run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -CleanupOnly"
}
