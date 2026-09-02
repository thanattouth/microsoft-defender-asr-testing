#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('MicrosoftSample', 'JScript', 'PowerShell')]
    [string]$Trigger = 'MicrosoftSample',

    [string]$MicrosoftSamplePath,

    [switch]$AllowOfficialDownload,

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\03-obfuscated-scripts'),

    [ValidateRange(1, 60)]
    [int]$WaitSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
$RuleName = 'Block execution of potentially obfuscated scripts'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$OfficialSampleUrl = 'https://demo.wd.microsoft.com/Content/TestFile_ScriptObfuscatedContent_5BEB7EFE-FD9A-4556-801D-275E5FFC04CC.js'
$OfficialSampleSha256 = 'cea7dbe4e275f248573c72ba75fff24362eb60143108dd909fb082f0464c70cb'

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

function ConvertTo-XorHexAscii {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][byte]$Key
    )

    return -join ([Text.Encoding]::ASCII.GetBytes($Value) | ForEach-Object { '{0:X2}' -f ($_ -bxor $Key) })
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

foreach ($requiredCommand in @('Get-MpPreference', 'Get-MpComputerStatus', 'Get-WinEvent')) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this test on a supported Windows device with Microsoft Defender Antivirus."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$markerPath = Join-Path $OutputDirectory "marker-$Trigger.txt"
$resultPath = Join-Path $OutputDirectory "result-$Trigger.json"
$artifactPath = $null

if (Test-Path -LiteralPath $markerPath) {
    Remove-Item -LiteralPath $markerPath -Force
}

$preference = Get-MpPreference
$ruleState = Get-ASRRuleState -Preference $preference -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$mapsReporting = Get-OptionalPropertyValue -InputObject $preference -Name 'MAPSReporting'
$disableScriptScanning = Get-OptionalPropertyValue -InputObject $preference -Name 'DisableScriptScanning'
$cloudProtectionEnabled = if ($null -eq $mapsReporting) { $null } else { [int]$mapsReporting -ne 0 }
$amsiPath = Join-Path $env:SystemRoot 'System32\amsi.dll'
$amsiPresent = Test-Path -LiteralPath $amsiPath -PathType Leaf
$startedAt = Get-Date
$triggerError = $null
$processExitCode = $null
$triggerDetail = $null
$artifactVersion = $null
$actualSampleSha256 = $null
$existingNotepadIds = @(Get-Process notepad -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "Cloud protection enabled: $cloudProtectionEnabled"
Write-Host "Script scanning disabled: $disableScriptScanning"
Write-Host "AMSI present: $amsiPresent"
Write-Host "Trigger: $Trigger"
Write-Host "Marker path: $markerPath"

if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}
if ($cloudProtectionEnabled -eq $false) {
    Write-Warning 'Cloud-delivered protection is disabled. Microsoft lists it as a dependency for this rule.'
}
if ($disableScriptScanning -eq $true) {
    Write-Warning 'Defender script scanning is disabled; the trigger might not reach AMSI evaluation.'
}
if (-not $amsiPresent) {
    Write-Warning 'amsi.dll was not found in System32; the target rule dependency is unavailable.'
}

try {
    if ($Trigger -eq 'MicrosoftSample') {
        if ($existingNotepadIds.Count -gt 0) {
            throw 'Close all Notepad windows before using MicrosoftSample so the runner can measure whether the sample starts Notepad.'
        }

        if ($MicrosoftSamplePath) {
            if (-not (Test-Path -LiteralPath $MicrosoftSamplePath -PathType Leaf)) {
                throw "Microsoft sample was not found at: $MicrosoftSamplePath"
            }
            $artifactPath = (Resolve-Path -LiteralPath $MicrosoftSamplePath).Path
        }
        else {
            if (-not $AllowOfficialDownload) {
                throw 'MicrosoftSample requires -AllowOfficialDownload or -MicrosoftSamplePath. No download was performed.'
            }
            $artifactPath = Join-Path $OutputDirectory 'Microsoft-official-obfuscated-script.js'
            Invoke-WebRequest -UseBasicParsing -Uri $OfficialSampleUrl -OutFile $artifactPath
        }

        $actualSampleSha256 = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSampleSha256 -ne $OfficialSampleSha256) {
            throw "Official sample SHA-256 mismatch. Expected $OfficialSampleSha256 but received $actualSampleSha256. The file was not executed."
        }

        $cscriptPath = Join-Path $env:SystemRoot 'System32\cscript.exe'
        if (-not (Test-Path -LiteralPath $cscriptPath -PathType Leaf)) {
            throw "Windows Script Host was not found at: $cscriptPath"
        }

        $artifactVersion = 'microsoft-official-sample-sha256-pinned'
        $triggerDetail = 'Microsoft Defender official obfuscated JScript sample; verified SHA-256; expected benign action is notepad.exe'
        $arguments = '//nologo "{0}"' -f $artifactPath
        $process = Start-Process -FilePath $cscriptPath -ArgumentList $arguments -Wait -PassThru
        $processExitCode = $process.ExitCode
    }
    elseif ($Trigger -eq 'JScript') {
        $padding = [Text.StringBuilder]::new()
        for ($index = 0; $index -lt 512; $index++) {
            [void]$padding.AppendLine(('var benignNoop{0:D4} = {0};' -f $index))
        }
        $clearJScript = $padding.ToString() + @'
var marker = WScript.Arguments.Item(0);
var shell = new ActiveXObject("WScript.Shell");
var command = '"' + shell.ExpandEnvironmentStrings("%ComSpec%") + '" /d /c echo defender-asr-rule-03> "' + marker + '"';
shell.Run(command, 0, true);
'@
        $xorKey = [byte]0x5A
        $encodedJScript = ConvertTo-XorHexAscii -Value $clearJScript -Key $xorKey
        $obfuscatedJScript = @"
var encodedPayload = "$encodedJScript";
var decodedPayload = "";
for (var offset = 0; offset < encodedPayload.length; offset += 2) {
    decodedPayload += String.fromCharCode(parseInt(encodedPayload.substr(offset, 2), 16) ^ 0x5A);
}
eval(decodedPayload);
"@
        $artifactPath = Join-Path $OutputDirectory 'obfuscated-marker-test.js'
        [IO.File]::WriteAllText($artifactPath, $obfuscatedJScript, [Text.Encoding]::ASCII)

        $cscriptPath = Join-Path $env:SystemRoot 'System32\cscript.exe'
        if (-not (Test-Path -LiteralPath $cscriptPath -PathType Leaf)) {
            throw "Windows Script Host was not found at: $cscriptPath"
        }

        $artifactVersion = 'xor-hex-child-process-v2'
        $triggerDetail = 'Large XOR-hex JScript blob decoded through eval() to launch a marker-only cmd.exe child'
        $arguments = '//nologo "{0}" "{1}"' -f $artifactPath, $markerPath
        $process = Start-Process -FilePath $cscriptPath -ArgumentList $arguments -Wait -PassThru
        $processExitCode = $process.ExitCode
    }
    else {
        $escapedMarkerPath = $markerPath.Replace("'", "''")
        $markerCommand = "Set-Content -LiteralPath '$escapedMarkerPath' -Value 'defender-asr-rule-03'"
        $innerBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($markerCommand))
        $decodedCommand = "`$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$innerBase64')); Invoke-Expression `$decoded"
        $outerBase64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decodedCommand))
        $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

        $artifactVersion = 'nested-base64-powershell-v1'
        $triggerDetail = 'PowerShell EncodedCommand containing a second Base64 layer and marker-only Set-Content'
        $process = Start-Process -FilePath $powerShellPath -ArgumentList @(
            '-NoProfile',
            '-NonInteractive',
            '-EncodedCommand',
            $outerBase64
        ) -Wait -PassThru
        $processExitCode = $process.ExitCode
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
$markerCreated = Test-Path -LiteralPath $markerPath
$artifactPresentAfterRun = if ($artifactPath) { Test-Path -LiteralPath $artifactPath } else { $null }
$newNotepadProcesses = @(Get-Process notepad -ErrorAction SilentlyContinue | Where-Object { $_.Id -notin $existingNotepadIds })
$notepadStarted = $newNotepadProcesses.Count -gt 0
$protectedEffectAbsent = if ($Trigger -eq 'MicrosoftSample') { -not $notepadStarted } else { -not $markerCreated }

if ($blockEvents.Count -gt 0 -and $protectedEffectAbsent) {
    $resultState = 'Blocked'
    $explanation = if ($Trigger -eq 'MicrosoftSample') {
        'Defender logged Event 1121 for this rule and the official sample did not start Notepad.'
    }
    else {
        'Defender logged Event 1121 for this rule and the decoded script did not create the benign marker.'
    }
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for this rule. Audit mode observes but does not block.'
}
elseif ($Trigger -eq 'MicrosoftSample' -and $notepadStarted -and $asrEvents.Count -eq 0) {
    $resultState = 'Not triggered'
    $explanation = 'The verified Microsoft sample started Notepad and no matching ASR event was found.'
}
elseif ($markerCreated -and $asrEvents.Count -eq 0) {
    $resultState = 'Not triggered'
    $explanation = 'The decoded script created the marker and no matching ASR event was found.'
}
    else {
        $resultState = 'Inconclusive'
        $explanation = if ($antivirusEvents.Count -gt 0) {
            'Antivirus detection events occurred without a matching target-rule event; Antivirus might have preempted ASR evaluation.'
        }
        elseif ($triggerError) {
            "The trigger did not complete: $triggerError"
        }
        else {
            'The protected action and ASR event evidence do not establish a clean block, audit, or non-trigger result. Review the trigger and dependency data.'
        }
    }

$asrEventSummary = @($asrEvents | ForEach-Object {
    [pscustomobject]@{
        EventId = $_.Id
        RecordId = $_.RecordId
        TimeCreated = $_.TimeCreated
        Message = $_.Message
    }
})
$antivirusEventSummary = @($antivirusEvents | ForEach-Object {
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
    CloudProtectionEnabled = $cloudProtectionEnabled
    MapsReporting = $mapsReporting
    ScriptScanningDisabled = $disableScriptScanning
    AmsiPresent = $amsiPresent
    Trigger = $Trigger
    ArtifactVersion = $artifactVersion
    TriggerDetail = $triggerDetail
    TriggerError = $triggerError
    ProcessExitCode = $processExitCode
    OfficialSampleUrl = if ($Trigger -eq 'MicrosoftSample') { $OfficialSampleUrl } else { $null }
    ExpectedSampleSha256 = if ($Trigger -eq 'MicrosoftSample') { $OfficialSampleSha256 } else { $null }
    ActualSampleSha256 = $actualSampleSha256
    ArtifactPath = $artifactPath
    ArtifactPresentAfterRun = $artifactPresentAfterRun
    MarkerPath = $markerPath
    MarkerCreated = $markerCreated
    NotepadStarted = $notepadStarted
    Result = $resultState
    Explanation = $explanation
    AsrEvents = $asrEventSummary
    AntivirusEvents = $antivirusEventSummary
}

$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"
