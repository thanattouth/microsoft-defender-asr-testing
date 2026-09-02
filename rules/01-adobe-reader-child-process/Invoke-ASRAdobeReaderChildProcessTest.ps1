#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Notepad', 'Browser')]
    [string]$Trigger = 'Notepad',

    [string]$AdobePath,

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\01-adobe-reader-child-process'),

    [switch]$GenerateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
$RuleName = 'Block Adobe Reader from creating child processes'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'

function ConvertTo-PdfLiteral {
    param([Parameter(Mandatory)][string]$Value)

    return $Value.Replace('\', '\\').Replace('(', '\(').Replace(')', '\)')
}

function New-ASRTestPdf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Notepad', 'Browser')][string]$Mode
    )

    $content = @'
q
0.90 0.95 1.00 rg
72 520 468 90 re
f
Q
BT
/F1 18 Tf
72 720 Td
(Defender ASR Lab - Rule 01) Tj
0 -34 Td
/F1 12 Tf
(This PDF performs one harmless child-process test.) Tj
0 -22 Td
(Click the blue box, then approve Adobe's security prompt if shown.) Tj
0 -116 Td
/F1 16 Tf
(RUN HARMLESS ASR TEST) Tj
0 -28 Td
/F1 10 Tf
(Expected in Block mode: the target app does not open and Event 1121 is logged.) Tj
ET
'@

    if ($Mode -eq 'Notepad') {
        $notepadPath = ConvertTo-PdfLiteral (Join-Path $env:SystemRoot 'System32\notepad.exe')
        $action = "<< /S /Launch /Win << /F ($notepadPath) >> >>"
    }
    else {
        $action = '<< /S /URI /URI (https://example.com/) >>'
    }

    $contentLength = [Text.Encoding]::ASCII.GetByteCount($content)
    $objects = [ordered]@{
        1 = '<< /Type /Catalog /Pages 2 0 R >>'
        2 = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'
        3 = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R /Annots [6 0 R] >>'
        4 = "<< /Length $contentLength >>`nstream`n$content`nendstream"
        5 = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
        6 = "<< /Type /Annot /Subtype /Link /Rect [72 520 540 610] /Border [0 0 2] /C [0 0.35 0.85] /A $action >>"
    }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append("%PDF-1.4`n")
    $offsets = [Collections.Generic.List[int]]::new()

    foreach ($entry in $objects.GetEnumerator()) {
        $offsets.Add([Text.Encoding]::ASCII.GetByteCount($builder.ToString()))
        [void]$builder.Append("$($entry.Key) 0 obj`n$($entry.Value)`nendobj`n")
    }

    $xrefOffset = [Text.Encoding]::ASCII.GetByteCount($builder.ToString())
    [void]$builder.Append("xref`n0 $($objects.Count + 1)`n")
    [void]$builder.Append("0000000000 65535 f `n")
    foreach ($offset in $offsets) {
        [void]$builder.Append(('{0:D10} 00000 n ' -f $offset) + "`n")
    }
    [void]$builder.Append("trailer`n<< /Size $($objects.Count + 1) /Root 1 0 R >>`nstartxref`n$xrefOffset`n%%EOF`n")

    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}

function Resolve-AdobeExecutable {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (-not (Test-Path -LiteralPath $RequestedPath -PathType Leaf)) {
            throw "Adobe executable was not found at: $RequestedPath"
        }
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($name in @('Acrobat.exe', 'AcroRd32.exe')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            $candidates.Add($command.Source)
        }
    }

    foreach ($root in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        foreach ($relativePath in @(
            'Adobe\Acrobat DC\Acrobat\Acrobat.exe',
            'Adobe\Acrobat Reader DC\Reader\AcroRd32.exe',
            'Adobe\Reader 11.0\Reader\AcroRd32.exe'
        )) {
            $candidates.Add((Join-Path $root $relativePath))
        }
    }

    $resolved = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $resolved) {
        throw 'Adobe Acrobat or Acrobat Reader was not found. Install it or pass -AdobePath with the full executable path.'
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

function Get-ASRRuleState {
    param([Parameter(Mandatory)][string]$Id)

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw 'Get-MpPreference is unavailable. Run this test on a supported Windows device with Microsoft Defender Antivirus.'
    }

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
            $displayAction = if ($actionNames.ContainsKey($numericAction)) { $actionNames[$numericAction] } else { "Unknown ($numericAction)" }
            return [pscustomobject]@{ Id = $Id; Action = $displayAction; ActionValue = $numericAction }
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

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$pdfPath = Join-Path $OutputDirectory "ASR-Adobe-$Trigger.pdf"
New-ASRTestPdf -Path $pdfPath -Mode $Trigger

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Generated: $pdfPath"

if ($GenerateOnly) {
    Write-Host 'Generation-only mode selected; Adobe was not started.'
    return
}

$ruleState = Get-ASRRuleState -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$resolvedAdobePath = Resolve-AdobeExecutable -RequestedPath $AdobePath
$existingNotepadIds = @(Get-Process notepad -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$startedAt = Get-Date

Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "Adobe executable: $resolvedAdobePath"
Write-Host ''
if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}
Write-Host 'In Adobe, click RUN HARMLESS ASR TEST. If Adobe asks whether to open the external application, approve it for this lab file.'
if ($Trigger -eq 'Browser') {
    Write-Warning 'For the browser fallback, close browser windows first so Adobe must attempt a new process.'
}

Start-Process -FilePath $resolvedAdobePath -ArgumentList ('"{0}"' -f $pdfPath) | Out-Null
Read-Host 'After clicking the test box and waiting 10 seconds, press Enter to collect evidence'

$events = Get-MatchingASREvents -Since $startedAt -Id $RuleId
$newNotepad = @(Get-Process notepad -ErrorAction SilentlyContinue | Where-Object { $_.Id -notin $existingNotepadIds })
$blockEvents = @($events | Where-Object Id -eq 1121)
$auditEvents = @($events | Where-Object Id -eq 1122)

if ($blockEvents.Count -gt 0 -and $newNotepad.Count -eq 0) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for this rule and the benign Notepad target did not start.'
}
elseif ($auditEvents.Count -gt 0) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 for this rule. Audit mode observes but does not block.'
}
elseif ($Trigger -eq 'Notepad' -and $newNotepad.Count -gt 0) {
    $resultState = 'Not triggered'
    $explanation = 'Notepad started and no matching Defender ASR event was found.'
}
else {
    $resultState = 'Inconclusive'
    $explanation = 'No matching Defender event was found and no observable target process started. Adobe may have stopped the action before ASR evaluated it.'
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
    AdobePath = $resolvedAdobePath
    Trigger = $Trigger
    Result = $resultState
    Explanation = $explanation
    Events = $eventSummary
}

$resultPath = Join-Path $OutputDirectory "result-$Trigger.json"
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"
