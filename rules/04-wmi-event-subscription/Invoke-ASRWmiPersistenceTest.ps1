#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('PowerShellWmi', 'MofComp')]
    [string]$Trigger = 'PowerShellWmi',

    [string]$OutputDirectory = (Join-Path $env:TEMP 'DefenderASRLab\04-wmi-event-subscription'),

    [ValidateRange(1, 60)]
    [int]$WaitSeconds = 10,

    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleId = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
$RuleName = 'Block persistence through WMI event subscription'
$DefenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$WmiLog = 'Microsoft-Windows-WMI-Activity/Operational'
$SubscriptionNamespace = 'root\subscription'
$TestName = 'DefenderASRLab_Rule04'

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

function Get-WmiActivityEvents {
    param(
        [Parameter(Mandatory)][datetime]$Since,
        [Parameter(Mandatory)][string]$Name
    )

    $events = Get-WinEvent -FilterHashtable @{
        LogName = $WmiLog
        Id = 5857, 5858, 5859, 5860, 5861
        StartTime = $Since.AddSeconds(-2)
    } -ErrorAction SilentlyContinue

    return @($events | Where-Object { $_.Message -match [regex]::Escape($Name) })
}

function Get-TestSubscriptionObjects {
    param([Parameter(Mandatory)][string]$Name)

    $escapedName = $Name.Replace("'", "''")
    $namePattern = [regex]::Escape($Name)
    $filters = @(Get-WmiObject -Namespace $SubscriptionNamespace -Class __EventFilter -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue)
    $consumers = @(Get-WmiObject -Namespace $SubscriptionNamespace -Class CommandLineEventConsumer -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue)
    $bindings = @(Get-WmiObject -Namespace $SubscriptionNamespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { $_.Filter -match $namePattern -or $_.Consumer -match $namePattern })

    return [pscustomobject]@{
        Filters = $filters
        Consumers = $consumers
        Bindings = $bindings
        Total = $filters.Count + $consumers.Count + $bindings.Count
    }
}

function Remove-TestSubscriptionObjects {
    param([Parameter(Mandatory)][string]$Name)

    $errors = [Collections.Generic.List[string]]::new()
    $objects = Get-TestSubscriptionObjects -Name $Name

    foreach ($binding in @($objects.Bindings)) {
        try { $binding | Remove-WmiObject -ErrorAction Stop }
        catch { $errors.Add("Binding cleanup failed: $($_.Exception.Message)") }
    }
    foreach ($consumer in @($objects.Consumers)) {
        try { $consumer | Remove-WmiObject -ErrorAction Stop }
        catch { $errors.Add("Consumer cleanup failed: $($_.Exception.Message)") }
    }
    foreach ($filter in @($objects.Filters)) {
        try { $filter | Remove-WmiObject -ErrorAction Stop }
        catch { $errors.Add("Filter cleanup failed: $($_.Exception.Message)") }
    }

    return @($errors)
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
    'Get-CimInstance',
    'Get-WmiObject',
    'Set-WmiInstance',
    'Remove-WmiObject'
)) {
    if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
        throw "$requiredCommand is unavailable. Run this script with Windows PowerShell 5.1 on a supported Windows device."
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$markerPath = Join-Path $OutputDirectory 'unexpected-consumer-trigger.txt'
$resultPath = Join-Path $OutputDirectory "result-$Trigger.json"
$mofPath = Join-Path $OutputDirectory 'wmi-subscription-test.mof'
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($CleanupOnly) {
    if (-not $isAdministrator) {
        throw 'Cleanup requires an elevated Windows PowerShell session.'
    }

    $cleanupErrors = @(Remove-TestSubscriptionObjects -Name $TestName)
    $remaining = Get-TestSubscriptionObjects -Name $TestName
    if ($remaining.Total -gt 0 -or $cleanupErrors.Count -gt 0) {
        throw "Cleanup is incomplete. Remaining WMI objects: $($remaining.Total). Errors: $($cleanupErrors -join '; ')"
    }

    Write-Host "Cleanup complete. No WMI subscription objects named '$TestName' remain."
    return
}

if (Test-Path -LiteralPath $markerPath) {
    Remove-Item -LiteralPath $markerPath -Force
}

$preference = Get-MpPreference
$ruleState = Get-ASRRuleState -Preference $preference -Id $RuleId
$defenderStatus = Get-MpComputerStatus
$rpcService = Get-Service -Name RpcSs -ErrorAction SilentlyContinue
$wmiService = Get-Service -Name Winmgmt -ErrorAction SilentlyContinue
$rpcServiceStatus = if ($rpcService) { [string]$rpcService.Status } else { 'Unavailable' }
$wmiServiceStatus = if ($wmiService) { [string]$wmiService.Status } else { 'Unavailable' }
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$operatingSystem = if ($os) { [string]$os.Caption } else { $null }
$operatingSystemVersion = if ($os) { [string]$os.Version } else { $null }
$supportedOsBuild = if ($operatingSystemVersion) {
    [version]$operatingSystemVersion -ge [version]'10.0.18362.0'
}
else {
    $null
}
$startedAt = Get-Date
$triggerError = $null
$processExitCode = $null
$preCleanupErrors = @()
$cleanupErrors = @()
$asrEvents = @()
$wmiActivityEvents = @()
$objectSnapshot = $null
$remainingObjects = $null
$subscriptionCompleted = $false
$artifactVersion = if ($Trigger -eq 'PowerShellWmi') { 'inert-command-consumer-powershell-v1' } else { 'inert-command-consumer-mof-v1' }
$uniqueNeverProcess = "ASRRule04Never-$([Guid]::NewGuid().ToString('N')).exe"
$eventQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '$uniqueNeverProcess'"
$cmdPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
$consumerCommand = "`"$cmdPath`" /d /c echo defender-asr-rule-04-unexpected-trigger>`"$markerPath`""

Write-Host "Rule: $RuleName"
Write-Host "GUID: $RuleId"
Write-Host "Configured action: $($ruleState.Action)"
Write-Host "Administrator: $isAdministrator"
Write-Host "Defender AV enabled: $($defenderStatus.AntivirusEnabled)"
Write-Host "Real-time protection enabled: $($defenderStatus.RealTimeProtectionEnabled)"
Write-Host "Supported OS build: $supportedOsBuild"
Write-Host "RPC service: $rpcServiceStatus"
Write-Host "WMI service: $wmiServiceStatus"
Write-Host "Trigger: $Trigger"
Write-Host "Test object name: $TestName"

if ($ruleState.Action -ne 'Block') {
    Write-Warning "This endpoint reports '$($ruleState.Action)' rather than Block for the target rule."
}
if (-not $isAdministrator) {
    $triggerError = 'Administrator privileges are required to create and clean up a permanent WMI event subscription.'
    Write-Warning $triggerError
}
elseif (-not $defenderStatus.AntivirusEnabled -or -not $defenderStatus.RealTimeProtectionEnabled) {
    Write-Warning 'Microsoft Defender Antivirus or real-time protection is not active; the result may be inconclusive.'
}
if ($null -eq $rpcService -or $rpcService.Status -ne 'Running') {
    Write-Warning 'The RPC service is not running. Microsoft lists RPC as a dependency for this rule.'
}
if ($null -eq $wmiService -or $wmiService.Status -ne 'Running') {
    Write-Warning 'The Windows Management Instrumentation service is not running.'
}
if ($supportedOsBuild -eq $false) {
    Write-Warning 'This OS build predates the documented Windows 10 version 1903 baseline for this rule.'
}

try {
    if ($isAdministrator) {
        $preCleanupErrors = @(Remove-TestSubscriptionObjects -Name $TestName)
        $preExistingObjects = Get-TestSubscriptionObjects -Name $TestName
        if ($preExistingObjects.Total -gt 0 -or $preCleanupErrors.Count -gt 0) {
            throw "Existing test objects could not be removed. Remaining: $($preExistingObjects.Total). Errors: $($preCleanupErrors -join '; ')"
        }

        if ($Trigger -eq 'PowerShellWmi') {
            $filter = Set-WmiInstance -Namespace $SubscriptionNamespace -Class __EventFilter -Arguments @{
                Name = $TestName
                EventNamespace = 'root\cimv2'
                QueryLanguage = 'WQL'
                Query = $eventQuery
            }
            $consumer = Set-WmiInstance -Namespace $SubscriptionNamespace -Class CommandLineEventConsumer -Arguments @{
                Name = $TestName
                ExecutablePath = $cmdPath
                CommandLineTemplate = $consumerCommand
                RunInteractively = $false
            }
            [void](Set-WmiInstance -Namespace $SubscriptionNamespace -Class __FilterToConsumerBinding -Arguments @{
                Filter = $filter
                Consumer = $consumer
            })
        }
        else {
            $mofQuery = $eventQuery.Replace('\', '\\').Replace('"', '\"')
            $mofCmdPath = $cmdPath.Replace('\', '\\')
            $mofConsumerCommand = $consumerCommand.Replace('\', '\\').Replace('"', '\"')
            $mofContent = @"
#pragma namespace ("\\\\.\\root\\subscription")

instance of __EventFilter as `$FILTER
{
    Name = "$TestName";
    EventNamespace = "root\\cimv2";
    QueryLanguage = "WQL";
    Query = "$mofQuery";
};

instance of CommandLineEventConsumer as `$CONSUMER
{
    Name = "$TestName";
    ExecutablePath = "$mofCmdPath";
    CommandLineTemplate = "$mofConsumerCommand";
    RunInteractively = FALSE;
};

instance of __FilterToConsumerBinding
{
    Filter = `$FILTER;
    Consumer = `$CONSUMER;
};
"@
            [IO.File]::WriteAllText($mofPath, $mofContent, [Text.Encoding]::ASCII)
            $mofCompPath = Join-Path $env:SystemRoot 'System32\wbem\mofcomp.exe'
            if (-not (Test-Path -LiteralPath $mofCompPath -PathType Leaf)) {
                throw "mofcomp.exe was not found at: $mofCompPath"
            }

            $process = Start-Process -FilePath $mofCompPath -ArgumentList @('-N:root\subscription', "`"$mofPath`"") -Wait -PassThru
            $processExitCode = $process.ExitCode
            if ($processExitCode -ne 0) {
                throw "mofcomp.exe returned exit code $processExitCode."
            }
        }
    }
}
catch {
    $triggerError = $_.Exception.Message
    Write-Warning "Trigger returned an error: $triggerError"
}
finally {
    Start-Sleep -Seconds $WaitSeconds
    $objectSnapshot = Get-TestSubscriptionObjects -Name $TestName
    $subscriptionCompleted = $objectSnapshot.Bindings.Count -gt 0
    $asrEvents = @(Get-ASRRuleEvents -Since $startedAt -Id $RuleId)
    $wmiActivityEvents = @(Get-WmiActivityEvents -Since $startedAt -Name $TestName)
    if ($isAdministrator) {
        $cleanupErrors = @(Remove-TestSubscriptionObjects -Name $TestName)
    }
    $remainingObjects = Get-TestSubscriptionObjects -Name $TestName
}

$blockEvents = @($asrEvents | Where-Object Id -eq 1121)
$auditEvents = @($asrEvents | Where-Object Id -eq 1122)
$markerCreated = Test-Path -LiteralPath $markerPath
$cleanupSucceeded = $remainingObjects.Total -eq 0 -and $cleanupErrors.Count -eq 0

if ($blockEvents.Count -gt 0 -and -not $subscriptionCompleted -and -not $markerCreated -and $cleanupSucceeded) {
    $resultState = 'Blocked'
    $explanation = 'Defender logged Event 1121 for this rule, the complete subscription was not registered, and no test WMI objects remain.'
}
elseif ($auditEvents.Count -gt 0 -and $subscriptionCompleted -and -not $markerCreated -and $cleanupSucceeded) {
    $resultState = 'Audited'
    $explanation = 'Defender logged Event 1122 and allowed the inert subscription; the runner then removed every test WMI object.'
}
elseif ($asrEvents.Count -eq 0 -and $subscriptionCompleted -and -not $markerCreated -and $cleanupSucceeded) {
    $resultState = 'Not triggered'
    $explanation = 'The inert permanent subscription was registered without a matching ASR event; the runner then removed it.'
}
else {
    $resultState = 'Inconclusive'
    if (-not $cleanupSucceeded) {
        $explanation = 'Cleanup is incomplete. Run this script from elevated Windows PowerShell with -CleanupOnly before another test.'
    }
    elseif ($triggerError) {
        $explanation = "The subscription attempt did not produce conclusive target-rule evidence: $triggerError"
    }
    elseif ($markerCreated) {
        $explanation = 'The never-trigger marker exists unexpectedly. Preserve evidence and verify that no process matched the randomized filter name.'
    }
    elseif ($blockEvents.Count -gt 0 -and $subscriptionCompleted) {
        $explanation = 'Event 1121 was recorded, but the complete subscription existed before cleanup; enforcement behavior needs review.'
    }
    else {
        $explanation = 'The WMI objects and target-rule events do not establish a clean block, audit, or non-trigger result.'
    }
}

$result = [pscustomobject]@{
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    OperatingSystem = $operatingSystem
    OperatingSystemVersion = $operatingSystemVersion
    SupportedOsBuild = $supportedOsBuild
    RuleId = $RuleId
    RuleName = $RuleName
    ConfiguredAction = $ruleState.Action
    DefenderAntivirusEnabled = $defenderStatus.AntivirusEnabled
    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
    RpcServiceStatus = $rpcServiceStatus
    WmiServiceStatus = $wmiServiceStatus
    Administrator = $isAdministrator
    Trigger = $Trigger
    ArtifactVersion = $artifactVersion
    TestObjectName = $TestName
    NeverTriggerProcessName = $uniqueNeverProcess
    EventQuery = $eventQuery
    ConsumerCommand = $consumerCommand
    TriggerError = $triggerError
    ProcessExitCode = $processExitCode
    SubscriptionCompletedBeforeCleanup = $subscriptionCompleted
    FiltersBeforeCleanup = $objectSnapshot.Filters.Count
    ConsumersBeforeCleanup = $objectSnapshot.Consumers.Count
    BindingsBeforeCleanup = $objectSnapshot.Bindings.Count
    MarkerPath = $markerPath
    MarkerCreated = $markerCreated
    CleanupSucceeded = $cleanupSucceeded
    CleanupErrors = $cleanupErrors
    RemainingArtifactsAfterCleanup = $remainingObjects.Total
    Result = $resultState
    Explanation = $explanation
    AsrEvents = ConvertTo-EventSummary -Events $asrEvents
    WmiActivityEvents = ConvertTo-EventSummary -Events $wmiActivityEvents
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | Format-List
Write-Host "Evidence saved to: $resultPath"

if (-not $cleanupSucceeded) {
    Write-Warning "Cleanup is incomplete. Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -CleanupOnly"
}
