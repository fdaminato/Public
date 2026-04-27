# ============================================================
# Intune Feature Update 25H2 - One CSV + HTML Dashboard
#
# Matches:
#   FeatureUpdate-Windows11-25H2-Enterprise-*
#
# Output:
#   1. One detailed CSV with all devices
#   2. One HTML dashboard auto-opened in browser
#
# Requires:
#   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
# ============================================================

$OutputFolder = "C:\Temp\Intune-25H2-FeatureUpdateReport"
$ProfileNamePattern = "FeatureUpdate-Windows11-25H2-Enterprise-*"

New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

Connect-MgGraph -Scopes `
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All"

# ============================================================
# Graph helpers
# ============================================================

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    Invoke-MgGraphRequest -Method GET -Uri $Uri
}

function Invoke-GraphPost {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [hashtable]$Body
    )

    $JsonBody = $Body | ConvertTo-Json -Depth 20

    try {
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri $Uri `
            -Body $JsonBody `
            -ContentType "application/json"
    }
    catch {
        Write-Host ""
        Write-Host "Graph POST failed. Request body was:"
        Write-Host $JsonBody
        Write-Host ""
        throw
    }
}

function Get-AllGraphPages {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Results = @()

    do {
        $Response = Invoke-GraphGet -Uri $Uri

        if ($Response.value) {
            $Results += $Response.value
        }

        $Uri = $Response.'@odata.nextLink'
    }
    while ($Uri)

    return $Results
}

function Start-IntuneReportExport {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyId
    )

    # No select list.
    # This keeps the portal-style FeatureUpdateDeviceState report.
    $Body = @{
        reportName       = "FeatureUpdateDeviceState"
        format           = "csv"
        localizationType = "LocalizedValuesAsAdditionalColumn"
        filter           = "(PolicyId eq '$PolicyId')"
    }

    Invoke-GraphPost `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" `
        -Body $Body
}

function Wait-IntuneReportExport {
    param(
        [Parameter(Mandatory)]
        [string]$JobId
    )

    if ([string]::IsNullOrWhiteSpace($JobId)) {
        throw "Export job was not created. JobId is empty."
    }

    $JobUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$JobId')"

    do {
        Start-Sleep -Seconds 5
        $Job = Invoke-GraphGet -Uri $JobUri
        Write-Host "Export job status: $($Job.status)"
    }
    while ($Job.status -notin @("completed", "failed"))

    if ($Job.status -eq "failed") {
        throw "Export job failed. JobId: $JobId"
    }

    return $Job
}

function Download-And-ExtractReport {
    param(
        [Parameter(Mandatory)]
        [string]$DownloadUrl,

        [Parameter(Mandatory)]
        [string]$ProfileName
    )

    $SafeProfileName = $ProfileName -replace '[\\/:*?"<>|]', '_'

    $ZipPath = Join-Path $OutputFolder "$SafeProfileName.zip"
    $ExtractPath = Join-Path $OutputFolder $SafeProfileName

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath

    if (Test-Path $ExtractPath) {
        Remove-Item -Path $ExtractPath -Recurse -Force
    }

    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

    $Csv = Get-ChildItem -Path $ExtractPath -Filter "*.csv" -Recurse | Select-Object -First 1

    if (-not $Csv) {
        throw "No CSV found for profile: $ProfileName"
    }

    return $Csv.FullName
}

# ============================================================
# Parsing helpers
# ============================================================

function Normalize-Text {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    # Converts InProgress / RebootRequired / OfferReady to word-separated text.
    $Value = $Value -replace '([a-z])([A-Z])', '$1 $2'

    return ($Value -replace '[^\p{L}\p{N}\s]', ' ' -replace '\s+', ' ').Trim().ToLower()
}

function Get-ValueByColumnAlias {
    param(
        [Parameter(Mandatory)]
        [object]$Row,

        [Parameter(Mandatory)]
        [string[]]$Aliases
    )

    foreach ($Property in $Row.PSObject.Properties) {
        $NormalizedPropertyName = Normalize-Text $Property.Name

        foreach ($Alias in $Aliases) {
            if ($NormalizedPropertyName -eq (Normalize-Text $Alias)) {
                return [string]$Property.Value
            }
        }
    }

    return $null
}

function Find-KnownValueInRow {
    param(
        [Parameter(Mandatory)]
        [object]$Row,

        [Parameter(Mandatory)]
        [string[]]$KnownValues
    )

    foreach ($Property in $Row.PSObject.Properties) {
        $RawValue = [string]$Property.Value
        $NormValue = Normalize-Text $RawValue

        foreach ($KnownValue in $KnownValues) {
            if ($NormValue -eq (Normalize-Text $KnownValue)) {
                return $RawValue
            }
        }
    }

    return $null
}

function Convert-ToDateTimeOrNull {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $ParsedDate = $null

    if ([datetime]::TryParse($Value, [ref]$ParsedDate)) {
        return $ParsedDate
    }

    return $null
}

function ConvertTo-JsonArray {
    param(
        [object[]]$InputObjects
    )

    $Items = @($InputObjects)

    if ($Items.Count -eq 0) {
        return "[]"
    }

    if ($Items.Count -eq 1) {
        return "[" + ($Items[0] | ConvertTo-Json -Depth 5 -Compress) + "]"
    }

    return ($Items | ConvertTo-Json -Depth 5 -Compress)
}

# ============================================================
# Known portal values
# ============================================================

$KnownUpdateStates = @(
    "Offering",
    "Installing",
    "Installed",
    "Uninstalling",
    "On hold"
)

$KnownUpdateSubstates = @(
    "Offer ready",
    "Reboot required",
    "Restart required",
    "Update installed",
    "Download start",
    "Download complete",
    "Install start",
    "Install complete",
    "Validation",
    "Commit",
    "Finalize"
)

$KnownAggregatedStates = @(
    "In progress",
    "InProgress",
    "Success",
    "Error",
    "Cancelled",
    "Canceled",
    "On hold",
    "OnHold"
)

# ============================================================
# Get Feature Update profiles
# ============================================================

Write-Host ""
Write-Host "Getting Feature Update profiles from Intune..."

$AllProfiles = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"

$TargetProfiles = $AllProfiles | Where-Object {
    $_.displayName -like $ProfileNamePattern
} | Sort-Object displayName

if (-not $TargetProfiles) {
    Write-Warning "No Feature Update profiles found matching: $ProfileNamePattern"

    Write-Host ""
    Write-Host "Profiles found:"
    $AllProfiles | Select-Object displayName, featureUpdateVersion, id | Format-Table -Auto

    return
}

Write-Host ""
Write-Host "Found $($TargetProfiles.Count) matching Feature Update profiles:"
$TargetProfiles | Select-Object displayName, featureUpdateVersion, id | Format-Table -Auto

# ============================================================
# Export and normalize all device rows
# ============================================================

$FinalRows = @()

foreach ($Profile in $TargetProfiles) {

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Exporting device status for:"
    Write-Host "  Profile: $($Profile.displayName)"
    Write-Host "  Version: $($Profile.featureUpdateVersion)"
    Write-Host "  PolicyId: $($Profile.id)"
    Write-Host "============================================================"

    $ExportJob = Start-IntuneReportExport -PolicyId $Profile.id

    if (-not $ExportJob.id) {
        throw "No export job ID returned for profile: $($Profile.displayName)"
    }

    $CompletedJob = Wait-IntuneReportExport -JobId $ExportJob.id

    $CsvPath = Download-And-ExtractReport `
        -DownloadUrl $CompletedJob.url `
        -ProfileName $Profile.displayName

    $Rows = @(Import-Csv -Path $CsvPath)

    Write-Host "Rows imported from profile report: $($Rows.Count)"

    foreach ($Row in $Rows) {

        # Standard portal columns
        $DeviceName = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Devices",
            "Device",
            "Device Name",
            "DeviceName"
        )

        $UPN = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "UPN",
            "User Principal Name",
            "UserPrincipalName"
        )

        $IntuneDeviceId = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Intune Device ID",
            "IntuneDeviceId",
            "Device Id",
            "DeviceId"
        )

        $EntraDeviceId = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Microsoft Entra Device ID",
            "Azure AD Device ID",
            "AADDeviceId",
            "AzureAdDeviceId",
            "AadDeviceId"
        )

        $LastEventTimeRaw = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Last event time",
            "Last Event Time",
            "LastEventTime",
            "EventDateTimeUTC",
            "CurrentDeviceUpdateStatusEventDateTimeUTC"
        )

        $LastScanTimeRaw = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Last scan time",
            "Last Scan Time",
            "LastScanTime",
            "LastWUScanTimeUTC",
            "Last WU Scan Time UTC"
        )

        $TargetVersion = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Target version",
            "Target Version",
            "TargetVersion",
            "FeatureUpdateVersion",
            "WindowsUpdateVersion"
        )

        # First try normal portal column names
        $UpdateState = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Update state",
            "Update State",
            "UpdateState",
            "CurrentDeviceUpdateStatus",
            "Current Device Update Status"
        )

        $UpdateSubstate = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Update substate",
            "Update Substate",
            "UpdateSubstate",
            "CurrentDeviceUpdateSubstatus",
            "Current Device Update Substatus"
        )

        $UpdateAggregatedState = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Update aggregated state",
            "Update Aggregated State",
            "Update aggregated status",
            "Update Aggregated Status",
            "UpdateAggregatedState",
            "UpdateAggregatedStatus",
            "AggregateState",
            "Aggregate State"
        )

        $AlertType = Get-ValueByColumnAlias -Row $Row -Aliases @(
            "Alert type",
            "Alert Type",
            "AlertType",
            "LatestAlertMessage",
            "Latest Alert Message"
        )

        # Critical fallback:
        # Scan the entire row for known portal values.
        # This catches cases where the export has duplicate/localized columns
        # and Import-Csv does not expose the expected header cleanly.
        $FoundState = Find-KnownValueInRow -Row $Row -KnownValues $KnownUpdateStates
        $FoundSubstate = Find-KnownValueInRow -Row $Row -KnownValues $KnownUpdateSubstates
        $FoundAggregatedState = Find-KnownValueInRow -Row $Row -KnownValues $KnownAggregatedStates

        if ($FoundState) {
            $UpdateState = $FoundState
        }

        if ($FoundSubstate) {
            $UpdateSubstate = $FoundSubstate
        }

        if ($FoundAggregatedState) {
            $UpdateAggregatedState = $FoundAggregatedState
        }

        $Result = if (-not [string]::IsNullOrWhiteSpace($UpdateSubstate)) {
            $UpdateSubstate
        }
        elseif (-not [string]::IsNullOrWhiteSpace($UpdateState)) {
            $UpdateState
        }
        elseif (-not [string]::IsNullOrWhiteSpace($UpdateAggregatedState)) {
            $UpdateAggregatedState
        }
        elseif (-not [string]::IsNullOrWhiteSpace($AlertType)) {
            "Alert: $AlertType"
        }
        else {
            "No status returned"
        }

        $FinalRows += [PSCustomObject]@{
            DeviceName                  = $DeviceName
            UPN                         = $UPN
            FeatureUpdateProfileName    = $Profile.displayName
            FeatureUpdateProfileVersion = $Profile.featureUpdateVersion
            TargetVersion               = $TargetVersion

            Result                      = $Result
            UpdateState                 = $UpdateState
            UpdateSubstate              = $UpdateSubstate
            UpdateAggregatedState       = $UpdateAggregatedState
            AlertType                   = $AlertType

            LastEventTime               = Convert-ToDateTimeOrNull -Value $LastEventTimeRaw
            LastEventTimeRaw            = $LastEventTimeRaw
            LastScanTime                = Convert-ToDateTimeOrNull -Value $LastScanTimeRaw
            LastScanTimeRaw             = $LastScanTimeRaw

            IntuneDeviceId              = $IntuneDeviceId
            EntraDeviceId               = $EntraDeviceId
            FeatureUpdateProfileId      = $Profile.id
        }
    }
}

# ============================================================
# Build wave summary
# ============================================================

$WaveSummary = $FinalRows |
    Group-Object FeatureUpdateProfileName |
    ForEach-Object {

        $ProfileName = $_.Name
        $Devices = $_.Group
        $TotalDevices = $Devices.Count

        $Success = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateAggregatedState) -eq "success" -or
            (Normalize-Text $_.UpdateState) -eq "installed" -or
            (Normalize-Text $_.UpdateSubstate) -eq "update installed" -or
            (Normalize-Text $_.Result) -eq "update installed"
        }).Count

        $ErrorCount = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateAggregatedState) -match "error|failed|failure" -or
            (Normalize-Text $_.AlertType) -match "error|failed|failure" -or
            (Normalize-Text $_.Result) -match "error|failed|failure"
        }).Count

        $Cancelled = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateAggregatedState) -match "cancelled|canceled" -or
            (Normalize-Text $_.Result) -match "cancelled|canceled"
        }).Count

        $OnHold = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateAggregatedState) -match "on hold|hold|safeguard" -or
            (Normalize-Text $_.Result) -match "on hold|hold|safeguard" -or
            (Normalize-Text $_.AlertType) -match "on hold|hold|safeguard"
        }).Count

        $InProgress = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateAggregatedState) -eq "in progress"
        }).Count

        if ($InProgress -eq 0) {
            $InProgress = $TotalDevices - $Success - $ErrorCount - $Cancelled - $OnHold
            if ($InProgress -lt 0) {
                $InProgress = 0
            }
        }

        $OfferReady = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateSubstate) -eq "offer ready" -or
            (Normalize-Text $_.Result) -eq "offer ready"
        }).Count

        $RebootRequired = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateSubstate) -match "reboot required|restart required" -or
            (Normalize-Text $_.Result) -match "reboot required|restart required"
        }).Count

        $UpdateInstalled = @($Devices | Where-Object {
            (Normalize-Text $_.UpdateSubstate) -eq "update installed" -or
            (Normalize-Text $_.Result) -eq "update installed" -or
            (Normalize-Text $_.UpdateState) -eq "installed"
        }).Count

        [PSCustomObject]@{
            FeatureUpdateProfileName = $ProfileName
            TotalDevices             = $TotalDevices
            InProgress               = $InProgress
            Success                  = $Success
            ErrorCount               = $ErrorCount
            Cancelled                = $Cancelled
            OnHold                   = $OnHold
            OfferReady               = $OfferReady
            RebootRequired           = $RebootRequired
            UpdateInstalled          = $UpdateInstalled
        }
    } |
    Sort-Object FeatureUpdateProfileName

# ============================================================
# Export one CSV only
# ============================================================

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$DetailedCsv = Join-Path $OutputFolder "Intune_25H2_FeatureUpdate_AllDeviceDetails_$Timestamp.csv"
$HtmlReportPath = Join-Path $OutputFolder "Intune_25H2_FeatureUpdate_Dashboard_$Timestamp.html"

$FinalRows |
    Sort-Object FeatureUpdateProfileName, Result, DeviceName |
    Export-Csv -Path $DetailedCsv -NoTypeInformation -Encoding UTF8

# ============================================================
# Prepare HTML data
# ============================================================

$WaveSummaryForHtml = @($WaveSummary | ForEach-Object {
    [PSCustomObject]@{
        FeatureUpdateProfileName = [string]$_.FeatureUpdateProfileName
        TotalDevices             = [int]$_.TotalDevices
        InProgress               = [int]$_.InProgress
        Success                  = [int]$_.Success
        ErrorCount               = [int]$_.ErrorCount
        Cancelled                = [int]$_.Cancelled
        OnHold                   = [int]$_.OnHold
        OfferReady               = [int]$_.OfferReady
        RebootRequired           = [int]$_.RebootRequired
        UpdateInstalled          = [int]$_.UpdateInstalled
    }
})

$DeviceRowsForHtml = @($FinalRows | ForEach-Object {
    [PSCustomObject]@{
        DeviceName                = [string]$_.DeviceName
        UPN                       = [string]$_.UPN
        FeatureUpdateProfileName  = [string]$_.FeatureUpdateProfileName
        Result                    = [string]$_.Result
        UpdateState               = [string]$_.UpdateState
        UpdateSubstate            = [string]$_.UpdateSubstate
        UpdateAggregatedState     = [string]$_.UpdateAggregatedState
        AlertType                 = [string]$_.AlertType
        LastEventTimeRaw          = [string]$_.LastEventTimeRaw
        LastScanTimeRaw           = [string]$_.LastScanTimeRaw
        TargetVersion             = [string]$_.TargetVersion
        IntuneDeviceId            = [string]$_.IntuneDeviceId
        EntraDeviceId             = [string]$_.EntraDeviceId
    }
})

$WaveSummaryJson = ConvertTo-JsonArray -InputObjects $WaveSummaryForHtml
$DeviceRowsJson  = ConvertTo-JsonArray -InputObjects $DeviceRowsForHtml

$TotalDevicesAll = ($WaveSummaryForHtml | Measure-Object TotalDevices -Sum).Sum
$TotalSuccessAll = ($WaveSummaryForHtml | Measure-Object Success -Sum).Sum
$TotalInProgressAll = ($WaveSummaryForHtml | Measure-Object InProgress -Sum).Sum
$TotalErrorAll = ($WaveSummaryForHtml | Measure-Object ErrorCount -Sum).Sum
$TotalRebootRequiredAll = ($WaveSummaryForHtml | Measure-Object RebootRequired -Sum).Sum

if ($null -eq $TotalDevicesAll) { $TotalDevicesAll = 0 }
if ($null -eq $TotalSuccessAll) { $TotalSuccessAll = 0 }
if ($null -eq $TotalInProgressAll) { $TotalInProgressAll = 0 }
if ($null -eq $TotalErrorAll) { $TotalErrorAll = 0 }
if ($null -eq $TotalRebootRequiredAll) { $TotalRebootRequiredAll = 0 }

# ============================================================
# Generate HTML dashboard
# ============================================================

$GeneratedOn = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

$HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Intune 25H2 Feature Update Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
:root {
    --bg: #f5f7fb;
    --card: #ffffff;
    --text: #172033;
    --muted: #667085;
    --border: #e4e7ec;
    --blue: #2563eb;
    --green: #16a34a;
    --orange: #f97316;
    --red: #dc2626;
    --yellow: #ca8a04;
    --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
}

* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: "Segoe UI", Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
}

header {
    padding: 32px 40px 22px;
    background: linear-gradient(135deg, #0f172a, #1e3a8a);
    color: white;
}

header h1 {
    margin: 0;
    font-size: 30px;
    font-weight: 700;
}

header p {
    margin: 8px 0 0;
    color: #cbd5e1;
    font-size: 14px;
}

main {
    padding: 28px 40px 40px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(5, minmax(160px, 1fr));
    gap: 18px;
    margin-bottom: 24px;
}

.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 20px;
    box-shadow: var(--shadow);
}

.card-title {
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 8px;
}

.card-value {
    font-size: 30px;
    font-weight: 700;
}

.blue { color: var(--blue); }
.green { color: var(--green); }
.orange { color: var(--orange); }
.red { color: var(--red); }
.yellow { color: var(--yellow); }

.section {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    box-shadow: var(--shadow);
    margin-bottom: 24px;
    overflow: hidden;
}

.section-header {
    padding: 18px 22px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
}

.section-header h2 {
    margin: 0;
    font-size: 18px;
}

.section-body {
    padding: 18px 22px;
}

.filters {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}

input, select {
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 14px;
    background: white;
    min-width: 220px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

th {
    text-align: left;
    color: var(--muted);
    font-weight: 600;
    border-bottom: 1px solid var(--border);
    padding: 12px 10px;
    white-space: nowrap;
}

td {
    border-bottom: 1px solid var(--border);
    padding: 11px 10px;
    vertical-align: middle;
}

tr:hover {
    background: #f8fafc;
}

.pill {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
}

.pill-success { background: #dcfce7; color: #166534; }
.pill-progress { background: #dbeafe; color: #1d4ed8; }
.pill-error { background: #fee2e2; color: #991b1b; }
.pill-reboot { background: #ffedd5; color: #9a3412; }
.pill-neutral { background: #f1f5f9; color: #475569; }

.bar-wrap {
    width: 180px;
    height: 10px;
    background: #e5e7eb;
    border-radius: 999px;
    overflow: hidden;
    display: flex;
}

.bar-success { background: var(--green); height: 100%; }
.bar-progress { background: var(--blue); height: 100%; }
.bar-error { background: var(--red); height: 100%; }

.small-muted {
    color: var(--muted);
    font-size: 12px;
}

.table-scroll {
    overflow: auto;
    max-height: 620px;
}

@media (max-width: 1100px) {
    .cards {
        grid-template-columns: repeat(2, 1fr);
    }

    main {
        padding: 20px;
    }

    header {
        padding: 24px 20px;
    }
}
</style>
</head>

<body>
<header>
    <h1>Intune 25H2 Feature Update Dashboard</h1>
    <p>Generated on __GENERATED_ON__ · Profiles matching __PROFILE_PATTERN__</p>
</header>

<main>
    <div class="cards">
        <div class="card">
            <div class="card-title">Total devices</div>
            <div class="card-value blue">__TOTAL_DEVICES__</div>
        </div>

        <div class="card">
            <div class="card-title">Success</div>
            <div class="card-value green">__TOTAL_SUCCESS__</div>
        </div>

        <div class="card">
            <div class="card-title">In progress</div>
            <div class="card-value orange">__TOTAL_INPROGRESS__</div>
        </div>

        <div class="card">
            <div class="card-title">Errors</div>
            <div class="card-value red">__TOTAL_ERROR__</div>
        </div>

        <div class="card">
            <div class="card-title">Reboot required</div>
            <div class="card-value yellow">__TOTAL_REBOOT__</div>
        </div>
    </div>

    <section class="section">
        <div class="section-header">
            <h2>Wave summary</h2>
            <span class="small-muted">Total / In progress / Success / Error / Reboot required</span>
        </div>

        <div class="section-body table-scroll">
            <table id="summaryTable">
                <thead>
                    <tr>
                        <th>Feature update profile</th>
                        <th>Total</th>
                        <th>Progress</th>
                        <th>In progress</th>
                        <th>Success</th>
                        <th>Error</th>
                        <th>Cancelled</th>
                        <th>On hold</th>
                        <th>Offer ready</th>
                        <th>Reboot required</th>
                        <th>Update installed</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </section>

    <section class="section">
        <div class="section-header">
            <h2>Device results</h2>
            <div class="filters">
                <input id="searchBox" placeholder="Search device, UPN, status..." />
                <select id="waveFilter">
                    <option value="">All waves</option>
                </select>
                <select id="resultFilter">
                    <option value="">All results</option>
                </select>
            </div>
        </div>

        <div class="section-body table-scroll">
            <table id="deviceTable">
                <thead>
                    <tr>
                        <th>Device</th>
                        <th>UPN</th>
                        <th>Wave</th>
                        <th>Result</th>
                        <th>Update state</th>
                        <th>Update substate</th>
                        <th>Aggregated state</th>
                        <th>Alert</th>
                        <th>Last event</th>
                        <th>Last scan</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </section>
</main>

<script>
const waveSummaryRaw = __WAVE_SUMMARY_JSON__;
const deviceRowsRaw = __DEVICE_ROWS_JSON__;

const waveSummary = Array.isArray(waveSummaryRaw) ? waveSummaryRaw : [waveSummaryRaw];
const deviceRows = Array.isArray(deviceRowsRaw) ? deviceRowsRaw : [deviceRowsRaw];

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function normalize(value) {
    return String(value || "").toLowerCase();
}

function getPillClass(value) {
    const v = normalize(value);

    if (v.includes("reboot") || v.includes("restart")) return "pill-reboot";
    if (v.includes("success") || v.includes("installed")) return "pill-success";
    if (v.includes("error") || v.includes("failed") || v.includes("failure")) return "pill-error";
    if (v.includes("progress") || v.includes("offer") || v.includes("installing") || v.includes("offering")) return "pill-progress";

    return "pill-neutral";
}

function renderSummary() {
    const tbody = document.querySelector("#summaryTable tbody");
    tbody.innerHTML = "";

    waveSummary.forEach(row => {
        const total = Number(row.TotalDevices || 0);
        const success = Number(row.Success || 0);
        const progress = Number(row.InProgress || 0);
        const error = Number(row.ErrorCount || 0);

        const successPct = total ? (success / total) * 100 : 0;
        const progressPct = total ? (progress / total) * 100 : 0;
        const errorPct = total ? (error / total) * 100 : 0;

        const tr = document.createElement("tr");

        tr.innerHTML =
            "<td><strong>" + escapeHtml(row.FeatureUpdateProfileName) + "</strong></td>" +
            "<td>" + total + "</td>" +
            "<td>" +
                "<div class='bar-wrap'>" +
                    "<div class='bar-success' style='width:" + successPct + "%'></div>" +
                    "<div class='bar-progress' style='width:" + progressPct + "%'></div>" +
                    "<div class='bar-error' style='width:" + errorPct + "%'></div>" +
                "</div>" +
            "</td>" +
            "<td><span class='pill pill-progress'>" + escapeHtml(row.InProgress) + "</span></td>" +
            "<td><span class='pill pill-success'>" + escapeHtml(row.Success) + "</span></td>" +
            "<td><span class='pill pill-error'>" + escapeHtml(row.ErrorCount) + "</span></td>" +
            "<td>" + escapeHtml(row.Cancelled) + "</td>" +
            "<td>" + escapeHtml(row.OnHold) + "</td>" +
            "<td>" + escapeHtml(row.OfferReady) + "</td>" +
            "<td><span class='pill pill-reboot'>" + escapeHtml(row.RebootRequired) + "</span></td>" +
            "<td>" + escapeHtml(row.UpdateInstalled) + "</td>";

        tbody.appendChild(tr);
    });
}

function populateFilters() {
    const waveFilter = document.querySelector("#waveFilter");
    const resultFilter = document.querySelector("#resultFilter");

    const waves = [...new Set(deviceRows.map(x => x.FeatureUpdateProfileName).filter(Boolean))].sort();
    const results = [...new Set(deviceRows.map(x => x.Result).filter(Boolean))].sort();

    waves.forEach(wave => {
        const opt = document.createElement("option");
        opt.value = wave;
        opt.textContent = wave;
        waveFilter.appendChild(opt);
    });

    results.forEach(result => {
        const opt = document.createElement("option");
        opt.value = result;
        opt.textContent = result;
        resultFilter.appendChild(opt);
    });
}

function renderDevices() {
    const tbody = document.querySelector("#deviceTable tbody");
    const search = normalize(document.querySelector("#searchBox").value);
    const selectedWave = document.querySelector("#waveFilter").value;
    const selectedResult = document.querySelector("#resultFilter").value;

    tbody.innerHTML = "";

    const filtered = deviceRows.filter(row => {
        const haystack = normalize([
            row.DeviceName,
            row.UPN,
            row.FeatureUpdateProfileName,
            row.Result,
            row.UpdateState,
            row.UpdateSubstate,
            row.UpdateAggregatedState,
            row.AlertType
        ].join(" "));

        const matchesSearch = !search || haystack.includes(search);
        const matchesWave = !selectedWave || row.FeatureUpdateProfileName === selectedWave;
        const matchesResult = !selectedResult || row.Result === selectedResult;

        return matchesSearch && matchesWave && matchesResult;
    });

    filtered.forEach(row => {
        const tr = document.createElement("tr");
        const pillClass = getPillClass(row.Result);

        tr.innerHTML =
            "<td><strong>" + escapeHtml(row.DeviceName) + "</strong></td>" +
            "<td>" + escapeHtml(row.UPN) + "</td>" +
            "<td>" + escapeHtml(row.FeatureUpdateProfileName) + "</td>" +
            "<td><span class='pill " + pillClass + "'>" + escapeHtml(row.Result) + "</span></td>" +
            "<td>" + escapeHtml(row.UpdateState) + "</td>" +
            "<td>" + escapeHtml(row.UpdateSubstate) + "</td>" +
            "<td>" + escapeHtml(row.UpdateAggregatedState) + "</td>" +
            "<td>" + escapeHtml(row.AlertType) + "</td>" +
            "<td>" + escapeHtml(row.LastEventTimeRaw) + "</td>" +
            "<td>" + escapeHtml(row.LastScanTimeRaw) + "</td>";

        tbody.appendChild(tr);
    });
}

renderSummary();
populateFilters();
renderDevices();

document.querySelector("#searchBox").addEventListener("input", renderDevices);
document.querySelector("#waveFilter").addEventListener("change", renderDevices);
document.querySelector("#resultFilter").addEventListener("change", renderDevices);
</script>
</body>
</html>
'@

$Html = $HtmlTemplate
$Html = $Html.Replace("__GENERATED_ON__", $GeneratedOn)
$Html = $Html.Replace("__PROFILE_PATTERN__", $ProfileNamePattern)
$Html = $Html.Replace("__TOTAL_DEVICES__", [string]$TotalDevicesAll)
$Html = $Html.Replace("__TOTAL_SUCCESS__", [string]$TotalSuccessAll)
$Html = $Html.Replace("__TOTAL_INPROGRESS__", [string]$TotalInProgressAll)
$Html = $Html.Replace("__TOTAL_ERROR__", [string]$TotalErrorAll)
$Html = $Html.Replace("__TOTAL_REBOOT__", [string]$TotalRebootRequiredAll)
$Html = $Html.Replace("__WAVE_SUMMARY_JSON__", $WaveSummaryJson)
$Html = $Html.Replace("__DEVICE_ROWS_JSON__", $DeviceRowsJson)

$Html | Out-File -FilePath $HtmlReportPath -Encoding UTF8 -Force

# ============================================================
# Console output
# ============================================================

Write-Host ""
Write-Host "============================================================"
Write-Host "Feature Update wave summary"
Write-Host "============================================================"

$WaveSummary | Format-Table -AutoSize

Write-Host ""
Write-Host "Detailed CSV report:"
Write-Host $DetailedCsv

Write-Host ""
Write-Host "HTML dashboard report:"
Write-Host $HtmlReportPath

Write-Host ""
Write-Host "Total merged rows exported: $($FinalRows.Count)"

Write-Host ""
Write-Host "Devices with reboot/restart in result/substate:"
$FinalRows |
    Where-Object {
        (Normalize-Text $_.Result) -match "reboot|restart" -or
        (Normalize-Text $_.UpdateSubstate) -match "reboot|restart"
    } |
    Select-Object DeviceName, UPN, FeatureUpdateProfileName, Result, UpdateState, UpdateSubstate, UpdateAggregatedState |
    Format-Table -AutoSize

Start-Process $HtmlReportPath
