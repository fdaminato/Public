<#
.SYNOPSIS
    Export Intune Windows device dashboard to HTML + CSV + JSON.

.DESCRIPTION
    Retrieves Windows managed devices from Microsoft Graph and builds a self-contained HTML dashboard.

    Included:
      - Tenant logo from Entra Company Branding
      - Device compliance
      - Windows OS version / UBR status
      - Primary user from Intune managedDevice users relationship
      - Primary user account status from Entra ID accountEnabled
      - Secure Boot status from Intune Windows health attestation report
      - Firmware details from the same Intune report when available
      - Storage
      - User / model / serial
      - Last check-in filtering
      - Dynamic quick cards and charts

.REQUIREMENTS
    PowerShell 7 recommended
    Microsoft.Graph.Authentication

.PERMISSIONS
    DeviceManagementManagedDevices.Read.All
    Directory.Read.All
    Organization.Read.All
    OrganizationalBranding.Read.All
    User.Read.All
#>

[CmdletBinding()]
param(
    [string]$OutputFolder,

    [int]$MinimumUBR_26100 = 8037,

    [int]$MinimumUBR_26200 = 8037,

    [int]$ReportExportTimeoutSeconds = 300,

    [string]$GraphClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",

    [string]$GraphTenantId = "organizations",

    [ValidateSet("Process", "CurrentUser")]
    [string]$GraphContextScope = "Process",

    [bool]$DisableLoginByWAM = $true,

    [switch]$UseDeviceCode,

    [switch]$OpenReport
)

$ErrorActionPreference = "Stop"

# ============================================================
# Output folder
# ============================================================

$ScriptRootSafe = if ($PSScriptRoot) {
    $PSScriptRoot
}
elseif ($PSCommandPath) {
    Split-Path -Parent $PSCommandPath
}
else {
    (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path $ScriptRootSafe "IntuneDashboardOutput"
}

if (!(Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$CsvPath  = Join-Path $OutputFolder "Intune-WindowsDevices-$Timestamp.csv"
$JsonPath = Join-Path $OutputFolder "Intune-WindowsDevices-$Timestamp.json"
$HtmlPath = Join-Path $OutputFolder "Intune-Dashboard-$Timestamp.html"
$PrimaryUserRawPath = Join-Path $OutputFolder "Intune-PrimaryUsers-Raw-$Timestamp.json"
$PrimaryUserAccountRawPath = Join-Path $OutputFolder "Intune-PrimaryUser-AccountStatus-Raw-$Timestamp.json"
$SecureBootRawPath = Join-Path $OutputFolder "Intune-SecureBoot-Firmware-Raw-$Timestamp.json"
$HardwareRawPath = Join-Path $OutputFolder "Intune-HardwareInformation-Raw-$Timestamp.json"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Intune Windows Dashboard Export" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output folder: $OutputFolder"
Write-Host ""

# ============================================================
# Module / Graph connection
# ============================================================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$Scopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "Directory.Read.All",
    "Organization.Read.All",
    "OrganizationalBranding.Read.All",
    "User.Read.All"
)

function Connect-DashboardMgGraph {
    param(
        [Parameter(Mandatory)]
        [string[]]$Scopes,

        [string]$ClientId,

        [string]$TenantId,

        [ValidateSet("Process", "CurrentUser")]
        [string]$ContextScope,

        [bool]$DisableLoginByWAM,

        [switch]$UseDeviceCode
    )

    $ConnectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    $ConnectParameters = @{ Scopes = $Scopes }

    if ($ConnectCommand.Parameters.ContainsKey("ContextScope")) {
        $ConnectParameters.ContextScope = $ContextScope
    }

    if ($DisableLoginByWAM -and -not $UseDeviceCode) {
        $SetGraphOptionCommand = Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue
        if ($SetGraphOptionCommand -and $SetGraphOptionCommand.Parameters.ContainsKey("DisableLoginByWAM")) {
            Set-MgGraphOption -DisableLoginByWAM $true
        }
    }

    if (-not $UseDeviceCode -and -not [string]::IsNullOrWhiteSpace($ClientId) -and $ConnectCommand.Parameters.ContainsKey("ClientId")) {
        $ConnectParameters.ClientId = $ClientId
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId) -and $ConnectCommand.Parameters.ContainsKey("TenantId")) {
        $ConnectParameters.TenantId = $TenantId
    }

    if ($UseDeviceCode -and $ConnectCommand.Parameters.ContainsKey("UseDeviceCode")) {
        $ConnectParameters.UseDeviceCode = $true
    }

    if ($ConnectCommand.Parameters.ContainsKey("NoWelcome")) {
        $ConnectParameters.NoWelcome = $true
    }

    Connect-MgGraph @ConnectParameters
}

function Test-DashboardMgGraphConnection {
    try {
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id" -ErrorAction Stop | Out-Null
    }
    catch {
        $Message = $_.Exception.Message
        throw @"
Microsoft Graph sign-in completed, but the SDK could not acquire a usable token.

Underlying error:
$Message

Try rerunning from a new PowerShell window. If browser auth is hidden in your terminal, rerun with -UseDeviceCode.
"@
    }
}

$Context = Get-MgContext -ErrorAction SilentlyContinue

if ($Context -and [string]::IsNullOrWhiteSpace($Context.ClientId)) {
    Write-Host "Current Graph session is missing a client id. Reconnecting..." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    $Context = $null
}

if ($Context -and $Context.ContextScope -and ([string]$Context.ContextScope -ne $GraphContextScope)) {
    Write-Host "Current Graph session context scope is $($Context.ContextScope). Reconnecting with $GraphContextScope scope..." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    $Context = $null
}

$ConnectedThisRun = $false

if (-not $Context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-DashboardMgGraph -Scopes $Scopes -ClientId $GraphClientId -TenantId $GraphTenantId -ContextScope $GraphContextScope -DisableLoginByWAM $DisableLoginByWAM -UseDeviceCode:$UseDeviceCode
    $ConnectedThisRun = $true
}
else {
    Write-Host "Already connected to Microsoft Graph as $($Context.Account)" -ForegroundColor Green

    $MissingScopes = @()

    foreach ($Scope in $Scopes) {
        if ($Context.Scopes -notcontains $Scope) {
            $MissingScopes += $Scope
        }
    }

    if ($MissingScopes.Count -gt 0) {
        Write-Host "Current Graph session is missing scope(s): $($MissingScopes -join ', ')" -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        Connect-DashboardMgGraph -Scopes $Scopes -ClientId $GraphClientId -TenantId $GraphTenantId -ContextScope $GraphContextScope -DisableLoginByWAM $DisableLoginByWAM -UseDeviceCode:$UseDeviceCode
        $ConnectedThisRun = $true
    }
}

try {
    Test-DashboardMgGraphConnection
}
catch {
    if ($ConnectedThisRun) { throw }

    Write-Host "Existing Graph session could not acquire a token. Reconnecting..." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    Connect-DashboardMgGraph -Scopes $Scopes -ClientId $GraphClientId -TenantId $GraphTenantId -ContextScope $GraphContextScope -DisableLoginByWAM $DisableLoginByWAM -UseDeviceCode:$UseDeviceCode
    Test-DashboardMgGraphConnection
}

# ============================================================
# Helpers
# ============================================================

function Normalize-Value {
    param($Value)

    if ($null -eq $Value) { return "" }
    return [string]$Value
}

function Use-ValueOrUnknown {
    param(
        $Value,
        [string]$UnknownText = "Unknown"
    )

    $Normalized = Normalize-Value $Value
    if ([string]::IsNullOrWhiteSpace($Normalized)) { return $UnknownText }
    return $Normalized
}

function ConvertTo-HtmlSafe {
    param($Value)

    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string[]]$PropertyNames
    )

    if ($null -eq $Object) { return "" }

    foreach ($PropertyName in $PropertyNames) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.ContainsKey($PropertyName)) {
                $Value = Normalize-Value $Object[$PropertyName]
                if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
            }
        }

        if ($Object.PSObject.Properties.Name -contains $PropertyName) {
            $Value = Normalize-Value $Object.$PropertyName
            if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
        }
    }

    return ""
}

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [switch]$AllowFailure
    )

    $Results = @()
    $NextUri = $Uri

    while ($NextUri) {
        try {
            Write-Host "GET $NextUri" -ForegroundColor DarkGray
            $Response = Invoke-MgGraphRequest -Method GET -Uri $NextUri

            if ($Response -and $Response.value) {
                foreach ($Item in @($Response.value)) {
                    $Results += $Item
                }
            }

            $NextUri = $Response.'@odata.nextLink'
        }
        catch {
            if ($AllowFailure) {
                Write-Warning "Graph query failed, continuing with partial/empty results."
                Write-Warning $_.Exception.Message
                break
            }
            else {
                throw
            }
        }
    }

    return $Results
}


function Normalize-ReportFieldName {
    param([string]$Value)

    return ((Normalize-Value $Value) -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
}

function Get-ReportFieldValue {
    param(
        $Object,
        [string[]]$PropertyNames
    )

    if ($null -eq $Object) { return "" }

    $Wanted = @{}
    foreach ($PropertyName in $PropertyNames) {
        $Wanted[(Normalize-ReportFieldName $PropertyName)] = $true
    }

    foreach ($Property in $Object.PSObject.Properties) {
        $NormalizedName = Normalize-ReportFieldName $Property.Name
        if ($Wanted.ContainsKey($NormalizedName)) {
            return Normalize-Value $Property.Value
        }
    }

    return ""
}

function Invoke-IntuneReportExport {
    param(
        [Parameter(Mandatory)]
        [string]$ReportName,

        [string[]]$Select,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [Parameter(Mandatory)]
        [string]$Timestamp,

        [int]$TimeoutSeconds = 300,

        [switch]$AllowFailure
    )

    $Body = @{
        reportName       = $ReportName
        format           = "csv"
        localizationType = "replaceLocalizableValues"
    }

    if ($Select -and $Select.Count -gt 0) {
        $Body.select = $Select
    }

    try {
        Write-Host "Requesting Intune report export: $ReportName" -ForegroundColor DarkGray

        $Job = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" `
            -Body ($Body | ConvertTo-Json -Depth 20) `
            -ContentType "application/json" `
            -ErrorAction Stop

        $JobId = Normalize-Value $Job.id
        if ([string]::IsNullOrWhiteSpace($JobId)) {
            throw "Report export did not return a job id."
        }

        $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $CompletedJob = $null

        while ((Get-Date) -lt $Deadline) {
            Start-Sleep -Seconds 5

            $JobStatusUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$JobId')"
            $JobStatus = Invoke-MgGraphRequest -Method GET -Uri $JobStatusUri -ErrorAction Stop
            $Status = (Normalize-Value $JobStatus.status).ToLowerInvariant()

            if ($Status -eq "completed" -or $Status -eq "complete") {
                $CompletedJob = $JobStatus
                break
            }

            if ($Status -eq "failed") {
                throw "Report export failed for $ReportName."
            }
        }

        if (-not $CompletedJob) {
            throw "Timed out waiting for $ReportName export after $TimeoutSeconds seconds."
        }

        $DownloadUrl = Normalize-Value $CompletedJob.url
        if ([string]::IsNullOrWhiteSpace($DownloadUrl)) {
            throw "Completed report export did not include a download URL."
        }

        $SafeReportName = (Normalize-Value $ReportName) -replace '[^a-zA-Z0-9\-_\.]', '_'
        $ZipPath = Join-Path $OutputFolder "$SafeReportName-$Timestamp.zip"
        $ExtractPath = Join-Path $OutputFolder "$SafeReportName-$Timestamp"

        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing

        if (Test-Path $ExtractPath) {
            Remove-Item -Path $ExtractPath -Recurse -Force
        }

        Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

        $CsvFile = Get-ChildItem -Path $ExtractPath -Filter *.csv -Recurse | Select-Object -First 1
        if (-not $CsvFile) {
            throw "The downloaded $ReportName export did not contain a CSV file."
        }

        $Rows = @(Import-Csv -Path $CsvFile.FullName)

        return [pscustomobject]@{
            Succeeded  = $true
            ReportName = $ReportName
            Rows       = $Rows
            CsvPath    = $CsvFile.FullName
            ZipPath    = $ZipPath
            Error      = ""
        }
    }
    catch {
        if ($AllowFailure) {
            Write-Warning "Could not export Intune report $ReportName."
            Write-Warning $_.Exception.Message

            return [pscustomobject]@{
                Succeeded  = $false
                ReportName = $ReportName
                Rows       = @()
                CsvPath    = ""
                ZipPath    = ""
                Error      = $_.Exception.Message
            }
        }

        throw
    }
}

function Convert-SecureBootStatus {
    param($SecureBoot)

    $Status = Normalize-Value $SecureBoot
    if ([string]::IsNullOrWhiteSpace($Status)) { return "Unknown" }

    switch -Regex ($Status.ToLowerInvariant()) {
        "^(enabled|on|true|1)$" { return "Enabled" }
        "^(disabled|off|false|0)$" { return "Disabled" }
        "not\s*applicable|notapplicable" { return "Not applicable" }
        "not\s*supported|notsupported|unsupported" { return "Not supported" }
        "unknown" { return "Unknown" }
        default { return $Status }
    }
}

function Get-SecureBootRecordFromReportRow {
    param(
        [Parameter(Mandatory)]
        $ReportRow,

        [string]$ReportName
    )

    $SecureBootRaw = Get-ReportFieldValue -Object $ReportRow -PropertyNames @(
        "SecureBootStatus",
        "Secure Boot Status",
        "SecureBootEnabled",
        "Secure Boot Enabled",
        "Secure Boot enabled"
    )

    return [pscustomobject]@{
        DeviceName                  = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceName", "Device name", "Device Name")
        DeviceId                    = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceId", "Device ID", "IntuneDeviceId", "Intune Device Id")
        AzureADDeviceId             = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("AadDeviceId", "AzureADDeviceId", "Azure AD Device ID", "Microsoft Entra device ID", "MicrosoftEntraDeviceId", "ReferenceId")
        UPN                         = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("UPN", "UserPrincipalName", "User Principal Name")
        PrimaryUser                 = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("PrimaryUser", "Primary User")

        SecureBootStatus            = Convert-SecureBootStatus $SecureBootRaw
        SecureBootRaw               = Normalize-Value $SecureBootRaw
        SecureBootReportSource      = $ReportName
        SecureBootLastUpdateDateTime = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("LastUpdateDateTime", "Last Update Date Time", "HealthCertIssuedDate")
        SecureBootCertificateStatus = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("CertificateStatus", "Certificate status", "SecureBootCertificateStatus")
        SecureBootAttestationError  = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("AttestationError", "Attestation Error")
        SecureBootDeviceOS          = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceOS", "Device OS", "OSVersion", "OS version")
        SecureBootTPMVersion        = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("TpmVersion", "TPM Version")
        SecureBootCodeIntegrityStatus = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("CodeIntegrityStatus", "Code Integrity Status")
        SecureBootVSMStatus         = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("VSMStatus", "VSM Status")

        FirmwareManufacturer        = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("FirmwareManufacturer", "Firmware Manufacturer")
        FirmwareVersion             = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("FirmwareVersion", "Firmware Version")
        FirmwareReleaseDate         = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("FirmwareReleaseDate", "Firmware Release Date")
        DeviceSKU                   = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceSKU", "Device SKU")
        SystemBoardManufacturer     = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("SystemBoardManufacturer", "System Board Manufacturer")
        SystemBoardModel            = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("SystemBoardModel", "System Board Model")
        SystemBoardVersion          = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("SystemBoardVersion", "System Board Version")
        ModelFamily                 = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("ModelFamily", "Model Family")
    }
}

function Convert-BytesToGB {
    param($Bytes)

    if ($null -eq $Bytes -or $Bytes -eq "") { return $null }

    try { return [math]::Round(($Bytes / 1GB), 2) }
    catch { return $null }
}

function Get-Percent {
    param($Part, $Total)

    if ($null -eq $Part -or $null -eq $Total -or $Total -eq 0) { return $null }
    return [math]::Round(($Part / $Total) * 100, 1)
}

function Open-FileCrossPlatform {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        if ($IsWindows) { Start-Process $Path }
        elseif ($IsMacOS) { & open $Path }
        elseif ($IsLinux) { & xdg-open $Path }
        else { Write-Host "Open this file manually: $Path" -ForegroundColor Yellow }
    }
    catch {
        Write-Warning "Could not automatically open report. Open manually: $Path"
    }
}

function Get-OSBuildInfo {
    param([string]$OSVersion)

    $Result = [ordered]@{
        Build           = $null
        UBR             = $null
        FriendlyVersion = "Unknown"
        VersionStatus   = "Unknown"
        UBRStatus       = "Unknown"
    }

    if ([string]::IsNullOrWhiteSpace($OSVersion)) { return [pscustomobject]$Result }

    $Parts = $OSVersion.Split(".")

    if ($Parts.Count -ge 3) {
        $Build = 0
        if ([int]::TryParse($Parts[2], [ref]$Build)) { $Result.Build = $Build }

        if ($Parts.Count -ge 4) {
            $UBR = 0
            if ([int]::TryParse($Parts[3], [ref]$UBR)) { $Result.UBR = $UBR }
        }

        switch ($Result.Build) {
            26100 {
                $Result.FriendlyVersion = "Windows 11 24H2"
                $Result.VersionStatus = "24H2 branch"
                if ($Result.UBR -ge $MinimumUBR_26100) { $Result.UBRStatus = "OK" }
                else { $Result.UBRStatus = "Below target" }
            }
            26200 {
                $Result.FriendlyVersion = "Windows 11 25H2"
                $Result.VersionStatus = "25H2 branch"
                if ($Result.UBR -ge $MinimumUBR_26200) { $Result.UBRStatus = "OK" }
                else { $Result.UBRStatus = "Below target" }
            }
            default {
                if ($Result.Build -and $Result.Build -lt 26100) {
                    $Result.FriendlyVersion = "Older Windows build"
                    $Result.VersionStatus = "Older than 24H2"
                    $Result.UBRStatus = "Review"
                }
                elseif ($Result.Build -and $Result.Build -gt 26200) {
                    $Result.FriendlyVersion = "Newer Windows build"
                    $Result.VersionStatus = "Newer than expected"
                    $Result.UBRStatus = "Review"
                }
                else {
                    $Result.FriendlyVersion = "Unknown Windows build"
                    $Result.VersionStatus = "Unknown"
                    $Result.UBRStatus = "Review"
                }
            }
        }
    }

    return [pscustomobject]$Result
}

function Convert-ImageFileToDataUri {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (!(Test-Path $Path)) { return "" }
    if ((Get-Item $Path).Length -le 0) { return "" }

    $Bytes = [System.IO.File]::ReadAllBytes($Path)
    $Mime = "image/png"

    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xD8 -and $Bytes[2] -eq 0xFF) {
        $Mime = "image/jpeg"
    }
    elseif ($Bytes.Length -ge 4 -and $Bytes[0] -eq 0x89 -and $Bytes[1] -eq 0x50 -and $Bytes[2] -eq 0x4E -and $Bytes[3] -eq 0x47) {
        $Mime = "image/png"
    }
    elseif ($Bytes.Length -ge 4 -and $Bytes[0] -eq 0x47 -and $Bytes[1] -eq 0x49 -and $Bytes[2] -eq 0x46 -and $Bytes[3] -eq 0x38) {
        $Mime = "image/gif"
    }
    elseif ($Bytes.Length -ge 4 -and $Bytes[0] -eq 0x52 -and $Bytes[1] -eq 0x49 -and $Bytes[2] -eq 0x46 -and $Bytes[3] -eq 0x46) {
        $Mime = "image/webp"
    }

    $Base64 = [Convert]::ToBase64String($Bytes)
    return "data:$Mime;base64,$Base64"
}

function Get-TenantBrandingLogo {
    param(
        [string]$OutputFolder,
        [string]$Timestamp
    )

    Write-Host ""
    Write-Host "Retrieving tenant logo from Entra Company Branding..." -ForegroundColor Cyan

    $TenantDisplayName = "Intune Windows Dashboard"
    $LogoDataUri = ""

    try {
        $OrgResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName"

        if (-not $OrgResponse.value -or $OrgResponse.value.Count -eq 0) {
            Write-Warning "Could not retrieve organization object."
            return [pscustomobject]@{ TenantDisplayName = $TenantDisplayName; LogoDataUri = $LogoDataUri }
        }

        $OrgId = $OrgResponse.value[0].id
        $TenantDisplayName = Normalize-Value $OrgResponse.value[0].displayName
        Write-Host "Tenant: $TenantDisplayName" -ForegroundColor Green

        try {
            $Branding = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$OrgId/branding"

            $LogoRelativeProperties = @(
                "headerLogoRelativeUrl",
                "bannerLogoRelativeUrl",
                "squareLogoRelativeUrl",
                "squareLogoDarkRelativeUrl"
            )

            $CdnList = @()
            if ($Branding.cdnList) { $CdnList = @($Branding.cdnList) }

            foreach ($RelativeProperty in $LogoRelativeProperties) {
                $RelativeUrl = Normalize-Value $Branding.$RelativeProperty

                if (-not [string]::IsNullOrWhiteSpace($RelativeUrl)) {
                    foreach ($Cdn in $CdnList) {
                        $CdnBase = Normalize-Value $Cdn
                        if ([string]::IsNullOrWhiteSpace($CdnBase)) { continue }

                        if ($RelativeUrl.StartsWith("http", [System.StringComparison]::OrdinalIgnoreCase)) {
                            $ImageUrl = $RelativeUrl
                        }
                        else {
                            $ImageUrl = $CdnBase.TrimEnd("/") + "/" + $RelativeUrl.TrimStart("/")
                        }

                        $TempFile = Join-Path $OutputFolder ("TenantLogo-cdn-{0}-{1}.bin" -f $RelativeProperty, $Timestamp)

                        try {
                            if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
                            Invoke-WebRequest -Uri $ImageUrl -OutFile $TempFile -UseBasicParsing -ErrorAction Stop
                            $LogoDataUri = Convert-ImageFileToDataUri -Path $TempFile

                            if (-not [string]::IsNullOrWhiteSpace($LogoDataUri)) {
                                Write-Host "Tenant logo found from CDN: $RelativeProperty" -ForegroundColor Green
                                return [pscustomobject]@{ TenantDisplayName = $TenantDisplayName; LogoDataUri = $LogoDataUri }
                            }
                        }
                        catch {
                            Write-Host "CDN logo failed for $RelativeProperty" -ForegroundColor DarkGray
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "Default branding CDN lookup failed." -ForegroundColor DarkGray
        }

        $StreamAttempts = @()
        foreach ($LogoProperty in @("headerLogo", "bannerLogo", "squareLogo", "squareLogoDark")) {
            $StreamAttempts += [pscustomobject]@{
                Name = "base-$LogoProperty"
                Uri  = "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/$LogoProperty/`$value"
            }
        }

        try {
            $LocalizationResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/localizations?`$select=id"

            if ($LocalizationResponse.value) {
                foreach ($Loc in $LocalizationResponse.value) {
                    $LocId = Normalize-Value $Loc.id
                    $EscapedLocId = [System.Uri]::EscapeDataString($LocId)

                    foreach ($LogoProperty in @("headerLogo", "bannerLogo", "squareLogo", "squareLogoDark")) {
                        $StreamAttempts += [pscustomobject]@{
                            Name = "localization-$LocId-$LogoProperty"
                            Uri  = "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/localizations/$EscapedLocId/$LogoProperty/`$value"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "Could not list localizations for stream fallback." -ForegroundColor DarkGray
        }

        foreach ($Attempt in $StreamAttempts) {
            $TempFile = Join-Path $OutputFolder ("TenantLogo-stream-{0}-{1}.bin" -f $Attempt.Name, $Timestamp)

            try {
                if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
                Invoke-MgGraphRequest -Method GET -Uri $Attempt.Uri -OutputFilePath $TempFile -ErrorAction Stop
                $LogoDataUri = Convert-ImageFileToDataUri -Path $TempFile

                if (-not [string]::IsNullOrWhiteSpace($LogoDataUri)) {
                    Write-Host "Tenant logo found from stream: $($Attempt.Name)" -ForegroundColor Green
                    return [pscustomobject]@{ TenantDisplayName = $TenantDisplayName; LogoDataUri = $LogoDataUri }
                }
            }
            catch {
                Write-Host "Stream logo source unavailable: $($Attempt.Name)" -ForegroundColor DarkGray
            }
        }

        Write-Warning "No Entra Company Branding logo was found. Dashboard will use tenant display name."
    }
    catch {
        Write-Warning "Could not retrieve tenant branding."
        Write-Warning $_.Exception.Message
    }

    return [pscustomobject]@{ TenantDisplayName = $TenantDisplayName; LogoDataUri = $LogoDataUri }
}

function Invoke-PrimaryUserBatch {
    param(
        [Parameter(Mandatory)]
        [array]$Requests,

        [Parameter(Mandatory)]
        [hashtable]$RequestMap
    )

    $ByDeviceId = @{}
    $ByDeviceName = @{}
    $Processed = 0
    $Failed = 0

    try {
        $BodyJson = @{ requests = $Requests } | ConvertTo-Json -Depth 20
        $Response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/`$batch" -Body $BodyJson -ContentType "application/json" -ErrorAction Stop

        foreach ($BatchResponse in @($Response.responses)) {
            $Processed++
            $RequestInfo = $RequestMap[(Normalize-Value $BatchResponse.id)]
            $DeviceId = Normalize-Value $RequestInfo.DeviceId
            $DeviceName = Normalize-Value $RequestInfo.DeviceName
            $PrimaryUser = "None"
            $PrimaryUserDisplayName = ""
            $PrimaryUserUPN = ""
            $PrimaryUserEmail = ""
            $PrimaryUserId = ""
            $LookupStatus = "OK"

            if ([int]$BatchResponse.status -ge 200 -and [int]$BatchResponse.status -lt 300) {
                $Users = @($BatchResponse.body.value)

                if ($Users.Count -gt 0) {
                    $User = $Users[0]
                    $PrimaryUserDisplayName = Normalize-Value $User.displayName
                    $PrimaryUserUPN = Normalize-Value $User.userPrincipalName
                    $PrimaryUserEmail = Normalize-Value $User.mail
                    $PrimaryUserId = Normalize-Value $User.id

                    if (-not [string]::IsNullOrWhiteSpace($PrimaryUserDisplayName) -and -not [string]::IsNullOrWhiteSpace($PrimaryUserUPN)) {
                        $PrimaryUser = "$PrimaryUserDisplayName <$PrimaryUserUPN>"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($PrimaryUserUPN)) {
                        $PrimaryUser = $PrimaryUserUPN
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($PrimaryUserDisplayName)) {
                        $PrimaryUser = $PrimaryUserDisplayName
                    }
                }
            }
            else {
                $Failed++
                $PrimaryUser = "Unknown"
                $LookupStatus = "HTTP $($BatchResponse.status)"
            }

            $Record = [pscustomobject]@{
                DeviceId                = $DeviceId
                DeviceName              = $DeviceName
                PrimaryUser             = $PrimaryUser
                PrimaryUserDisplayName  = $PrimaryUserDisplayName
                PrimaryUserUPN          = $PrimaryUserUPN
                PrimaryUserEmail        = $PrimaryUserEmail
                PrimaryUserId           = $PrimaryUserId
                PrimaryUserLookupStatus = $LookupStatus
            }

            if (-not [string]::IsNullOrWhiteSpace($DeviceId)) { $ByDeviceId[$DeviceId.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $ByDeviceName[$DeviceName.ToLowerInvariant()] = $Record }
        }
    }
    catch {
        $Failed += $Requests.Count
        Write-Warning "Primary user batch lookup failed."
        Write-Warning $_.Exception.Message
    }

    return [pscustomobject]@{ ByDeviceId = $ByDeviceId; ByDeviceName = $ByDeviceName; Processed = $Processed; Failed = $Failed }
}

function Get-PrimaryUsersByManagedDevice {
    param(
        [Parameter(Mandatory)]
        [array]$ManagedDevices,

        [string]$RawExportPath
    )

    $ByDeviceId = @{}
    $ByDeviceName = @{}
    $Requests = @()
    $RequestMap = @{}
    $BatchSize = 20
    $RequestNumber = 0
    $Processed = 0
    $Failed = 0

    foreach ($Device in $ManagedDevices) {
        $DeviceId = Normalize-Value $Device.id
        $DeviceName = Normalize-Value $Device.deviceName

        if ([string]::IsNullOrWhiteSpace($DeviceId)) { continue }

        $RequestNumber++
        $RequestId = [string]$RequestNumber

        $Requests += @{
            id     = $RequestId
            method = "GET"
            url    = "/deviceManagement/managedDevices/$DeviceId/users?`$select=id,displayName,userPrincipalName,mail"
        }

        $RequestMap[$RequestId] = [pscustomobject]@{ DeviceId = $DeviceId; DeviceName = $DeviceName }

        if ($Requests.Count -eq $BatchSize) {
            $Result = Invoke-PrimaryUserBatch -Requests $Requests -RequestMap $RequestMap
            $Processed += $Result.Processed
            $Failed += $Result.Failed
            foreach ($Key in $Result.ByDeviceId.Keys) { $ByDeviceId[$Key] = $Result.ByDeviceId[$Key] }
            foreach ($Key in $Result.ByDeviceName.Keys) { $ByDeviceName[$Key] = $Result.ByDeviceName[$Key] }
            $Requests = @()
            $RequestMap = @{}
        }
    }

    if ($Requests.Count -gt 0) {
        $Result = Invoke-PrimaryUserBatch -Requests $Requests -RequestMap $RequestMap
        $Processed += $Result.Processed
        $Failed += $Result.Failed
        foreach ($Key in $Result.ByDeviceId.Keys) { $ByDeviceId[$Key] = $Result.ByDeviceId[$Key] }
        foreach ($Key in $Result.ByDeviceName.Keys) { $ByDeviceName[$Key] = $Result.ByDeviceName[$Key] }
    }

    if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
        try {
            $ExportRows = foreach ($Key in $ByDeviceId.Keys) { $ByDeviceId[$Key] }
            $ExportRows | ConvertTo-Json -Depth 10 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Primary user raw mapping exported: $RawExportPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export primary user raw mapping."
            Write-Warning $_.Exception.Message
        }
    }

    return [pscustomobject]@{ ByDeviceId = $ByDeviceId; ByDeviceName = $ByDeviceName; Processed = $Processed; Failed = $Failed }
}

function Invoke-PrimaryUserAccountBatch {
    param(
        [Parameter(Mandatory)]
        [array]$Requests,

        [Parameter(Mandatory)]
        [hashtable]$RequestMap
    )

    $ByUserId = @{}
    $ByUPN = @{}
    $Processed = 0
    $Failed = 0

    try {
        $BodyJson = @{ requests = $Requests } | ConvertTo-Json -Depth 20
        $Response = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/`$batch" `
            -Body $BodyJson `
            -ContentType "application/json" `
            -ErrorAction Stop

        $BatchResponses = @()

        if ($Response -is [System.Collections.IDictionary] -and $Response.ContainsKey("responses")) {
            $BatchResponses = @($Response["responses"])
        }
        elseif ($Response.PSObject.Properties.Name -contains "responses") {
            $BatchResponses = @($Response.responses)
        }

        foreach ($BatchResponse in $BatchResponses) {
            $Processed++
            $ResponseId = Get-PropertyValue -Object $BatchResponse -PropertyNames @("id")
            $RequestInfo = $RequestMap[$ResponseId]

            $UserId = Normalize-Value $RequestInfo.UserId
            $UPN = Normalize-Value $RequestInfo.UserPrincipalName
            $DisplayName = Normalize-Value $RequestInfo.DisplayName
            $AccountEnabled = ""
            $AccountStatus = "Unknown"
            $LookupStatus = "OK"

            $StatusText = Get-PropertyValue -Object $BatchResponse -PropertyNames @("status")
            $StatusCode = 0
            [void][int]::TryParse($StatusText, [ref]$StatusCode)

            if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
                $Body = $null

                if ($BatchResponse -is [System.Collections.IDictionary] -and $BatchResponse.ContainsKey("body")) {
                    $Body = $BatchResponse["body"]
                }
                elseif ($BatchResponse.PSObject.Properties.Name -contains "body") {
                    $Body = $BatchResponse.body
                }

                $AccountEnabled = Get-PropertyValue -Object $Body -PropertyNames @("accountEnabled")
                $UserIdFromGraph = Get-PropertyValue -Object $Body -PropertyNames @("id")
                $UPNFromGraph = Get-PropertyValue -Object $Body -PropertyNames @("userPrincipalName")
                $DisplayNameFromGraph = Get-PropertyValue -Object $Body -PropertyNames @("displayName")

                if ($AccountEnabled -eq "True" -or $AccountEnabled -eq "true") {
                    $AccountStatus = "Enabled"
                }
                elseif ($AccountEnabled -eq "False" -or $AccountEnabled -eq "false") {
                    $AccountStatus = "Disabled"
                }
                else {
                    $LookupStatus = "OK but accountEnabled missing"
                }

                if (-not [string]::IsNullOrWhiteSpace($UserIdFromGraph)) { $UserId = $UserIdFromGraph }
                if (-not [string]::IsNullOrWhiteSpace($UPNFromGraph)) { $UPN = $UPNFromGraph }
                if (-not [string]::IsNullOrWhiteSpace($DisplayNameFromGraph)) { $DisplayName = $DisplayNameFromGraph }
            }
            else {
                $Failed++
                $LookupStatus = "HTTP $StatusCode"

                $Body = $null
                if ($BatchResponse -is [System.Collections.IDictionary] -and $BatchResponse.ContainsKey("body")) { $Body = $BatchResponse["body"] }
                elseif ($BatchResponse.PSObject.Properties.Name -contains "body") { $Body = $BatchResponse.body }

                $ErrorMessage = Get-PropertyValue -Object $Body -PropertyNames @("message")
                if ([string]::IsNullOrWhiteSpace($ErrorMessage)) {
                    $ErrorObj = $null
                    if ($Body -is [System.Collections.IDictionary] -and $Body.ContainsKey("error")) { $ErrorObj = $Body["error"] }
                    elseif ($Body -and $Body.PSObject.Properties.Name -contains "error") { $ErrorObj = $Body.error }
                    $ErrorMessage = Get-PropertyValue -Object $ErrorObj -PropertyNames @("message")
                }
                if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) { $LookupStatus = "$LookupStatus - $ErrorMessage" }
            }

            $Record = [pscustomobject]@{
                UserId              = $UserId
                UserPrincipalName   = $UPN
                DisplayName         = $DisplayName
                AccountEnabled      = $AccountEnabled
                AccountStatus       = $AccountStatus
                AccountLookupStatus = $LookupStatus
            }

            if (-not [string]::IsNullOrWhiteSpace($UserId)) { $ByUserId[$UserId.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($UPN)) { $ByUPN[$UPN.ToLowerInvariant()] = $Record }
        }
    }
    catch {
        $Failed += $Requests.Count
        Write-Warning "Primary user account status batch lookup failed."
        Write-Warning $_.Exception.Message
    }

    return [pscustomobject]@{ ByUserId = $ByUserId; ByUPN = $ByUPN; Processed = $Processed; Failed = $Failed }
}

function Get-PrimaryUserAccountStatuses {
    param(
        [Parameter(Mandatory)]
        [hashtable]$PrimaryUserByDeviceId,

        [string]$RawExportPath
    )

    $ByUserId = @{}
    $ByUPN = @{}
    $Requests = @()
    $RequestMap = @{}
    $BatchSize = 20
    $RequestNumber = 0
    $Processed = 0
    $Failed = 0
    $SeenUsers = @{}

    foreach ($Key in $PrimaryUserByDeviceId.Keys) {
        $Record = $PrimaryUserByDeviceId[$Key]
        $UserId = Normalize-Value $Record.PrimaryUserId
        $UPN = Normalize-Value $Record.PrimaryUserUPN
        $DisplayName = Normalize-Value $Record.PrimaryUserDisplayName

        if ([string]::IsNullOrWhiteSpace($UPN) -and [string]::IsNullOrWhiteSpace($UserId)) { continue }

        # Prefer UPN first, because some tenants return an Intune relationship id that does not resolve cleanly against /users/{id}.
        $Identifier = if (-not [string]::IsNullOrWhiteSpace($UPN)) { $UPN } else { $UserId }
        $SeenKey = $Identifier.ToLowerInvariant()
        if ($SeenUsers.ContainsKey($SeenKey)) { continue }
        $SeenUsers[$SeenKey] = $true

        $RequestNumber++
        $RequestId = [string]$RequestNumber
        $EncodedIdentifier = [System.Uri]::EscapeDataString($Identifier)

        $Requests += @{
            id     = $RequestId
            method = "GET"
            url    = "/users/$EncodedIdentifier?`$select=id,displayName,userPrincipalName,accountEnabled"
        }

        $RequestMap[$RequestId] = [pscustomobject]@{
            UserId            = $UserId
            UserPrincipalName = $UPN
            DisplayName       = $DisplayName
        }

        if ($Requests.Count -eq $BatchSize) {
            $Result = Invoke-PrimaryUserAccountBatch -Requests $Requests -RequestMap $RequestMap
            $Processed += $Result.Processed
            $Failed += $Result.Failed
            foreach ($ResultKey in $Result.ByUserId.Keys) { $ByUserId[$ResultKey] = $Result.ByUserId[$ResultKey] }
            foreach ($ResultKey in $Result.ByUPN.Keys) { $ByUPN[$ResultKey] = $Result.ByUPN[$ResultKey] }
            $Requests = @()
            $RequestMap = @{}
        }
    }

    if ($Requests.Count -gt 0) {
        $Result = Invoke-PrimaryUserAccountBatch -Requests $Requests -RequestMap $RequestMap
        $Processed += $Result.Processed
        $Failed += $Result.Failed
        foreach ($ResultKey in $Result.ByUserId.Keys) { $ByUserId[$ResultKey] = $Result.ByUserId[$ResultKey] }
        foreach ($ResultKey in $Result.ByUPN.Keys) { $ByUPN[$ResultKey] = $Result.ByUPN[$ResultKey] }
    }

    if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
        try {
            $ExportRows = foreach ($Key in $ByUPN.Keys) { $ByUPN[$Key] }
            $ExportRows | ConvertTo-Json -Depth 10 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Primary user account status raw mapping exported: $RawExportPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export primary user account status raw mapping."
            Write-Warning $_.Exception.Message
        }
    }

    return [pscustomobject]@{ ByUserId = $ByUserId; ByUPN = $ByUPN; Processed = $Processed; Failed = $Failed }
}

# ============================================================
# Tenant branding
# ============================================================

$Branding = Get-TenantBrandingLogo -OutputFolder $OutputFolder -Timestamp $Timestamp
$TenantDisplayName = $Branding.TenantDisplayName
$TenantLogoDataUri = $Branding.LogoDataUri
$SafeTenantName = ConvertTo-HtmlSafe $TenantDisplayName

if ([string]::IsNullOrWhiteSpace($TenantLogoDataUri)) {
    $LogoHtml = "<div class='logo-fallback'>$SafeTenantName</div>"
}
else {
    $LogoHtml = "<img class='tenant-logo' src='$TenantLogoDataUri' alt='$SafeTenantName logo'>"
}

function Get-HardwareRecordFromManagedDevice {
    param(
        [Parameter(Mandatory)]
        $ManagedDevice
    )

    $Hardware = $null

    if ($ManagedDevice -is [System.Collections.IDictionary] -and $ManagedDevice.ContainsKey("hardwareInformation")) {
        $Hardware = $ManagedDevice["hardwareInformation"]
    }
    elseif ($ManagedDevice.PSObject.Properties.Name -contains "hardwareInformation") {
        $Hardware = $ManagedDevice.hardwareInformation
    }

    $FirmwareVersion = Get-PropertyValue -Object $Hardware -PropertyNames @(
        "systemManagementBIOSVersion",
        "biosVersion",
        "firmwareVersion",
        "uefiVersion",
        "smbiosVersion"
    )

    $FirmwareManufacturer = Get-PropertyValue -Object $Hardware -PropertyNames @(
        "systemManagementBIOSManufacturer",
        "biosManufacturer",
        "firmwareManufacturer",
        "manufacturer"
    )

    if ([string]::IsNullOrWhiteSpace($FirmwareManufacturer)) {
        $FirmwareManufacturer = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("manufacturer")
    }

    $FirmwareReleaseDate = Get-PropertyValue -Object $Hardware -PropertyNames @(
        "systemManagementBIOSReleaseDate",
        "biosReleaseDate",
        "firmwareReleaseDate"
    )

    return [pscustomobject]@{
        DeviceId                = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("id")
        DeviceName              = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("deviceName")
        AzureADDeviceId         = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("azureADDeviceId")
        FirmwareManufacturer    = Normalize-Value $FirmwareManufacturer
        FirmwareVersion         = Normalize-Value $FirmwareVersion
        FirmwareReleaseDate     = Normalize-Value $FirmwareReleaseDate
        DeviceSKU               = Get-PropertyValue -Object $Hardware -PropertyNames @("deviceSku", "deviceSKU", "skuNumber", "productName")
        SystemBoardModel        = Get-PropertyValue -Object $Hardware -PropertyNames @("systemBoardModel", "baseBoardProduct", "boardProduct", "model")
        SystemBoardManufacturer = Get-PropertyValue -Object $Hardware -PropertyNames @("systemBoardManufacturer", "baseBoardManufacturer", "boardManufacturer")
        SystemBoardVersion      = Get-PropertyValue -Object $Hardware -PropertyNames @("systemBoardVersion", "baseBoardVersion", "boardVersion")
        ModelFamily             = Get-PropertyValue -Object $Hardware -PropertyNames @("modelFamily", "chassisType")
        TPMVersion              = Get-PropertyValue -Object $Hardware -PropertyNames @("tpmSpecificationVersion", "tpmVersion")
        HardwareSource          = "managedDevice hardwareInformation"
    }
}

function Get-ManagedDeviceHardwareInformation {
    param(
        [string]$RawExportPath
    )

    $ByDeviceId = @{}
    $ByDeviceName = @{}
    $ByAzureADDeviceId = @{}
    $AllRecords = @()

    Write-Host ""
    Write-Host "Retrieving firmware / hardware information from managedDevices hardwareInformation..." -ForegroundColor Cyan

    $HardwareUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem%20eq%20'Windows'&`$select=id,deviceName,azureADDeviceId,manufacturer,model,hardwareInformation&`$top=100"
    $HardwareDevices = @(Invoke-GraphGetAll -Uri $HardwareUri -AllowFailure)

    if ($HardwareDevices.Count -eq 0) {
        Write-Warning "No hardwareInformation records returned from managedDevices. Firmware version may remain blank if it is not included in the Secure Boot report."
    }

    foreach ($HardwareDevice in $HardwareDevices) {
        $Record = Get-HardwareRecordFromManagedDevice -ManagedDevice $HardwareDevice
        $AllRecords += $Record

        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceId)) { $ByDeviceId[$Record.DeviceId.ToLowerInvariant()] = $Record }
        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceName)) { $ByDeviceName[$Record.DeviceName.ToLowerInvariant()] = $Record }
        if (-not [string]::IsNullOrWhiteSpace($Record.AzureADDeviceId)) { $ByAzureADDeviceId[$Record.AzureADDeviceId.ToLowerInvariant()] = $Record }
    }

    if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
        try {
            $AllRecords | ConvertTo-Json -Depth 10 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Hardware information raw mapping exported: $RawExportPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export hardware information raw mapping."
            Write-Warning $_.Exception.Message
        }
    }

    $WithFirmwareVersion = @($AllRecords | Where-Object { -not [string]::IsNullOrWhiteSpace($_.FirmwareVersion) }).Count
    Write-Host "Hardware records found: $($AllRecords.Count)" -ForegroundColor Green
    Write-Host "Hardware records with firmware version: $WithFirmwareVersion" -ForegroundColor Green

    return [pscustomobject]@{
        ByDeviceId        = $ByDeviceId
        ByDeviceName      = $ByDeviceName
        ByAzureADDeviceId = $ByAzureADDeviceId
        Count             = $AllRecords.Count
    }
}

# ============================================================
# Retrieve Intune Windows managed devices
# ============================================================

Write-Host ""
Write-Host "Retrieving Windows managed devices from Intune..." -ForegroundColor Cyan

$ManagedDeviceSelect = @(
    "id",
    "deviceName",
    "userPrincipalName",
    "userDisplayName",
    "emailAddress",
    "operatingSystem",
    "osVersion",
    "complianceState",
    "managementAgent",
    "managedDeviceOwnerType",
    "manufacturer",
    "model",
    "serialNumber",
    "azureADDeviceId",
    "lastSyncDateTime",
    "enrolledDateTime",
    "deviceRegistrationState",
    "totalStorageSpaceInBytes",
    "freeStorageSpaceInBytes"
) -join ","

$ManagedDevicesUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem%20eq%20'Windows'&`$select=$ManagedDeviceSelect&`$top=100"
$ManagedDevices = Invoke-GraphGetAll -Uri $ManagedDevicesUri
Write-Host "Windows managed devices found: $($ManagedDevices.Count)" -ForegroundColor Green

# ============================================================
# Retrieve firmware / hardware information from managedDevices
# ============================================================

$HardwareResults = Get-ManagedDeviceHardwareInformation -RawExportPath $HardwareRawPath
$HardwareByDeviceId = $HardwareResults.ByDeviceId
$HardwareByDeviceName = $HardwareResults.ByDeviceName
$HardwareByAzureADDeviceId = $HardwareResults.ByAzureADDeviceId


# ============================================================
# Retrieve primary users and account status
# ============================================================

Write-Host ""
Write-Host "Retrieving primary users from Intune managedDevice users relationship..." -ForegroundColor Cyan

$PrimaryUserResults = Get-PrimaryUsersByManagedDevice -ManagedDevices $ManagedDevices -RawExportPath $PrimaryUserRawPath
$PrimaryUserByDeviceId = $PrimaryUserResults.ByDeviceId
$PrimaryUserByDeviceName = $PrimaryUserResults.ByDeviceName

Write-Host "Primary user lookups processed: $($PrimaryUserResults.Processed)" -ForegroundColor Green
Write-Host "Primary user lookup failures: $($PrimaryUserResults.Failed)" -ForegroundColor Yellow

Write-Host ""
Write-Host "Retrieving primary user account enabled/disabled status from Entra ID..." -ForegroundColor Cyan

$PrimaryUserAccountResults = Get-PrimaryUserAccountStatuses -PrimaryUserByDeviceId $PrimaryUserByDeviceId -RawExportPath $PrimaryUserAccountRawPath
$PrimaryUserAccountByUserId = $PrimaryUserAccountResults.ByUserId
$PrimaryUserAccountByUPN = $PrimaryUserAccountResults.ByUPN

Write-Host "Primary user account lookups processed: $($PrimaryUserAccountResults.Processed)" -ForegroundColor Green
Write-Host "Primary user account lookup failures: $($PrimaryUserAccountResults.Failed)" -ForegroundColor Yellow


# ============================================================
# Retrieve Secure Boot status and firmware from Intune report
# ============================================================

Write-Host ""
Write-Host "Retrieving Secure Boot status and firmware from Intune Windows health attestation report..." -ForegroundColor Cyan

$SecureBootByDeviceName = @{}
$SecureBootByManagedDeviceId = @{}
$SecureBootByAzureADDeviceId = @{}
$SecureBootReportRows = @()

$SecureBootReportSelect = @(
    "AIKKey",
    "AttestationError",
    "BitlockerStatus",
    "BootDebuggingStatus",
    "CodeIntegrityStatus",
    "DEPPolicy",
    "DeviceId",
    "DeviceName",
    "DeviceOS",
    "DeviceSKU",
    "ELAMDriverLoadedStatus",
    "FirmwareManufacturer",
    "FirmwareReleaseDate",
    "FirmwareVersion",
    "HealthCertIssuedDate",
    "MemoryAccessProtectionStatus",
    "MemoryIntegrityProtectionStatus",
    "ModelFamily",
    "OSKernelDebuggingStatus",
    "PrimaryUser",
    "SafeModeStatus",
    "SecuredCorePCStatus",
    "SecureBootStatus",
    "SystemBoardManufacturer",
    "SystemBoardModel",
    "SystemBoardVersion",
    "SystemManagementMode",
    "TpmVersion",
    "UPN",
    "VSMStatus",
    "WinPEStatus"
)

$SecureBootReportResult = Invoke-IntuneReportExport `
    -ReportName "WindowsDeviceHealthAttestationReport" `
    -Select $SecureBootReportSelect `
    -OutputFolder $OutputFolder `
    -Timestamp $Timestamp `
    -TimeoutSeconds $ReportExportTimeoutSeconds `
    -AllowFailure

if (-not $SecureBootReportResult.Succeeded) {
    Write-Warning "Retrying WindowsDeviceHealthAttestationReport export without explicit column selection."

    $SecureBootReportResult = Invoke-IntuneReportExport `
        -ReportName "WindowsDeviceHealthAttestationReport" `
        -OutputFolder $OutputFolder `
        -Timestamp $Timestamp `
        -TimeoutSeconds $ReportExportTimeoutSeconds `
        -AllowFailure
}

if ($SecureBootReportResult.Succeeded -and $SecureBootReportResult.Rows.Count -gt 0) {
    $SecureBootReportRows = @($SecureBootReportResult.Rows)
    Write-Host "Secure Boot / firmware report rows found: $($SecureBootReportRows.Count)" -ForegroundColor Green

    foreach ($ReportRow in $SecureBootReportRows) {
        $Record = Get-SecureBootRecordFromReportRow -ReportRow $ReportRow -ReportName $SecureBootReportResult.ReportName

        $ReportDeviceId = Normalize-Value $Record.DeviceId
        $ReportDeviceName = Normalize-Value $Record.DeviceName
        $ReportAzureADDeviceId = Normalize-Value $Record.AzureADDeviceId

        if (-not [string]::IsNullOrWhiteSpace($ReportDeviceId)) {
            $SecureBootByManagedDeviceId[$ReportDeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($ReportAzureADDeviceId)) {
            $SecureBootByAzureADDeviceId[$ReportAzureADDeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($ReportDeviceName)) {
            $SecureBootByDeviceName[$ReportDeviceName.ToLowerInvariant()] = $Record
        }
    }
}
else {
    Write-Warning "No Secure Boot / firmware report rows were retrieved. Secure Boot and firmware columns will show Unknown."
}

try {
    $SecureBootExportRows = foreach ($Key in $SecureBootByDeviceName.Keys) {
        $SecureBootByDeviceName[$Key]
    }

    $SecureBootExportRows | ConvertTo-Json -Depth 10 | Out-File -FilePath $SecureBootRawPath -Encoding UTF8
    Write-Host "Secure Boot / firmware raw mapping exported: $SecureBootRawPath" -ForegroundColor Green
}
catch {
    Write-Warning "Could not export Secure Boot / firmware raw mapping."
    Write-Warning $_.Exception.Message
}

# ============================================================
# Build dataset
# ============================================================

Write-Host ""
Write-Host "Building dashboard dataset..." -ForegroundColor Cyan

$Rows = foreach ($Device in $ManagedDevices) {
    $DeviceName  = Normalize-Value $Device.deviceName
    $DeviceKey   = $DeviceName.ToLowerInvariant()
    $DeviceId    = Normalize-Value $Device.id
    $DeviceIdKey = $DeviceId.ToLowerInvariant()
    $AzureADDeviceId = Normalize-Value $Device.azureADDeviceId
    $AzureADDeviceIdKey = $AzureADDeviceId.ToLowerInvariant()

    $OSInfo = Get-OSBuildInfo -OSVersion $Device.osVersion

    $HardwareRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $HardwareByDeviceId.ContainsKey($DeviceIdKey)) {
        $HardwareRecord = $HardwareByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($AzureADDeviceIdKey) -and $HardwareByAzureADDeviceId.ContainsKey($AzureADDeviceIdKey)) {
        $HardwareRecord = $HardwareByAzureADDeviceId[$AzureADDeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $HardwareByDeviceName.ContainsKey($DeviceKey)) {
        $HardwareRecord = $HardwareByDeviceName[$DeviceKey]
    }

    $PrimaryUserRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $PrimaryUserByDeviceId.ContainsKey($DeviceIdKey)) {
        $PrimaryUserRecord = $PrimaryUserByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $PrimaryUserByDeviceName.ContainsKey($DeviceKey)) {
        $PrimaryUserRecord = $PrimaryUserByDeviceName[$DeviceKey]
    }

    $SecureBootRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $SecureBootByManagedDeviceId.ContainsKey($DeviceIdKey)) {
        $SecureBootRecord = $SecureBootByManagedDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($AzureADDeviceIdKey) -and $SecureBootByAzureADDeviceId.ContainsKey($AzureADDeviceIdKey)) {
        $SecureBootRecord = $SecureBootByAzureADDeviceId[$AzureADDeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $SecureBootByDeviceName.ContainsKey($DeviceKey)) {
        $SecureBootRecord = $SecureBootByDeviceName[$DeviceKey]
    }

    $TotalGB = Convert-BytesToGB $Device.totalStorageSpaceInBytes
    $FreeGB  = Convert-BytesToGB $Device.freeStorageSpaceInBytes
    $FreePct = Get-Percent -Part $FreeGB -Total $TotalGB

    $PrimaryUser = "Unknown"
    $PrimaryUserDisplayName = ""
    $PrimaryUserUPN = ""
    $PrimaryUserEmail = ""
    $PrimaryUserId = ""
    $PrimaryUserLookupStatus = ""
    $PrimaryUserAccountEnabled = ""
    $PrimaryUserAccountStatus = "Unknown"
    $PrimaryUserAccountLookupStatus = ""

    $SecureBootStatus = "Unknown"
    $SecureBootRaw = ""
    $SecureBootReportSource = ""
    $SecureBootLastUpdateDateTime = ""
    $SecureBootCertificateStatus = ""
    $SecureBootAttestationError = ""
    $SecureBootDeviceOS = ""
    $SecureBootTPMVersion = ""
    $SecureBootCodeIntegrityStatus = ""
    $SecureBootVSMStatus = ""
    $FirmwareManufacturer = ""
    $FirmwareVersion = ""
    $FirmwareReleaseDate = ""
    $DeviceSKU = ""
    $SystemBoardManufacturer = ""
    $SystemBoardModel = ""
    $SystemBoardVersion = ""
    $ModelFamily = ""

    if ($SecureBootRecord) {
        $SecureBootStatus = Use-ValueOrUnknown $SecureBootRecord.SecureBootStatus
        $SecureBootRaw = Normalize-Value $SecureBootRecord.SecureBootRaw
        $SecureBootReportSource = Normalize-Value $SecureBootRecord.SecureBootReportSource
        $SecureBootLastUpdateDateTime = Normalize-Value $SecureBootRecord.SecureBootLastUpdateDateTime
        $SecureBootCertificateStatus = Normalize-Value $SecureBootRecord.SecureBootCertificateStatus
        $SecureBootAttestationError = Normalize-Value $SecureBootRecord.SecureBootAttestationError
        $SecureBootDeviceOS = Normalize-Value $SecureBootRecord.SecureBootDeviceOS
        $SecureBootTPMVersion = Normalize-Value $SecureBootRecord.SecureBootTPMVersion
        $SecureBootCodeIntegrityStatus = Normalize-Value $SecureBootRecord.SecureBootCodeIntegrityStatus
        $SecureBootVSMStatus = Normalize-Value $SecureBootRecord.SecureBootVSMStatus
        $FirmwareManufacturer = Normalize-Value $SecureBootRecord.FirmwareManufacturer
        $FirmwareVersion = Normalize-Value $SecureBootRecord.FirmwareVersion
        $FirmwareReleaseDate = Normalize-Value $SecureBootRecord.FirmwareReleaseDate
        $DeviceSKU = Normalize-Value $SecureBootRecord.DeviceSKU
        $SystemBoardManufacturer = Normalize-Value $SecureBootRecord.SystemBoardManufacturer
        $SystemBoardModel = Normalize-Value $SecureBootRecord.SystemBoardModel
        $SystemBoardVersion = Normalize-Value $SecureBootRecord.SystemBoardVersion
        $ModelFamily = Normalize-Value $SecureBootRecord.ModelFamily
    }

    if ($HardwareRecord) {
        if ([string]::IsNullOrWhiteSpace($FirmwareManufacturer)) { $FirmwareManufacturer = Normalize-Value $HardwareRecord.FirmwareManufacturer }
        if ([string]::IsNullOrWhiteSpace($FirmwareVersion)) { $FirmwareVersion = Normalize-Value $HardwareRecord.FirmwareVersion }
        if ([string]::IsNullOrWhiteSpace($FirmwareReleaseDate)) { $FirmwareReleaseDate = Normalize-Value $HardwareRecord.FirmwareReleaseDate }
        if ([string]::IsNullOrWhiteSpace($DeviceSKU)) { $DeviceSKU = Normalize-Value $HardwareRecord.DeviceSKU }
        if ([string]::IsNullOrWhiteSpace($SystemBoardModel)) { $SystemBoardModel = Normalize-Value $HardwareRecord.SystemBoardModel }
    }

    if ($PrimaryUserRecord) {
        $PrimaryUser = Normalize-Value $PrimaryUserRecord.PrimaryUser
        $PrimaryUserDisplayName = Normalize-Value $PrimaryUserRecord.PrimaryUserDisplayName
        $PrimaryUserUPN = Normalize-Value $PrimaryUserRecord.PrimaryUserUPN
        $PrimaryUserEmail = Normalize-Value $PrimaryUserRecord.PrimaryUserEmail
        $PrimaryUserId = Normalize-Value $PrimaryUserRecord.PrimaryUserId
        $PrimaryUserLookupStatus = Normalize-Value $PrimaryUserRecord.PrimaryUserLookupStatus

        if ([string]::IsNullOrWhiteSpace($PrimaryUser)) { $PrimaryUser = "None" }

        if ($PrimaryUser -eq "None") {
            $PrimaryUserAccountStatus = "No primary user"
            $PrimaryUserAccountLookupStatus = "No primary user"
        }
        else {
            $PrimaryUserAccountRecord = $null

            # UPN first. This avoids Unknown in tenants where the relationship user id does not resolve cleanly.
            if (-not [string]::IsNullOrWhiteSpace($PrimaryUserUPN) -and $PrimaryUserAccountByUPN.ContainsKey($PrimaryUserUPN.ToLowerInvariant())) {
                $PrimaryUserAccountRecord = $PrimaryUserAccountByUPN[$PrimaryUserUPN.ToLowerInvariant()]
            }
            elseif (-not [string]::IsNullOrWhiteSpace($PrimaryUserId) -and $PrimaryUserAccountByUserId.ContainsKey($PrimaryUserId.ToLowerInvariant())) {
                $PrimaryUserAccountRecord = $PrimaryUserAccountByUserId[$PrimaryUserId.ToLowerInvariant()]
            }

            if ($PrimaryUserAccountRecord) {
                $PrimaryUserAccountEnabled = Normalize-Value $PrimaryUserAccountRecord.AccountEnabled
                $PrimaryUserAccountStatus = Normalize-Value $PrimaryUserAccountRecord.AccountStatus
                $PrimaryUserAccountLookupStatus = Normalize-Value $PrimaryUserAccountRecord.AccountLookupStatus
            }
        }
    }

    [pscustomobject]@{
        DeviceName                      = $DeviceName
        UserPrincipalName               = Normalize-Value $Device.userPrincipalName
        UserDisplayName                 = Normalize-Value $Device.userDisplayName
        EmailAddress                    = Normalize-Value $Device.emailAddress
        PrimaryUser                     = $PrimaryUser
        PrimaryUserDisplayName          = $PrimaryUserDisplayName
        PrimaryUserUPN                  = $PrimaryUserUPN
        PrimaryUserEmail                = $PrimaryUserEmail
        PrimaryUserId                   = $PrimaryUserId
        PrimaryUserLookupStatus         = $PrimaryUserLookupStatus
        PrimaryUserAccountEnabled       = $PrimaryUserAccountEnabled
        PrimaryUserAccountStatus        = $PrimaryUserAccountStatus
        PrimaryUserAccountLookupStatus  = $PrimaryUserAccountLookupStatus

        SecureBootStatus                = $SecureBootStatus
        SecureBootRaw                   = $SecureBootRaw
        SecureBootReportSource          = $SecureBootReportSource
        SecureBootLastUpdateDateTime    = $SecureBootLastUpdateDateTime
        SecureBootCertificateStatus     = $SecureBootCertificateStatus
        SecureBootAttestationError      = $SecureBootAttestationError
        SecureBootDeviceOS              = $SecureBootDeviceOS
        SecureBootTPMVersion            = $SecureBootTPMVersion
        SecureBootCodeIntegrityStatus   = $SecureBootCodeIntegrityStatus
        SecureBootVSMStatus             = $SecureBootVSMStatus
        FirmwareManufacturer            = $FirmwareManufacturer
        FirmwareVersion                 = $FirmwareVersion
        FirmwareReleaseDate             = $FirmwareReleaseDate
        DeviceSKU                       = $DeviceSKU
        SystemBoardManufacturer         = $SystemBoardManufacturer
        SystemBoardModel                = $SystemBoardModel
        SystemBoardVersion              = $SystemBoardVersion
        ModelFamily                     = $ModelFamily

        ComplianceState                 = Normalize-Value $Device.complianceState

        OperatingSystem                 = Normalize-Value $Device.operatingSystem
        OSVersion                       = Normalize-Value $Device.osVersion
        OSFriendlyVersion               = $OSInfo.FriendlyVersion
        OSBuild                         = $OSInfo.Build
        OSUBR                           = $OSInfo.UBR
        OSVersionStatus                 = $OSInfo.VersionStatus
        OSUBRStatus                     = $OSInfo.UBRStatus

        Manufacturer                    = Normalize-Value $Device.manufacturer
        Model                           = Normalize-Value $Device.model
        SerialNumber                    = Normalize-Value $Device.serialNumber
        AzureADDeviceId                 = $AzureADDeviceId
        IntuneDeviceId                  = Normalize-Value $Device.id

        ManagementAgent                 = Normalize-Value $Device.managementAgent
        OwnerType                       = Normalize-Value $Device.managedDeviceOwnerType
        RegistrationState               = Normalize-Value $Device.deviceRegistrationState

        LastSyncDateTime                = Normalize-Value $Device.lastSyncDateTime
        EnrolledDateTime                = Normalize-Value $Device.enrolledDateTime

        TotalStorageGB                  = $TotalGB
        FreeStorageGB                   = $FreeGB
        FreeStoragePercent              = $FreePct
    }
}

$Rows = @($Rows)

$RowsWithPrimaryUserDisabled = @($Rows | Where-Object { $_.PrimaryUserAccountStatus -eq "Disabled" }).Count
$RowsWithPrimaryUserEnabled = @($Rows | Where-Object { $_.PrimaryUserAccountStatus -eq "Enabled" }).Count
$RowsWithNoPrimaryUser = @($Rows | Where-Object { $_.PrimaryUserAccountStatus -eq "No primary user" }).Count

Write-Host "Primary users enabled: $RowsWithPrimaryUserEnabled" -ForegroundColor Green
Write-Host "Primary users disabled: $RowsWithPrimaryUserDisabled" -ForegroundColor Yellow
Write-Host "Devices with no primary user: $RowsWithNoPrimaryUser" -ForegroundColor Yellow

$RowsWithSecureBootEnabled = @($Rows | Where-Object { $_.SecureBootStatus -eq "Enabled" }).Count
$RowsWithSecureBootDisabled = @($Rows | Where-Object { $_.SecureBootStatus -eq "Disabled" }).Count
$RowsWithSecureBootUnknown = @($Rows | Where-Object { $_.SecureBootStatus -ne "Enabled" -and $_.SecureBootStatus -ne "Disabled" }).Count

Write-Host "Secure Boot enabled: $RowsWithSecureBootEnabled" -ForegroundColor Green
Write-Host "Secure Boot disabled: $RowsWithSecureBootDisabled" -ForegroundColor Yellow
Write-Host "Secure Boot unknown/other: $RowsWithSecureBootUnknown" -ForegroundColor Yellow

# ============================================================
# Export CSV and JSON
# ============================================================

$Rows | Sort-Object DeviceName | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
$Rows | ConvertTo-Json -Depth 20 | Out-File -FilePath $JsonPath -Encoding UTF8

Write-Host ""
Write-Host "CSV exported:  $CsvPath" -ForegroundColor Green
Write-Host "JSON exported: $JsonPath" -ForegroundColor Green

# ============================================================
# Prepare dashboard data
# ============================================================

$GeneratedOn = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$DashboardDataJson = @($Rows) | ConvertTo-Json -Depth 20 -Compress
$DashboardDataBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($DashboardDataJson))
$TotalDevices = $Rows.Count
$SafeTenantName = ConvertTo-HtmlSafe $TenantDisplayName

# ============================================================
# HTML dashboard
# ============================================================

$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Intune Windows Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    :root {
        --bg: #f4f7fb;
        --surface: #ffffff;
        --text: #102033;
        --muted: #64748b;
        --border: #dbe4ee;
        --shadow: 0 18px 45px rgba(15, 23, 42, 0.08);
        --blue: #2563eb;
        --green: #16a34a;
        --red: #dc2626;
        --orange: #f59e0b;
        --gray: #94a3b8;
        --purple: #7c3aed;
        --cyan: #0891b2;
        --green-soft: #dcfce7;
        --red-soft: #fee2e2;
        --orange-soft: #fef3c7;
    }

    * { box-sizing: border-box; }

    body {
        margin: 0;
        font-family: Segoe UI, Arial, sans-serif;
        background:
            radial-gradient(circle at top left, #e0ecff 0, transparent 34%),
            linear-gradient(180deg, #f8fbff 0, #eef3f9 100%);
        color: var(--text);
    }

    header { padding: 28px 34px 16px 34px; }

    .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 24px;
        background: rgba(255,255,255,0.86);
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 18px 22px;
        box-shadow: var(--shadow);
    }

    .brand-left { display: flex; align-items: center; gap: 18px; }

    .tenant-logo {
        max-height: 56px;
        max-width: 280px;
        object-fit: contain;
        display: block;
    }

    .logo-fallback {
        min-width: 52px;
        height: 52px;
        padding: 0 18px;
        border-radius: 16px;
        background: #0f172a;
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
    }

    h1 { margin: 0; font-size: 30px; letter-spacing: -0.7px; color: #0f172a; }
    .subtitle { color: var(--muted); margin-top: 6px; font-size: 14px; }
    .generated { text-align: right; color: var(--muted); font-size: 13px; line-height: 1.5; }
    .layout { padding: 18px 34px 40px 34px; }

    .grid {
        display: grid;
        grid-template-columns: repeat(6, minmax(160px, 1fr));
        gap: 16px;
        margin-bottom: 18px;
    }

    .card {
        background: rgba(255,255,255,0.92);
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
        box-shadow: var(--shadow);
    }

    .card-title {
        color: var(--muted);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 700;
    }

    .card-value { font-size: 34px; font-weight: 800; margin-top: 8px; color: #0f172a; }
    .card-note { color: var(--muted); font-size: 13px; margin-top: 6px; line-height: 1.5; }
    .good { color: var(--green); }
    .bad { color: var(--red); }
    .warn { color: var(--orange); }
    .info { color: var(--blue); }

    .section {
        background: rgba(255,255,255,0.86);
        border: 1px solid var(--border);
        border-radius: 22px;
        padding: 20px;
        margin-top: 18px;
        box-shadow: var(--shadow);
    }

    .section h2 { margin: 0 0 14px 0; font-size: 20px; color: #0f172a; }

    .mini-grid { display: grid; grid-template-columns: repeat(3, minmax(260px, 1fr)); gap: 16px; }
    .chart-card { display: grid; grid-template-columns: 150px 1fr; gap: 18px; align-items: center; min-height: 190px; }

    .pie {
        width: 140px;
        height: 140px;
        border-radius: 50%;
        position: relative;
        box-shadow: inset 0 0 0 1px rgba(15,23,42,0.08);
        background: conic-gradient(var(--gray) 0deg 360deg);
    }

    .pie::after {
        content: "";
        position: absolute;
        inset: 28px;
        background: #ffffff;
        border-radius: 50%;
        box-shadow: inset 0 0 0 1px rgba(15,23,42,0.08);
    }

    .pie-center {
        position: absolute;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 2;
        font-size: 19px;
        font-weight: 800;
        color: #0f172a;
    }

    .legend { display: grid; gap: 8px; font-size: 13px; color: #334155; }
    .legend-row { display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; align-items: center; }
    .dot { width: 11px; height: 11px; border-radius: 999px; }
    .dot.green { background: var(--green); }
    .dot.red { background: var(--red); }
    .dot.orange { background: var(--orange); }
    .dot.gray { background: var(--gray); }
    .dot.blue { background: var(--blue); }
    .dot.purple { background: var(--purple); }
    .dot.cyan { background: var(--cyan); }

    .toolbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }

    input, select, button, .check-filter summary {
        background: #ffffff;
        color: #0f172a;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 10px 12px;
        font-size: 14px;
        box-shadow: 0 6px 16px rgba(15,23,42,0.04);
    }

    input { min-width: 260px; }
    input[type="date"] { min-width: 160px; }

    .check-filter { position: relative; min-width: 170px; }
    .check-filter summary { cursor: pointer; list-style: none; min-width: 170px; user-select: none; }
    .check-filter summary::-webkit-details-marker { display: none; }
    .check-filter summary:after { content: "v"; float: right; color: var(--muted); margin-left: 12px; }
    .check-filter[open] summary:after { content: "^"; }

    .check-filter-panel {
        position: absolute;
        top: calc(100% + 6px);
        left: 0;
        z-index: 30;
        display: grid;
        gap: 4px;
        min-width: 100%;
        width: max-content;
        max-height: 300px;
        overflow: auto;
        padding: 8px;
        background: #ffffff;
        border: 1px solid var(--border);
        border-radius: 12px;
        box-shadow: 0 18px 36px rgba(15,23,42,0.14);
    }

    .check-filter-panel label {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 7px 8px;
        border-radius: 8px;
        font-size: 13px;
        color: #334155;
        white-space: nowrap;
        cursor: pointer;
    }

    .check-filter-panel label:hover { background: #f8fafc; }
    .check-filter-panel input[type="checkbox"] { min-width: 0; width: 16px; height: 16px; padding: 0; box-shadow: none; accent-color: #2563eb; }

    button { cursor: pointer; background: #0f172a; color: #ffffff; border-color: #0f172a; font-weight: 600; }
    button:hover { background: #1e293b; }

    .filter-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--muted);
        font-size: 13px;
        background: #ffffff;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 6px 10px;
        box-shadow: 0 6px 16px rgba(15,23,42,0.04);
    }

    .filter-label input { box-shadow: none; border-radius: 8px; padding: 8px; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; color: #334155; background: #eef4fb; position: sticky; top: 0; z-index: 2; font-weight: 700; }
    th, td { padding: 10px; border-bottom: 1px solid #e5edf5; vertical-align: top; white-space: nowrap; }
    tr:hover { background: #f8fafc; }
    .table-wrap { overflow: auto; max-height: 720px; border: 1px solid var(--border); border-radius: 16px; background: #ffffff; }

    .pill {
        display: inline-block;
        padding: 4px 9px;
        border-radius: 999px;
        font-size: 12px;
        border: 1px solid var(--border);
        background: #f8fafc;
        color: #334155;
        font-weight: 600;
    }

    .pill.good { background: var(--green-soft); border-color: #86efac; color: #166534; }
    .pill.bad { background: var(--red-soft); border-color: #fca5a5; color: #991b1b; }
    .pill.warn { background: var(--orange-soft); border-color: #fcd34d; color: #92400e; }

    footer { color: var(--muted); padding: 20px 34px 35px 34px; font-size: 12px; }

    @media (max-width: 1400px) {
        .grid { grid-template-columns: repeat(3, minmax(180px, 1fr)); }
        .mini-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 760px) {
        .topbar { flex-direction: column; align-items: flex-start; }
        .generated { text-align: left; }
        .grid { grid-template-columns: 1fr; }
        input { min-width: 100%; }
        .chart-card { grid-template-columns: 1fr; }
    }
</style>
</head>
<body>

<header>
    <div class="topbar">
        <div class="brand-left">
            $LogoHtml
            <div>
                <h1>Intune Windows Dashboard</h1>
                <div class="subtitle">$SafeTenantName</div>
            </div>
        </div>
        <div class="generated">
            <strong>Generated</strong><br>
            $GeneratedOn
        </div>
    </div>
</header>

<div class="layout">

    <div class="grid">
        <div class="card">
            <div class="card-title">Filtered Devices</div>
            <div class="card-value" id="cardTotalDevices">0</div>
            <div class="card-note" id="cardTotalNote">Showing 0 of $TotalDevices devices</div>
        </div>

        <div class="card">
            <div class="card-title">Compliant</div>
            <div class="card-value good" id="cardCompliant">0</div>
            <div class="card-note" id="cardCompliantNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Non-Compliant</div>
            <div class="card-value bad" id="cardNonCompliant">0</div>
            <div class="card-note" id="cardNonCompliantNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Primary Users Enabled</div>
            <div class="card-value good" id="cardPrimaryEnabled">0</div>
            <div class="card-note" id="cardPrimaryEnabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Disabled Primary Users</div>
            <div class="card-value bad" id="cardPrimaryDisabled">0</div>
            <div class="card-note" id="cardPrimaryDisabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Secure Boot Enabled</div>
            <div class="card-value good" id="cardSecureBootEnabled">0</div>
            <div class="card-note" id="cardSecureBootEnabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Secure Boot Disabled</div>
            <div class="card-value bad" id="cardSecureBootDisabled">0</div>
            <div class="card-note" id="cardSecureBootDisabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Below OS Target</div>
            <div class="card-value warn" id="cardBelowTarget">0</div>
            <div class="card-note">UBR below configured threshold</div>
        </div>
    </div>

    <div class="section">
        <h2>Quick Look</h2>

        <div class="mini-grid">
            <div class="card chart-card">
                <div class="pie" id="pieCompliance"><div class="pie-center" id="pieComplianceCenter">0%</div></div>
                <div>
                    <div class="card-title">Compliance</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot green"></span><span>Compliant</span><strong id="legendCompliant">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot red"></span><span>Non-compliant</span><strong id="legendNonCompliant">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Other / unknown</span><strong id="legendComplianceOther">0 / 0%</strong></div>
                    </div>
                </div>
            </div>

            <div class="card chart-card">
                <div class="pie" id="piePrimaryUser"><div class="pie-center" id="piePrimaryUserCenter">0%</div></div>
                <div>
                    <div class="card-title">Primary User Status</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot green"></span><span>Enabled</span><strong id="legendPrimaryEnabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot red"></span><span>Disabled</span><strong id="legendPrimaryDisabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot orange"></span><span>No primary user</span><strong id="legendNoPrimaryUser">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Unknown</span><strong id="legendPrimaryUnknown">0 / 0%</strong></div>
                    </div>
                </div>
            </div>



            <div class="card chart-card">
                <div class="pie" id="pieSecureBoot"><div class="pie-center" id="pieSecureBootCenter">0%</div></div>
                <div>
                    <div class="card-title">Secure Boot</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot green"></span><span>Enabled</span><strong id="legendSecureBootEnabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot red"></span><span>Disabled</span><strong id="legendSecureBootDisabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Unknown / other</span><strong id="legendSecureBootUnknown">0 / 0%</strong></div>
                    </div>
                </div>
            </div>

            <div class="card chart-card">
                <div class="pie" id="pieOS"><div class="pie-center" id="pieOSCenter">0%</div></div>
                <div>
                    <div class="card-title">Windows OS Branch</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot blue"></span><span>24H2 / 26100</span><strong id="legend26100">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot purple"></span><span>25H2 / 26200</span><strong id="legend26200">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot orange"></span><span>Older</span><strong id="legendOlder">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot cyan"></span><span>Newer</span><strong id="legendNewer">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Unknown</span><strong id="legendOSUnknown">0 / 0%</strong></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Device Details</h2>

        <div class="toolbar">
            <input id="searchBox" type="text" placeholder="Search device, user, model, serial, OS..." oninput="renderDashboard()">

            <details class="check-filter" id="complianceFilterMenu">
                <summary><span id="complianceFilterSummary">All compliance states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="complianceFilter" value="compliant" data-label="Compliant" onchange="onCheckboxFilterChanged()"> Compliant</label>
                    <label><input type="checkbox" name="complianceFilter" value="noncompliant" data-label="Non-compliant" onchange="onCheckboxFilterChanged()"> Non-compliant</label>
                    <label><input type="checkbox" name="complianceFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                    <label><input type="checkbox" name="complianceFilter" value="ingraceperiod" data-label="In grace period" onchange="onCheckboxFilterChanged()"> In grace period</label>
                    <label><input type="checkbox" name="complianceFilter" value="configmanager" data-label="Config Manager" onchange="onCheckboxFilterChanged()"> Config Manager</label>
                </div>
            </details>

            <details class="check-filter" id="primaryStatusFilterMenu">
                <summary><span id="primaryStatusFilterSummary">All primary user states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="primaryStatusFilter" value="enabled" data-label="Enabled" onchange="onCheckboxFilterChanged()"> Enabled</label>
                    <label><input type="checkbox" name="primaryStatusFilter" value="disabled" data-label="Disabled" onchange="onCheckboxFilterChanged()"> Disabled</label>
                    <label><input type="checkbox" name="primaryStatusFilter" value="no primary user" data-label="No primary user" onchange="onCheckboxFilterChanged()"> No primary user</label>
                    <label><input type="checkbox" name="primaryStatusFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                </div>
            </details>



            <details class="check-filter" id="secureBootFilterMenu">
                <summary><span id="secureBootFilterSummary">All Secure Boot states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="secureBootFilter" value="enabled" data-label="Enabled" onchange="onCheckboxFilterChanged()"> Enabled</label>
                    <label><input type="checkbox" name="secureBootFilter" value="disabled" data-label="Disabled" onchange="onCheckboxFilterChanged()"> Disabled</label>
                    <label><input type="checkbox" name="secureBootFilter" value="unknown" data-label="Unknown / other" onchange="onCheckboxFilterChanged()"> Unknown / other</label>
                </div>
            </details>

            <details class="check-filter" id="osFilterMenu">
                <summary><span id="osFilterSummary">All OS branches</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="osFilter" value="26100" data-label="Windows 11 24H2 / 26100" onchange="onCheckboxFilterChanged()"> Windows 11 24H2 / 26100</label>
                    <label><input type="checkbox" name="osFilter" value="26200" data-label="Windows 11 25H2 / 26200" onchange="onCheckboxFilterChanged()"> Windows 11 25H2 / 26200</label>
                    <label><input type="checkbox" name="osFilter" value="older" data-label="Older than 26100" onchange="onCheckboxFilterChanged()"> Older than 26100</label>
                    <label><input type="checkbox" name="osFilter" value="newer" data-label="Newer than 26200" onchange="onCheckboxFilterChanged()"> Newer than 26200</label>
                    <label><input type="checkbox" name="osFilter" value="belowtarget" data-label="Below UBR target" onchange="onCheckboxFilterChanged()"> Below UBR target</label>
                </div>
            </details>

            <select id="lastSyncPreset" onchange="onLastSyncPresetChanged()">
                <option value="">All last check-ins</option>
                <option value="last7">Last 7 days</option>
                <option value="last14">Last 14 days</option>
                <option value="last30">Last 30 days</option>
                <option value="last60">Last 60 days</option>
                <option value="last90">Last 90 days</option>
                <option value="older30">Older than 30 days</option>
                <option value="older60">Older than 60 days</option>
                <option value="older90">Older than 90 days</option>
                <option value="never">Never / blank</option>
            </select>

            <label class="filter-label">From <input id="lastSyncFrom" type="date" onchange="renderDashboard()"></label>
            <label class="filter-label">To <input id="lastSyncTo" type="date" onchange="renderDashboard()"></label>

            <button onclick="clearAllFilters()">Clear filters</button>
            <button onclick="downloadVisibleCsv()">Download visible CSV</button>
        </div>

        <div class="card-note" id="visibleCount"></div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Device</th>
                        <th>User</th>
                        <th>Primary User</th>
                        <th>Primary User Status</th>
                        <th>Primary User UPN</th>
                        <th>Email</th>
                        <th>Secure Boot</th>
                        <th>SB Cert</th>
                        <th>SB Source</th>
                        <th>Firmware Manufacturer</th>
                        <th>Firmware Version</th>
                        <th>Firmware Release Date</th>
                        <th>Device SKU</th>
                        <th>System Board Model</th>
                        <th>Compliance</th>
                        <th>OS</th>
                        <th>OS Version</th>
                        <th>Build</th>
                        <th>UBR</th>
                        <th>UBR Status</th>
                        <th>Manufacturer</th>
                        <th>Model</th>
                        <th>Serial</th>
                        <th>Owner</th>
                        <th>Mgmt Agent</th>
                        <th>Registration</th>
                        <th>Last Check-in</th>
                        <th>Free Storage %</th>
                    </tr>
                </thead>
                <tbody id="deviceTableBody"></tbody>
            </table>
        </div>
    </div>

</div>

<footer>
    Primary user status comes from Entra ID accountEnabled.
</footer>

<script>
const dashboardDataBase64 = "$DashboardDataBase64";

const devices = JSON.parse(
    new TextDecoder().decode(
        Uint8Array.from(atob(dashboardDataBase64), function(c) { return c.charCodeAt(0); })
    )
);

const totalDeviceCount = devices.length;

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function pct(count, total) {
    if (!total || total <= 0) return 0;
    return Math.round((count / total) * 1000) / 10;
}

function deg(count, total) {
    if (!total || total <= 0) return 0;
    return Math.round((count / total) * 3600) / 10;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerText = value;
}

function setPie(id, segments) {
    const pie = document.getElementById(id);
    if (!pie) return;

    let current = 0;
    let parts = [];

    segments.forEach(function(segment) {
        const next = current + segment.degrees;
        parts.push(segment.color + " " + current + "deg " + next + "deg");
        current = next;
    });

    if (current < 360) { parts.push("var(--gray) " + current + "deg 360deg"); }
    pie.style.background = "conic-gradient(" + parts.join(", ") + ")";
}

function pill(value, type) {
    const clean = value || "unknown";
    let cls = "pill";

    if (type === "compliance") {
        if (clean.toLowerCase() === "compliant") cls += " good";
        else if (clean.toLowerCase() === "noncompliant") cls += " bad";
        else cls += " warn";
    }

    if (type === "primaryuser") {
        if (clean.toLowerCase() === "enabled") cls += " good";
        else if (clean.toLowerCase() === "disabled") cls += " bad";
        else cls += " warn";
    }

    if (type === "secureboot") {
        if (clean.toLowerCase() === "enabled") cls += " good";
        else if (clean.toLowerCase() === "disabled") cls += " bad";
        else cls += " warn";
    }

    if (type === "ubr") {
        if (clean.toLowerCase() === "ok") cls += " good";
        else if (clean.toLowerCase() === "below target") cls += " bad";
        else cls += " warn";
    }

    return '<span class="' + cls + '">' + escapeHtml(clean) + '</span>';
}

function parseDeviceDate(value) {
    if (!value) return null;
    const d = new Date(value);
    if (isNaN(d.getTime())) return null;
    return d;
}

function parseDateInput(value, endOfDay) {
    if (!value) return null;
    const parts = value.split("-");
    if (parts.length !== 3) return null;
    const year = Number(parts[0]);
    const month = Number(parts[1]) - 1;
    const day = Number(parts[2]);
    if (endOfDay) return new Date(year, month, day, 23, 59, 59, 999);
    return new Date(year, month, day, 0, 0, 0, 0);
}

function getCheckedValues(name) {
    const boxes = document.querySelectorAll('input[name="' + name + '"]:checked');
    const values = [];
    for (let i = 0; i < boxes.length; i++) values.push(boxes[i].value);
    return values;
}

function getCheckedLabels(name) {
    const boxes = document.querySelectorAll('input[name="' + name + '"]:checked');
    const labels = [];
    for (let i = 0; i < boxes.length; i++) labels.push(boxes[i].getAttribute("data-label") || boxes[i].value);
    return labels;
}

function clearCheckboxGroup(name) {
    const boxes = document.querySelectorAll('input[name="' + name + '"]');
    for (let i = 0; i < boxes.length; i++) boxes[i].checked = false;
}

function matchesAny(values, tester) {
    if (!values || values.length === 0) return true;
    for (let i = 0; i < values.length; i++) {
        if (tester(values[i])) return true;
    }
    return false;
}

function updateFilterSummary(summaryId, filterName, defaultText) {
    const labels = getCheckedLabels(filterName);
    let text = defaultText;
    if (labels.length === 1) text = labels[0];
    else if (labels.length > 1) text = labels.length + " selected";
    setText(summaryId, text);
}

function updateFilterSummaries() {
    updateFilterSummary("complianceFilterSummary", "complianceFilter", "All compliance states");
    updateFilterSummary("primaryStatusFilterSummary", "primaryStatusFilter", "All primary user states");
    updateFilterSummary("secureBootFilterSummary", "secureBootFilter", "All Secure Boot states");
    updateFilterSummary("osFilterSummary", "osFilter", "All OS branches");
}

function onCheckboxFilterChanged() { renderDashboard(); }

function setupFilterMenus() {
    const menus = document.querySelectorAll(".check-filter");

    for (let i = 0; i < menus.length; i++) {
        menus[i].addEventListener("toggle", function() {
            if (!this.open) return;
            for (let j = 0; j < menus.length; j++) {
                if (menus[j] !== this) menus[j].removeAttribute("open");
            }
        });
    }

    document.addEventListener("click", function(event) {
        for (let i = 0; i < menus.length; i++) {
            if (!menus[i].contains(event.target)) menus[i].removeAttribute("open");
        }
    });
}

function matchesLastSyncFilter(d) {
    const preset = document.getElementById("lastSyncPreset").value;
    const fromValue = document.getElementById("lastSyncFrom").value;
    const toValue = document.getElementById("lastSyncTo").value;
    const lastSync = parseDeviceDate(d.LastSyncDateTime);
    const now = new Date();

    if (preset === "never") return lastSync === null;

    if (preset === "last7" || preset === "last14" || preset === "last30" || preset === "last60" || preset === "last90") {
        if (!lastSync) return false;
        const days = Number(preset.replace("last", ""));
        const cutoff = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
        if (lastSync < cutoff) return false;
    }

    if (preset === "older30" || preset === "older60" || preset === "older90") {
        if (!lastSync) return false;
        const days = Number(preset.replace("older", ""));
        const cutoff = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
        if (lastSync >= cutoff) return false;
    }

    const fromDate = parseDateInput(fromValue, false);
    const toDate = parseDateInput(toValue, true);

    if (fromDate || toDate) {
        if (!lastSync) return false;
        if (fromDate && lastSync < fromDate) return false;
        if (toDate && lastSync > toDate) return false;
    }

    return true;
}

function onLastSyncPresetChanged() {
    const preset = document.getElementById("lastSyncPreset").value;
    if (preset) {
        document.getElementById("lastSyncFrom").value = "";
        document.getElementById("lastSyncTo").value = "";
    }
    renderDashboard();
}

function clearAllFilters() {
    document.getElementById("searchBox").value = "";
    clearCheckboxGroup("complianceFilter");
    clearCheckboxGroup("primaryStatusFilter");
    clearCheckboxGroup("secureBootFilter");
    clearCheckboxGroup("osFilter");
    document.getElementById("lastSyncPreset").value = "";
    document.getElementById("lastSyncFrom").value = "";
    document.getElementById("lastSyncTo").value = "";
    renderDashboard();
}

function getFilteredDevices() {
    const search = document.getElementById("searchBox").value.toLowerCase();
    const compliance = getCheckedValues("complianceFilter");
    const primaryStatus = getCheckedValues("primaryStatusFilter");
    const secureBoot = getCheckedValues("secureBootFilter");
    const os = getCheckedValues("osFilter");

    return devices.filter(function(d) {
        const blob = Object.values(d).join(" ").toLowerCase();
        if (search && !blob.includes(search)) return false;

        if (compliance.length) {
            const state = String(d.ComplianceState || "").toLowerCase();
            if (!matchesAny(compliance, function(value) {
                if (value === "unknown") return state === "" || state === "unknown";
                return state === value;
            })) return false;
        }

        if (primaryStatus.length) {
            const status = String(d.PrimaryUserAccountStatus || "unknown").toLowerCase();
            if (!matchesAny(primaryStatus, function(value) {
                if (value === "unknown") return status === "" || status === "unknown";
                return status === value;
            })) return false;
        }

        if (secureBoot.length) {
            const sb = String(d.SecureBootStatus || "unknown").toLowerCase();
            if (!matchesAny(secureBoot, function(value) {
                if (value === "unknown") return sb !== "enabled" && sb !== "disabled";
                return sb === value;
            })) return false;
        }

        if (os.length) {
            const build = Number(d.OSBuild);
            if (!matchesAny(os, function(value) {
                if (value === "26100") return build === 26100;
                if (value === "26200") return build === 26200;
                if (value === "older") return build < 26100;
                if (value === "newer") return build > 26200;
                if (value === "belowtarget") return String(d.OSUBRStatus || "").toLowerCase() === "below target";
                return false;
            })) return false;
        }

        if (!matchesLastSyncFilter(d)) return false;
        return true;
    });
}

function updateQuickLook(rows) {
    const total = rows.length;

    const compliant = rows.filter(function(d) { return String(d.ComplianceState || "").toLowerCase() === "compliant"; }).length;
    const nonCompliant = rows.filter(function(d) { return String(d.ComplianceState || "").toLowerCase() === "noncompliant"; }).length;
    const complianceOther = total - compliant - nonCompliant;

    const primaryEnabled = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "enabled"; }).length;
    const primaryDisabled = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "disabled"; }).length;
    const noPrimaryUser = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "no primary user"; }).length;
    const primaryUnknown = total - primaryEnabled - primaryDisabled - noPrimaryUser;

    const secureBootEnabled = rows.filter(function(d) { return String(d.SecureBootStatus || "").toLowerCase() === "enabled"; }).length;
    const secureBootDisabled = rows.filter(function(d) { return String(d.SecureBootStatus || "").toLowerCase() === "disabled"; }).length;
    const secureBootUnknown = total - secureBootEnabled - secureBootDisabled;

    const build26100 = rows.filter(function(d) { return Number(d.OSBuild) === 26100; }).length;
    const build26200 = rows.filter(function(d) { return Number(d.OSBuild) === 26200; }).length;
    const older = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) < 26100; }).length;
    const newer = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) > 26200; }).length;
    const osUnknown = total - build26100 - build26200 - older - newer;
    const belowTarget = rows.filter(function(d) { return String(d.OSUBRStatus || "").toLowerCase() === "below target"; }).length;

    setText("cardTotalDevices", total);
    setText("cardTotalNote", "Showing " + total + " of " + totalDeviceCount + " devices");
    setText("cardCompliant", compliant);
    setText("cardCompliantNote", pct(compliant, total) + "% of filtered devices");
    setText("cardNonCompliant", nonCompliant);
    setText("cardNonCompliantNote", pct(nonCompliant, total) + "% of filtered devices");
    setText("cardPrimaryEnabled", primaryEnabled);
    setText("cardPrimaryEnabledNote", pct(primaryEnabled, total) + "% of filtered devices");
    setText("cardPrimaryDisabled", primaryDisabled);
    setText("cardPrimaryDisabledNote", pct(primaryDisabled, total) + "% of filtered devices");
    setText("cardSecureBootEnabled", secureBootEnabled);
    setText("cardSecureBootEnabledNote", pct(secureBootEnabled, total) + "% of filtered devices");
    setText("cardSecureBootDisabled", secureBootDisabled);
    setText("cardSecureBootDisabledNote", pct(secureBootDisabled, total) + "% of filtered devices");
    setText("cardBelowTarget", belowTarget);

    setText("legendCompliant", compliant + " / " + pct(compliant, total) + "%");
    setText("legendNonCompliant", nonCompliant + " / " + pct(nonCompliant, total) + "%");
    setText("legendComplianceOther", complianceOther + " / " + pct(complianceOther, total) + "%");
    setText("pieComplianceCenter", pct(compliant, total) + "%");

    setPie("pieCompliance", [
        { color: "var(--green)", degrees: deg(compliant, total) },
        { color: "var(--red)", degrees: deg(nonCompliant, total) },
        { color: "var(--gray)", degrees: deg(complianceOther, total) }
    ]);

    setText("legendPrimaryEnabled", primaryEnabled + " / " + pct(primaryEnabled, total) + "%");
    setText("legendPrimaryDisabled", primaryDisabled + " / " + pct(primaryDisabled, total) + "%");
    setText("legendNoPrimaryUser", noPrimaryUser + " / " + pct(noPrimaryUser, total) + "%");
    setText("legendPrimaryUnknown", primaryUnknown + " / " + pct(primaryUnknown, total) + "%");
    setText("piePrimaryUserCenter", pct(primaryEnabled, total) + "%");

    setPie("piePrimaryUser", [
        { color: "var(--green)", degrees: deg(primaryEnabled, total) },
        { color: "var(--red)", degrees: deg(primaryDisabled, total) },
        { color: "var(--orange)", degrees: deg(noPrimaryUser, total) },
        { color: "var(--gray)", degrees: deg(primaryUnknown, total) }
    ]);

    setText("legendSecureBootEnabled", secureBootEnabled + " / " + pct(secureBootEnabled, total) + "%");
    setText("legendSecureBootDisabled", secureBootDisabled + " / " + pct(secureBootDisabled, total) + "%");
    setText("legendSecureBootUnknown", secureBootUnknown + " / " + pct(secureBootUnknown, total) + "%");
    setText("pieSecureBootCenter", pct(secureBootEnabled, total) + "%");

    setPie("pieSecureBoot", [
        { color: "var(--green)", degrees: deg(secureBootEnabled, total) },
        { color: "var(--red)", degrees: deg(secureBootDisabled, total) },
        { color: "var(--gray)", degrees: deg(secureBootUnknown, total) }
    ]);

    setText("legend26100", build26100 + " / " + pct(build26100, total) + "%");
    setText("legend26200", build26200 + " / " + pct(build26200, total) + "%");
    setText("legendOlder", older + " / " + pct(older, total) + "%");
    setText("legendNewer", newer + " / " + pct(newer, total) + "%");
    setText("legendOSUnknown", osUnknown + " / " + pct(osUnknown, total) + "%");
    setText("pieOSCenter", pct(build26200, total) + "%");

    setPie("pieOS", [
        { color: "var(--blue)", degrees: deg(build26100, total) },
        { color: "var(--purple)", degrees: deg(build26200, total) },
        { color: "var(--orange)", degrees: deg(older, total) },
        { color: "var(--cyan)", degrees: deg(newer, total) },
        { color: "var(--gray)", degrees: deg(osUnknown, total) }
    ]);
}

function renderTable(rows) {
    const tbody = document.getElementById("deviceTableBody");
    document.getElementById("visibleCount").innerText = "Showing " + rows.length + " of " + devices.length + " devices";

    tbody.innerHTML = rows.map(function(d) {
        return "" +
            "<tr>" +
            "<td>" + escapeHtml(d.DeviceName) + "</td>" +
            "<td>" + escapeHtml(d.UserDisplayName || d.UserPrincipalName) + "</td>" +
            "<td>" + escapeHtml(d.PrimaryUser) + "</td>" +
            "<td>" + pill(d.PrimaryUserAccountStatus, "primaryuser") + "</td>" +
            "<td>" + escapeHtml(d.PrimaryUserUPN) + "</td>" +
            "<td>" + escapeHtml(d.EmailAddress) + "</td>" +
            "<td>" + pill(d.SecureBootStatus, "secureboot") + "</td>" +
            "<td>" + escapeHtml(d.SecureBootCertificateStatus) + "</td>" +
            "<td>" + escapeHtml(d.SecureBootReportSource) + "</td>" +
            "<td>" + escapeHtml(d.FirmwareManufacturer) + "</td>" +
            "<td>" + escapeHtml(d.FirmwareVersion) + "</td>" +
            "<td>" + escapeHtml(d.FirmwareReleaseDate) + "</td>" +
            "<td>" + escapeHtml(d.DeviceSKU) + "</td>" +
            "<td>" + escapeHtml(d.SystemBoardModel) + "</td>" +
            "<td>" + pill(d.ComplianceState, "compliance") + "</td>" +
            "<td>" + escapeHtml(d.OSFriendlyVersion) + "</td>" +
            "<td>" + escapeHtml(d.OSVersion) + "</td>" +
            "<td>" + escapeHtml(d.OSBuild) + "</td>" +
            "<td>" + escapeHtml(d.OSUBR) + "</td>" +
            "<td>" + pill(d.OSUBRStatus, "ubr") + "</td>" +
            "<td>" + escapeHtml(d.Manufacturer) + "</td>" +
            "<td>" + escapeHtml(d.Model) + "</td>" +
            "<td>" + escapeHtml(d.SerialNumber) + "</td>" +
            "<td>" + escapeHtml(d.OwnerType) + "</td>" +
            "<td>" + escapeHtml(d.ManagementAgent) + "</td>" +
            "<td>" + escapeHtml(d.RegistrationState) + "</td>" +
            "<td>" + escapeHtml(d.LastSyncDateTime) + "</td>" +
            "<td>" + escapeHtml(d.FreeStoragePercent) + "</td>" +
            "</tr>";
    }).join("");
}

function renderDashboard() {
    const rows = getFilteredDevices();
    updateQuickLook(rows);
    renderTable(rows);
    updateFilterSummaries();
}

function downloadVisibleCsv() {
    const rows = getFilteredDevices();
    if (!rows.length) { alert("No rows to export."); return; }

    const headers = Object.keys(rows[0]);

    function csvEscape(value) {
        if (value === null || value === undefined) return '""';
        const text = String(value).replace(/\r?\n/g, " ").replace(/"/g, '""');
        return '"' + text + '"';
    }

    const csvLines = [headers.map(csvEscape).join(",")];

    rows.forEach(function(row) {
        csvLines.push(headers.map(function(h) { return csvEscape(row[h]); }).join(","));
    });

    const csv = csvLines.join("\r\n");
    const blob = new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "Intune-Dashboard-Visible-Devices.csv";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();

    setTimeout(function() {
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }, 1000);
}

setupFilterMenus();
renderDashboard();
</script>

</body>
</html>
"@

$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host ""
Write-Host "HTML dashboard exported:" -ForegroundColor Green
Write-Host $HtmlPath -ForegroundColor Green

if ($OpenReport) {
    Open-FileCrossPlatform -Path $HtmlPath
}

Write-Host ""
Write-Host "Completed." -ForegroundColor Green
