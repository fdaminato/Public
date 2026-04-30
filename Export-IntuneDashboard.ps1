<#
.SYNOPSIS
    Export Intune Windows device dashboard to HTML + CSV + JSON.

.DESCRIPTION
    Cross-platform PowerShell script for Windows/macOS/Linux.

    Retrieves Intune Windows managed devices from Microsoft Graph and builds
    a self-contained HTML dashboard with:
      - Tenant logo from Entra Company Branding
      - Dynamic Quick Look cards
      - Dynamic pie charts that update with filters
      - Last check-in filtering
      - BitLocker disk encryption percentage from Intune remediation:
        DaaS - Detection - Bitlocker - Get status
      - Device compliance
      - Windows OS build / UBR status
      - BitLocker / encryption status
      - Storage
      - User / model / serial

.NOTES
    BitLocker remediation run states in some tenants do not expose deviceName or managedDeviceId.
    This script extracts Intune managedDeviceId from the run state id:
      {scriptId}{managedDeviceId}{extraGuid}
#>

[CmdletBinding()]
param(
    [string]$OutputFolder,

    [int]$MinimumUBR_26100 = 8037,

    [int]$MinimumUBR_26200 = 8037,

    [string]$BitLockerRemediationName = "DaaS - Detection - Bitlocker - Get status",

    [int]$MaxBitLockerRunStates = 1200,

    [int]$BitLockerRunStateTop = 50,

    [switch]$OpenReport
)

$ErrorActionPreference = "Stop"

# ============================================================
# Cross-platform output folder
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
$BitLockerRawPath = Join-Path $OutputFolder "Intune-BitLocker-RunStates-Raw-$Timestamp.json"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Intune Windows Dashboard Export" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output folder: $OutputFolder"
Write-Host "BitLocker remediation source: $BitLockerRemediationName"
Write-Host "Max BitLocker run states: $MaxBitLockerRunStates"
Write-Host ""

# ============================================================
# Module check
# ============================================================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ============================================================
# Graph connection
# ============================================================

$Scopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementScripts.Read.All",
    "Directory.Read.All",
    "Organization.Read.All",
    "OrganizationalBranding.Read.All"
)

$Context = Get-MgContext -ErrorAction SilentlyContinue

if (-not $Context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $Scopes -NoWelcome
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
        Connect-MgGraph -Scopes $Scopes -NoWelcome
    }
}

# ============================================================
# Helper functions
# ============================================================

function Normalize-Value {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [string]$Value
}

function ConvertTo-HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string[]]$PropertyNames
    )

    if ($null -eq $Object) {
        return ""
    }

    foreach ($PropertyName in $PropertyNames) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.ContainsKey($PropertyName)) {
                $Value = Normalize-Value $Object[$PropertyName]
                if (-not [string]::IsNullOrWhiteSpace($Value)) {
                    return $Value
                }
            }
        }

        if ($Object.PSObject.Properties.Name -contains $PropertyName) {
            $Value = Normalize-Value $Object.$PropertyName
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                return $Value
            }
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

    # Use a plain PowerShell array instead of System.Collections.Generic.List[object].
    # Some Microsoft Graph SDK responses are returned as Dictionary/Hashtable objects on macOS/PowerShell 7,
    # and returning a generic .NET list can throw: "Argument types do not match".
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

function Invoke-GraphGetAllSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxItems = 1200
    )

    $Results = @()
    $NextUri = $Uri
    $FailedUri = ""

    while ($NextUri) {
        if ($Results.Count -ge $MaxItems) {
            Write-Host "Reached MaxItems limit: $MaxItems. Stopping safely." -ForegroundColor Yellow
            break
        }

        try {
            Write-Host "GET $NextUri" -ForegroundColor DarkGray
            $Response = Invoke-MgGraphRequest -Method GET -Uri $NextUri

            if ($Response.value) {
                foreach ($Item in @($Response.value)) {
                    if ($Results.Count -lt $MaxItems) {
                        $Results += $Item
                    }
                }
            }

            $NextUri = $Response.'@odata.nextLink'
        }
        catch {
            $FailedUri = $NextUri
            Write-Warning "Graph page failed. Keeping partial results and stopping."
            Write-Warning $_.Exception.Message
            $NextUri = $null
        }
    }

    return @{
        Results   = $Results
        FailedUri = $FailedUri
    }
}

function Convert-BytesToGB {
    param($Bytes)

    if ($null -eq $Bytes -or $Bytes -eq "") {
        return $null
    }

    try {
        return [math]::Round(($Bytes / 1GB), 2)
    }
    catch {
        return $null
    }
}

function Get-Percent {
    param($Part, $Total)

    if ($null -eq $Part -or $null -eq $Total -or $Total -eq 0) {
        return $null
    }

    return [math]::Round(($Part / $Total) * 100, 1)
}

function Convert-IsEncryptedToState {
    param($IsEncrypted)

    if ($null -eq $IsEncrypted -or $IsEncrypted -eq "") {
        return ""
    }

    if ($IsEncrypted -eq $true -or $IsEncrypted -eq "True" -or $IsEncrypted -eq "true") {
        return "encrypted"
    }

    if ($IsEncrypted -eq $false -or $IsEncrypted -eq "False" -or $IsEncrypted -eq "false") {
        return "notEncrypted"
    }

    return ""
}

function Open-FileCrossPlatform {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        if ($IsWindows) {
            Start-Process $Path
        }
        elseif ($IsMacOS) {
            & open $Path
        }
        elseif ($IsLinux) {
            & xdg-open $Path
        }
        else {
            Write-Host "Open this file manually: $Path" -ForegroundColor Yellow
        }
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

    if ([string]::IsNullOrWhiteSpace($OSVersion)) {
        return [pscustomobject]$Result
    }

    $Parts = $OSVersion.Split(".")

    if ($Parts.Count -ge 3) {
        $Build = 0
        if ([int]::TryParse($Parts[2], [ref]$Build)) {
            $Result.Build = $Build
        }

        if ($Parts.Count -ge 4) {
            $UBR = 0
            if ([int]::TryParse($Parts[3], [ref]$UBR)) {
                $Result.UBR = $UBR
            }
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
            return [pscustomobject]@{
                TenantDisplayName = $TenantDisplayName
                LogoDataUri       = $LogoDataUri
            }
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
            if ($Branding.cdnList) {
                $CdnList = @($Branding.cdnList)
            }

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
                            if (Test-Path $TempFile) {
                                Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
                            }

                            Invoke-WebRequest -Uri $ImageUrl -OutFile $TempFile -UseBasicParsing -ErrorAction Stop
                            $LogoDataUri = Convert-ImageFileToDataUri -Path $TempFile

                            if (-not [string]::IsNullOrWhiteSpace($LogoDataUri)) {
                                Write-Host "Tenant logo found from CDN: $RelativeProperty" -ForegroundColor Green
                                return [pscustomobject]@{
                                    TenantDisplayName = $TenantDisplayName
                                    LogoDataUri       = $LogoDataUri
                                }
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

        # Stream fallback
        $StreamAttempts = New-Object System.Collections.Generic.List[object]

        foreach ($LogoProperty in @("headerLogo", "bannerLogo", "squareLogo", "squareLogoDark")) {
            $StreamAttempts.Add([pscustomobject]@{
                Name = "base-$LogoProperty"
                Uri  = "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/$LogoProperty/`$value"
            })
        }

        try {
            $LocalizationResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/localizations?`$select=id"

            if ($LocalizationResponse.value) {
                foreach ($Loc in $LocalizationResponse.value) {
                    $LocId = Normalize-Value $Loc.id
                    $EscapedLocId = [System.Uri]::EscapeDataString($LocId)

                    foreach ($LogoProperty in @("headerLogo", "bannerLogo", "squareLogo", "squareLogoDark")) {
                        $StreamAttempts.Add([pscustomobject]@{
                            Name = "localization-$LocId-$LogoProperty"
                            Uri  = "https://graph.microsoft.com/v1.0/organization/$OrgId/branding/localizations/$EscapedLocId/$LogoProperty/`$value"
                        })
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
                if (Test-Path $TempFile) {
                    Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
                }

                Invoke-MgGraphRequest -Method GET -Uri $Attempt.Uri -OutputFilePath $TempFile -ErrorAction Stop
                $LogoDataUri = Convert-ImageFileToDataUri -Path $TempFile

                if (-not [string]::IsNullOrWhiteSpace($LogoDataUri)) {
                    Write-Host "Tenant logo found from stream: $($Attempt.Name)" -ForegroundColor Green
                    return [pscustomobject]@{
                        TenantDisplayName = $TenantDisplayName
                        LogoDataUri       = $LogoDataUri
                    }
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

    return [pscustomobject]@{
        TenantDisplayName = $TenantDisplayName
        LogoDataUri       = $LogoDataUri
    }
}

function Parse-KeyValueOutput {
    param([string]$Output)

    $Parsed = [ordered]@{}

    if ([string]::IsNullOrWhiteSpace($Output)) {
        return $Parsed
    }

    $Parts = $Output -split '\|'

    foreach ($Part in $Parts) {
        $CleanPart = $Part.Trim()

        if ($CleanPart -match '^\s*([^=:\r\n]+)\s*[=:]\s*(.+?)\s*$') {
            $Key = $Matches[1].Trim()
            $Value = $Matches[2].Trim()

            if (-not [string]::IsNullOrWhiteSpace($Key)) {
                $Parsed[$Key] = $Value
            }
        }
    }

    return $Parsed
}

function ConvertFrom-BitLockerOutput {
    param([string]$Output)

    $Drive = ""
    $Protection = ""
    $ProtectionState = ""
    $VolumeStatus = ""
    $EncryptionPercentage = ""
    $KeyProtectors = ""
    $EncryptionMethod = ""
    $ParseMethod = "None"

    if (-not [string]::IsNullOrWhiteSpace($Output)) {
        try {
            $Json = $Output | ConvertFrom-Json -ErrorAction Stop

            if ($Json -is [array]) {
                $Json = $Json | Select-Object -First 1
            }

            $Drive = Get-PropertyValue -Object $Json -PropertyNames @("Drive", "OSDrive", "MountPoint")
            $Protection = Get-PropertyValue -Object $Json -PropertyNames @("Protection", "ProtectionStatus")
            $VolumeStatus = Get-PropertyValue -Object $Json -PropertyNames @("VolumeStatus", "Status")
            $EncryptionPercentage = Get-PropertyValue -Object $Json -PropertyNames @("EncryptionPercentage", "DiskEncryptionPercentage", "Percentage")
            $KeyProtectors = Get-PropertyValue -Object $Json -PropertyNames @("KeyProtectors", "KeyProtector", "Protectors")
            $EncryptionMethod = Get-PropertyValue -Object $Json -PropertyNames @("EncryptionMethod", "Method")
            $ParseMethod = "JSON"
        }
        catch {
            $KeyValues = Parse-KeyValueOutput -Output $Output

            if ($KeyValues.Count -gt 0) {
                foreach ($Key in $KeyValues.Keys) {
                    switch -Regex ($Key) {
                        '^Drive$|^OSDrive$|^MountPoint$' { $Drive = $KeyValues[$Key] }
                        '^Protection$|^ProtectionStatus$' { $Protection = $KeyValues[$Key] }
                        '^VolumeStatus$|^Status$' { $VolumeStatus = $KeyValues[$Key] }
                        '^EncryptionPercentage$|^DiskEncryptionPercentage$|^Percentage$' { $EncryptionPercentage = $KeyValues[$Key] }
                        '^KeyProtectors$|^KeyProtector$|^Protectors$' { $KeyProtectors = $KeyValues[$Key] }
                        '^EncryptionMethod$|^Method$' { $EncryptionMethod = $KeyValues[$Key] }
                    }
                }

                $ParseMethod = "KeyValue"
            }

            if ([string]::IsNullOrWhiteSpace($EncryptionPercentage) -and $Output -match '(?i)(EncryptionPercentage|DiskEncryptionPercentage|Encryption\s*Percentage)\s*[=:]\s*([0-9]{1,3})') {
                $EncryptionPercentage = $Matches[2].Trim()
                $ParseMethod = "Regex"
            }
            elseif ([string]::IsNullOrWhiteSpace($EncryptionPercentage) -and $Output -match '(?i)([0-9]{1,3})\s*%') {
                $EncryptionPercentage = $Matches[1].Trim()
                $ParseMethod = "Regex"
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Protection)) {
        if ($Protection -match '\(([^)]+)\)') {
            $ProtectionState = $Matches[1].Trim()
        }
        else {
            $ProtectionState = $Protection
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($EncryptionPercentage)) {
        $CleanPct = $EncryptionPercentage -replace '[^0-9\.]', ''
        if (-not [string]::IsNullOrWhiteSpace($CleanPct)) {
            $EncryptionPercentage = "$CleanPct%"
        }
    }

    return [pscustomobject]@{
        Drive                = $Drive
        Protection           = $Protection
        ProtectionState      = $ProtectionState
        VolumeStatus         = $VolumeStatus
        EncryptionPercentage = $EncryptionPercentage
        KeyProtectors        = $KeyProtectors
        EncryptionMethod     = $EncryptionMethod
        ParseMethod          = $ParseMethod
    }
}

function Get-BestDetectionOutput {
    param(
        [Parameter(Mandatory)]
        $RunState
    )

    $Candidates = @(
        "preRemediationDetectionScriptOutput",
        "postRemediationDetectionScriptOutput",
        "remediationScriptOutput",
        "detectionScriptOutput",
        "output",
        "resultMessage",
        "errorMessage"
    )

    foreach ($Candidate in $Candidates) {
        $Value = Get-PropertyValue -Object $RunState -PropertyNames @($Candidate)

        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            return [pscustomobject]@{
                OutputField = $Candidate
                Output      = $Value
            }
        }
    }

    return [pscustomobject]@{
        OutputField = ""
        Output      = ""
    }
}

function Get-ManagedDeviceIdFromRunStateId {
    param(
        [Parameter(Mandatory)]
        [string]$RunStateId,

        [Parameter(Mandatory)]
        [string]$ScriptId
    )

    if ([string]::IsNullOrWhiteSpace($RunStateId) -or [string]::IsNullOrWhiteSpace($ScriptId)) {
        return ""
    }

    if (-not $RunStateId.StartsWith($ScriptId, [System.StringComparison]::OrdinalIgnoreCase)) {
        return ""
    }

    $Remaining = $RunStateId.Substring($ScriptId.Length)

    # Next GUID after scriptId is the Intune managedDeviceId.
    if ($Remaining.Length -ge 36) {
        $Candidate = $Remaining.Substring(0, 36)
        $GuidTest = [guid]::Empty

        if ([guid]::TryParse($Candidate, [ref]$GuidTest)) {
            return $Candidate
        }
    }

    return ""
}

function Get-IntuneRemediationByName {
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    Write-Host ""
    Write-Host "Looking for Intune remediation: $DisplayName" -ForegroundColor Cyan

    $SafeName = $DisplayName.Replace("'", "''")
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$filter=displayName eq '$SafeName'&`$select=id,displayName&`$top=10"

    try {
        $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri

        if ($Response.value -and $Response.value.Count -gt 0) {
            $Remediation = $Response.value[0]
            Write-Host "Found remediation: $($Remediation.displayName)" -ForegroundColor Green
            return $Remediation
        }

        Write-Warning "Remediation not found: $DisplayName"
        return $null
    }
    catch {
        Write-Warning "Could not retrieve remediation by name."
        Write-Warning $_.Exception.Message
        return $null
    }
}

function Get-BitLockerRemediationResults {
    param(
        [Parameter(Mandatory)]
        [string]$RemediationName,

        [int]$Top = 50,

        [int]$MaxRunStates = 1200,

        [string]$RawExportPath
    )

    $ResultsByDeviceId = @{}
    $ResultsByDeviceName = @{}

    $Remediation = Get-IntuneRemediationByName -DisplayName $RemediationName

    if (-not $Remediation) {
        return [pscustomobject]@{
            ByDeviceId   = $ResultsByDeviceId
            ByDeviceName = $ResultsByDeviceName
            Count        = 0
        }
    }

    $RemediationId = $Remediation.id

    Write-Host ""
    Write-Host "Retrieving BitLocker remediation device run states WITHOUT select..." -ForegroundColor Cyan

    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$RemediationId/deviceRunStates?`$top=$Top"

    $SafeResult = Invoke-GraphGetAllSafe -Uri $Uri -MaxItems $MaxRunStates
    $RunStates = @($SafeResult["Results"])

    if (-not [string]::IsNullOrWhiteSpace($SafeResult["FailedUri"])) {
        Write-Host "Stopped after failed page:" -ForegroundColor Yellow
        Write-Host $SafeResult["FailedUri"] -ForegroundColor Yellow
    }

    Write-Host "Remediation device run states retrieved: $($RunStates.Count)" -ForegroundColor Green

    if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
        try {
            $RunStates | ConvertTo-Json -Depth 30 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Raw BitLocker run states exported: $RawExportPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export raw BitLocker run states."
        }
    }

    $WithOutput = 0
    $WithPercentage = 0
    $WithManagedDeviceIdFromId = 0
    $MappedByDeviceId = 0

    foreach ($State in $RunStates) {
        $BestOutput = Get-BestDetectionOutput -RunState $State
        $Parsed = ConvertFrom-BitLockerOutput -Output $BestOutput.Output

        $RunStateId = Get-PropertyValue -Object $State -PropertyNames @("id")
        $DeviceId = Get-ManagedDeviceIdFromRunStateId -RunStateId $RunStateId -ScriptId $RemediationId

        $DeviceName = Get-PropertyValue -Object $State -PropertyNames @(
            "deviceName",
            "managedDeviceName",
            "deviceDisplayName",
            "managedDeviceDeviceName"
        )

        if (-not [string]::IsNullOrWhiteSpace($BestOutput.Output)) {
            $WithOutput++
        }

        if (-not [string]::IsNullOrWhiteSpace($Parsed.EncryptionPercentage)) {
            $WithPercentage++
        }

        if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
            $WithManagedDeviceIdFromId++
            $Key = $DeviceId.ToLowerInvariant()

            $ResultsByDeviceId[$Key] = [pscustomobject]@{
                DiskEncryptionPercentage = $Parsed.EncryptionPercentage
                VolumeStatus             = $Parsed.VolumeStatus
                ProtectionStatus         = $Parsed.Protection
                ProtectionState          = $Parsed.ProtectionState
                EncryptionMethod         = $Parsed.EncryptionMethod
                MountPoint               = $Parsed.Drive
                KeyProtectors            = $Parsed.KeyProtectors
                ParseMethod              = $Parsed.ParseMethod
                OutputField              = $BestOutput.OutputField
                DetectionState           = Get-PropertyValue -Object $State -PropertyNames @("detectionState")
                RemediationState         = Get-PropertyValue -Object $State -PropertyNames @("remediationState")
                LastRunDateTime          = Get-PropertyValue -Object $State -PropertyNames @("lastStateUpdateDateTime")
                RunStateLastSync         = Get-PropertyValue -Object $State -PropertyNames @("lastSyncDateTime")
                RunStateId               = $RunStateId
                RawOutput                = $BestOutput.Output
            }

            $MappedByDeviceId++
        }

        if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
            $Key = $DeviceName.ToLowerInvariant()
            $ResultsByDeviceName[$Key] = $ResultsByDeviceId[$DeviceId.ToLowerInvariant()]
        }
    }

    Write-Host "Run states with detection output: $WithOutput" -ForegroundColor Green
    Write-Host "Run states with parsed encryption percentage: $WithPercentage" -ForegroundColor Green
    Write-Host "Run states with managedDeviceId parsed from runState id: $WithManagedDeviceIdFromId" -ForegroundColor Green
    Write-Host "Run states mapped by managedDeviceId: $MappedByDeviceId" -ForegroundColor Green

    return [pscustomobject]@{
        ByDeviceId   = $ResultsByDeviceId
        ByDeviceName = $ResultsByDeviceName
        Count        = $RunStates.Count
    }
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
    "isEncrypted",
    "totalStorageSpaceInBytes",
    "freeStorageSpaceInBytes"
) -join ","

$ManagedDevicesUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem%20eq%20'Windows'&`$select=$ManagedDeviceSelect&`$top=100"

$ManagedDevices = Invoke-GraphGetAll -Uri $ManagedDevicesUri

Write-Host "Windows managed devices found: $($ManagedDevices.Count)" -ForegroundColor Green

# ============================================================
# Retrieve supplemental encryption state
# ============================================================

Write-Host ""
Write-Host "Retrieving BitLocker / encryption supplemental states..." -ForegroundColor Cyan

$EncryptionStates = @()

try {
    $EncryptionUri = "https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$top=100"
    $EncryptionStates = Invoke-GraphGetAll -Uri $EncryptionUri -AllowFailure

    if ($EncryptionStates.Count -gt 0) {
        Write-Host "Encryption records found: $($EncryptionStates.Count)" -ForegroundColor Green
    }
    else {
        Write-Warning "No encryption records returned. The script will use isEncrypted from managedDevices as fallback."
    }
}
catch {
    Write-Warning "Could not retrieve encryption states. The script will use isEncrypted from managedDevices as fallback."
    Write-Warning $_.Exception.Message
}

$EncryptionByDeviceName = @{}
$EncryptionByManagedDeviceId = @{}

foreach ($Enc in $EncryptionStates) {
    $EncDeviceName = Normalize-Value $Enc.deviceName
    $EncManagedDeviceId = Normalize-Value $Enc.managedDeviceId

    if (-not [string]::IsNullOrWhiteSpace($EncDeviceName)) {
        $Key = $EncDeviceName.ToLowerInvariant()
        $EncryptionByDeviceName[$Key] = $Enc
    }

    if (-not [string]::IsNullOrWhiteSpace($EncManagedDeviceId)) {
        $Key = $EncManagedDeviceId.ToLowerInvariant()
        $EncryptionByManagedDeviceId[$Key] = $Enc
    }
}

# ============================================================
# Retrieve BitLocker remediation results
# ============================================================

$BitLockerRemediationResults = Get-BitLockerRemediationResults `
    -RemediationName $BitLockerRemediationName `
    -Top $BitLockerRunStateTop `
    -MaxRunStates $MaxBitLockerRunStates `
    -RawExportPath $BitLockerRawPath

$BitLockerRemediationByDeviceId = $BitLockerRemediationResults.ByDeviceId
$BitLockerRemediationByDeviceName = $BitLockerRemediationResults.ByDeviceName

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

    $OSInfo = Get-OSBuildInfo -OSVersion $Device.osVersion

    $Enc = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $EncryptionByManagedDeviceId.ContainsKey($DeviceIdKey)) {
        $Enc = $EncryptionByManagedDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $EncryptionByDeviceName.ContainsKey($DeviceKey)) {
        $Enc = $EncryptionByDeviceName[$DeviceKey]
    }

    $BitLockerRemediation = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $BitLockerRemediationByDeviceId.ContainsKey($DeviceIdKey)) {
        $BitLockerRemediation = $BitLockerRemediationByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $BitLockerRemediationByDeviceName.ContainsKey($DeviceKey)) {
        $BitLockerRemediation = $BitLockerRemediationByDeviceName[$DeviceKey]
    }

    $TotalGB = Convert-BytesToGB $Device.totalStorageSpaceInBytes
    $FreeGB  = Convert-BytesToGB $Device.freeStorageSpaceInBytes
    $FreePct = Get-Percent -Part $FreeGB -Total $TotalGB

    $EncryptionState = Convert-IsEncryptedToState -IsEncrypted $Device.isEncrypted
    $EncryptionReadinessState = ""
    $TPMVersion = ""
    $AdvancedBitLockerStates = ""
    $EncryptionStatusDetails = ""

    if ($Enc) {
        if (-not [string]::IsNullOrWhiteSpace((Normalize-Value $Enc.encryptionState))) {
            $EncryptionState = Normalize-Value $Enc.encryptionState
        }

        $EncryptionReadinessState = Normalize-Value $Enc.encryptionReadinessState
        $TPMVersion = Normalize-Value $Enc.tpmSpecificationVersion
        $AdvancedBitLockerStates = Normalize-Value $Enc.advancedBitLockerStates
        $EncryptionStatusDetails = Normalize-Value $Enc.statusDetails
    }

    $DiskEncryptionPercentage = ""
    $BitLockerVolumeStatus = ""
    $BitLockerProtectionStatus = ""
    $BitLockerProtectionState = ""
    $BitLockerEncryptionMethod = ""
    $BitLockerMountPoint = ""
    $BitLockerKeyProtectors = ""
    $BitLockerRemediationLastRun = ""
    $BitLockerRemediationState = ""
    $BitLockerOutputField = ""
    $BitLockerParseMethod = ""

    if ($BitLockerRemediation) {
        $DiskEncryptionPercentage = Normalize-Value $BitLockerRemediation.DiskEncryptionPercentage
        $BitLockerVolumeStatus = Normalize-Value $BitLockerRemediation.VolumeStatus
        $BitLockerProtectionStatus = Normalize-Value $BitLockerRemediation.ProtectionStatus
        $BitLockerProtectionState = Normalize-Value $BitLockerRemediation.ProtectionState
        $BitLockerEncryptionMethod = Normalize-Value $BitLockerRemediation.EncryptionMethod
        $BitLockerMountPoint = Normalize-Value $BitLockerRemediation.MountPoint
        $BitLockerKeyProtectors = Normalize-Value $BitLockerRemediation.KeyProtectors
        $BitLockerRemediationLastRun = Normalize-Value $BitLockerRemediation.LastRunDateTime
        $BitLockerRemediationState = Normalize-Value $BitLockerRemediation.RemediationState
        $BitLockerOutputField = Normalize-Value $BitLockerRemediation.OutputField
        $BitLockerParseMethod = Normalize-Value $BitLockerRemediation.ParseMethod
    }

    [pscustomobject]@{
        DeviceName                    = $DeviceName
        UserPrincipalName             = Normalize-Value $Device.userPrincipalName
        UserDisplayName               = Normalize-Value $Device.userDisplayName
        EmailAddress                  = Normalize-Value $Device.emailAddress

        ComplianceState               = Normalize-Value $Device.complianceState

        OperatingSystem               = Normalize-Value $Device.operatingSystem
        OSVersion                     = Normalize-Value $Device.osVersion
        OSFriendlyVersion             = $OSInfo.FriendlyVersion
        OSBuild                       = $OSInfo.Build
        OSUBR                         = $OSInfo.UBR
        OSVersionStatus               = $OSInfo.VersionStatus
        OSUBRStatus                   = $OSInfo.UBRStatus

        IsEncryptedRaw                = Normalize-Value $Device.isEncrypted
        BitLockerEncryptionState      = $EncryptionState
        DiskEncryptionPercentage      = $DiskEncryptionPercentage
        BitLockerVolumeStatus         = $BitLockerVolumeStatus
        BitLockerProtectionStatus     = $BitLockerProtectionStatus
        BitLockerProtectionState      = $BitLockerProtectionState
        BitLockerEncryptionMethod     = $BitLockerEncryptionMethod
        BitLockerMountPoint           = $BitLockerMountPoint
        BitLockerKeyProtectors        = $BitLockerKeyProtectors
        BitLockerRemediationLastRun   = $BitLockerRemediationLastRun
        BitLockerRemediationState     = $BitLockerRemediationState
        BitLockerOutputField          = $BitLockerOutputField
        BitLockerParseMethod          = $BitLockerParseMethod

        BitLockerReadinessState       = $EncryptionReadinessState
        TPMVersion                    = $TPMVersion
        AdvancedBitLockerStates       = $AdvancedBitLockerStates
        EncryptionStatusDetails       = $EncryptionStatusDetails

        Manufacturer                  = Normalize-Value $Device.manufacturer
        Model                         = Normalize-Value $Device.model
        SerialNumber                  = Normalize-Value $Device.serialNumber
        AzureADDeviceId               = Normalize-Value $Device.azureADDeviceId
        IntuneDeviceId                = Normalize-Value $Device.id

        ManagementAgent               = Normalize-Value $Device.managementAgent
        OwnerType                     = Normalize-Value $Device.managedDeviceOwnerType
        RegistrationState             = Normalize-Value $Device.deviceRegistrationState

        LastSyncDateTime              = Normalize-Value $Device.lastSyncDateTime
        EnrolledDateTime              = Normalize-Value $Device.enrolledDateTime

        TotalStorageGB                = $TotalGB
        FreeStorageGB                 = $FreeGB
        FreeStoragePercent            = $FreePct
    }
}

$Rows = @($Rows)

$RowsWithBitLockerPercent = @($Rows | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.DiskEncryptionPercentage)
}).Count

Write-Host "Rows with BitLocker disk encryption percentage: $RowsWithBitLockerPercent" -ForegroundColor Green

# ============================================================
# Export CSV and JSON
# ============================================================

$Rows |
    Sort-Object DeviceName |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$Rows |
    ConvertTo-Json -Depth 20 |
    Out-File -FilePath $JsonPath -Encoding UTF8

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

    .brand-left {
        display: flex;
        align-items: center;
        gap: 18px;
    }

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

    h1 {
        margin: 0;
        font-size: 30px;
        letter-spacing: -0.7px;
        color: #0f172a;
    }

    .subtitle {
        color: var(--muted);
        margin-top: 6px;
        font-size: 14px;
    }

    .generated {
        text-align: right;
        color: var(--muted);
        font-size: 13px;
        line-height: 1.5;
    }

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

    .card-value {
        font-size: 34px;
        font-weight: 800;
        margin-top: 8px;
        color: #0f172a;
    }

    .card-note {
        color: var(--muted);
        font-size: 13px;
        margin-top: 6px;
        line-height: 1.5;
    }

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

    .section h2 {
        margin: 0 0 14px 0;
        font-size: 20px;
        color: #0f172a;
    }

    .mini-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(260px, 1fr));
        gap: 16px;
    }

    .chart-card {
        display: grid;
        grid-template-columns: 150px 1fr;
        gap: 18px;
        align-items: center;
        min-height: 190px;
    }

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

    .legend {
        display: grid;
        gap: 8px;
        font-size: 13px;
        color: #334155;
    }

    .legend-row {
        display: grid;
        grid-template-columns: 12px 1fr auto;
        gap: 8px;
        align-items: center;
    }

    .dot {
        width: 11px;
        height: 11px;
        border-radius: 999px;
    }

    .dot.green { background: var(--green); }
    .dot.red { background: var(--red); }
    .dot.orange { background: var(--orange); }
    .dot.gray { background: var(--gray); }
    .dot.blue { background: var(--blue); }
    .dot.purple { background: var(--purple); }
    .dot.cyan { background: var(--cyan); }

    .toolbar {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 14px;
    }

    input, select, button {
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

    button {
        cursor: pointer;
        background: #0f172a;
        color: #ffffff;
        border-color: #0f172a;
        font-weight: 600;
    }

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

    .filter-label input {
        box-shadow: none;
        border-radius: 8px;
        padding: 8px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }

    th {
        text-align: left;
        color: #334155;
        background: #eef4fb;
        position: sticky;
        top: 0;
        z-index: 2;
        font-weight: 700;
    }

    th, td {
        padding: 10px;
        border-bottom: 1px solid #e5edf5;
        vertical-align: top;
        white-space: nowrap;
    }

    tr:hover { background: #f8fafc; }

    .table-wrap {
        overflow: auto;
        max-height: 720px;
        border: 1px solid var(--border);
        border-radius: 16px;
        background: #ffffff;
    }

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

    .pill.good {
        background: var(--green-soft);
        border-color: #86efac;
        color: #166534;
    }

    .pill.bad {
        background: var(--red-soft);
        border-color: #fca5a5;
        color: #991b1b;
    }

    .pill.warn {
        background: var(--orange-soft);
        border-color: #fcd34d;
        color: #92400e;
    }

    footer {
        color: var(--muted);
        padding: 20px 34px 35px 34px;
        font-size: 12px;
    }

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
            <div class="card-title">Encrypted</div>
            <div class="card-value good" id="cardEncrypted">0</div>
            <div class="card-note" id="cardEncryptedNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">Avg Disk Encryption</div>
            <div class="card-value info" id="cardAvgDiskEncryption">N/A</div>
            <div class="card-note" id="cardAvgDiskEncryptionNote">From remediation output</div>
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
                <div class="pie" id="pieCompliance">
                    <div class="pie-center" id="pieComplianceCenter">0%</div>
                </div>
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
                <div class="pie" id="pieEncryption">
                    <div class="pie-center" id="pieEncryptionCenter">0%</div>
                </div>
                <div>
                    <div class="card-title">Encryption</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot green"></span><span>Encrypted</span><strong id="legendEncrypted">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot red"></span><span>Not encrypted</span><strong id="legendNotEncrypted">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Unknown</span><strong id="legendEncryptionUnknown">0 / 0%</strong></div>
                    </div>
                </div>
            </div>

            <div class="card chart-card">
                <div class="pie" id="pieOS">
                    <div class="pie-center" id="pieOSCenter">0%</div>
                </div>
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

            <select id="complianceFilter" onchange="renderDashboard()">
                <option value="">All compliance states</option>
                <option value="compliant">Compliant</option>
                <option value="noncompliant">Non-compliant</option>
                <option value="unknown">Unknown</option>
                <option value="inGracePeriod">In grace period</option>
                <option value="configManager">Config Manager</option>
            </select>

            <select id="encryptionFilter" onchange="renderDashboard()">
                <option value="">All encryption states</option>
                <option value="encrypted">Encrypted</option>
                <option value="notEncrypted">Not encrypted</option>
                <option value="unknown">Unknown / blank</option>
            </select>

            <select id="diskEncryptionFilter" onchange="renderDashboard()">
                <option value="">All disk encryption %</option>
                <option value="100">100%</option>
                <option value="below100">Below 100%</option>
                <option value="missing">Missing remediation result</option>
            </select>

            <select id="osFilter" onchange="renderDashboard()">
                <option value="">All OS branches</option>
                <option value="26100">Windows 11 24H2 / 26100</option>
                <option value="26200">Windows 11 25H2 / 26200</option>
                <option value="older">Older than 26100</option>
                <option value="newer">Newer than 26200</option>
                <option value="belowtarget">Below UBR target</option>
            </select>

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

            <label class="filter-label">
                From
                <input id="lastSyncFrom" type="date" onchange="renderDashboard()">
            </label>

            <label class="filter-label">
                To
                <input id="lastSyncTo" type="date" onchange="renderDashboard()">
            </label>

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
                        <th>Email</th>
                        <th>Compliance</th>
                        <th>OS</th>
                        <th>OS Version</th>
                        <th>Build</th>
                        <th>UBR</th>
                        <th>UBR Status</th>
                        <th>Encryption</th>
                        <th>Disk Encryption %</th>
                        <th>Drive</th>
                        <th>Volume Status</th>
                        <th>Protection</th>
                        <th>Protectors</th>
                        <th>BL Last Run</th>
                        <th>Readiness</th>
                        <th>TPM</th>
                        <th>Status Details</th>
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
    Disk encryption percentage is populated from Intune remediation: $BitLockerRemediationName. Raw run states are exported beside this report.
</footer>

<script>
const dashboardDataBase64 = "$DashboardDataBase64";

const devices = JSON.parse(
    new TextDecoder().decode(
        Uint8Array.from(atob(dashboardDataBase64), function(c) {
            return c.charCodeAt(0);
        })
    )
);

const totalDeviceCount = devices.length;

function escapeHtml(value) {
    if (value === null || value === undefined) return "";

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
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

    if (current < 360) {
        parts.push("var(--gray) " + current + "deg 360deg");
    }

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

    if (type === "encryption") {
        if (clean.toLowerCase() === "encrypted") cls += " good";
        else if (clean.toLowerCase() === "notencrypted") cls += " bad";
        else cls += " warn";
    }

    if (type === "ubr") {
        if (clean.toLowerCase() === "ok") cls += " good";
        else if (clean.toLowerCase() === "below target") cls += " bad";
        else cls += " warn";
    }

    return '<span class="' + cls + '">' + escapeHtml(clean) + '</span>';
}

function parsePercent(value) {
    if (value === null || value === undefined) return null;

    const cleaned = String(value).replace(/[^0-9.]/g, "");
    if (!cleaned) return null;

    const n = Number(cleaned);
    if (isNaN(n)) return null;

    return n;
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
    document.getElementById("complianceFilter").value = "";
    document.getElementById("encryptionFilter").value = "";
    document.getElementById("diskEncryptionFilter").value = "";
    document.getElementById("osFilter").value = "";
    document.getElementById("lastSyncPreset").value = "";
    document.getElementById("lastSyncFrom").value = "";
    document.getElementById("lastSyncTo").value = "";
    renderDashboard();
}

function getFilteredDevices() {
    const search = document.getElementById("searchBox").value.toLowerCase();
    const compliance = document.getElementById("complianceFilter").value;
    const encryption = document.getElementById("encryptionFilter").value;
    const diskEncryption = document.getElementById("diskEncryptionFilter").value;
    const os = document.getElementById("osFilter").value;

    return devices.filter(function(d) {
        const blob = Object.values(d).join(" ").toLowerCase();

        if (search && !blob.includes(search)) return false;

        if (compliance && String(d.ComplianceState || "").toLowerCase() !== compliance.toLowerCase()) return false;

        if (encryption) {
            const enc = String(d.BitLockerEncryptionState || "unknown").toLowerCase();

            if (encryption === "unknown") {
                if (enc !== "" && enc !== "unknown") return false;
            }
            else if (enc !== encryption.toLowerCase()) {
                return false;
            }
        }

        if (diskEncryption) {
            const p = parsePercent(d.DiskEncryptionPercentage);

            if (diskEncryption === "100" && p !== 100) return false;
            if (diskEncryption === "below100" && (p === null || p >= 100)) return false;
            if (diskEncryption === "missing" && p !== null) return false;
        }

        if (os) {
            const build = Number(d.OSBuild);

            if (os === "26100" && build !== 26100) return false;
            if (os === "26200" && build !== 26200) return false;
            if (os === "older" && !(build < 26100)) return false;
            if (os === "newer" && !(build > 26200)) return false;
            if (os === "belowtarget" && String(d.OSUBRStatus || "").toLowerCase() !== "below target") return false;
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

    const encrypted = rows.filter(function(d) { return String(d.BitLockerEncryptionState || "").toLowerCase() === "encrypted"; }).length;
    const notEncrypted = rows.filter(function(d) { return String(d.BitLockerEncryptionState || "").toLowerCase() === "notencrypted"; }).length;
    const encryptionUnknown = total - encrypted - notEncrypted;

    const build26100 = rows.filter(function(d) { return Number(d.OSBuild) === 26100; }).length;
    const build26200 = rows.filter(function(d) { return Number(d.OSBuild) === 26200; }).length;
    const older = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) < 26100; }).length;
    const newer = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) > 26200; }).length;
    const osUnknown = total - build26100 - build26200 - older - newer;

    const belowTarget = rows.filter(function(d) { return String(d.OSUBRStatus || "").toLowerCase() === "below target"; }).length;

    const diskPercentValues = rows
        .map(function(d) { return parsePercent(d.DiskEncryptionPercentage); })
        .filter(function(v) { return v !== null; });

    let avgDiskEncryption = "N/A";

    if (diskPercentValues.length > 0) {
        const sum = diskPercentValues.reduce(function(a, b) { return a + b; }, 0);
        avgDiskEncryption = (Math.round((sum / diskPercentValues.length) * 10) / 10) + "%";
    }

    setText("cardTotalDevices", total);
    setText("cardTotalNote", "Showing " + total + " of " + totalDeviceCount + " devices");

    setText("cardCompliant", compliant);
    setText("cardCompliantNote", pct(compliant, total) + "% of filtered devices");

    setText("cardNonCompliant", nonCompliant);
    setText("cardNonCompliantNote", pct(nonCompliant, total) + "% of filtered devices");

    setText("cardEncrypted", encrypted);
    setText("cardEncryptedNote", pct(encrypted, total) + "% of filtered devices");

    setText("cardAvgDiskEncryption", avgDiskEncryption);
    setText("cardAvgDiskEncryptionNote", "Based on " + diskPercentValues.length + " remediation results");

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

    setText("legendEncrypted", encrypted + " / " + pct(encrypted, total) + "%");
    setText("legendNotEncrypted", notEncrypted + " / " + pct(notEncrypted, total) + "%");
    setText("legendEncryptionUnknown", encryptionUnknown + " / " + pct(encryptionUnknown, total) + "%");
    setText("pieEncryptionCenter", pct(encrypted, total) + "%");

    setPie("pieEncryption", [
        { color: "var(--green)", degrees: deg(encrypted, total) },
        { color: "var(--red)", degrees: deg(notEncrypted, total) },
        { color: "var(--gray)", degrees: deg(encryptionUnknown, total) }
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

    document.getElementById("visibleCount").innerText =
        "Showing " + rows.length + " of " + devices.length + " devices";

    tbody.innerHTML = rows.map(function(d) {
        return "" +
            "<tr>" +
            "<td>" + escapeHtml(d.DeviceName) + "</td>" +
            "<td>" + escapeHtml(d.UserDisplayName || d.UserPrincipalName) + "</td>" +
            "<td>" + escapeHtml(d.EmailAddress) + "</td>" +
            "<td>" + pill(d.ComplianceState, "compliance") + "</td>" +
            "<td>" + escapeHtml(d.OSFriendlyVersion) + "</td>" +
            "<td>" + escapeHtml(d.OSVersion) + "</td>" +
            "<td>" + escapeHtml(d.OSBuild) + "</td>" +
            "<td>" + escapeHtml(d.OSUBR) + "</td>" +
            "<td>" + pill(d.OSUBRStatus, "ubr") + "</td>" +
            "<td>" + pill(d.BitLockerEncryptionState, "encryption") + "</td>" +
            "<td>" + escapeHtml(d.DiskEncryptionPercentage) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerMountPoint) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerVolumeStatus) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerProtectionStatus) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerKeyProtectors) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerRemediationLastRun) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerReadinessState) + "</td>" +
            "<td>" + escapeHtml(d.TPMVersion) + "</td>" +
            "<td>" + escapeHtml(d.EncryptionStatusDetails) + "</td>" +
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
}

function downloadVisibleCsv() {
    const rows = getFilteredDevices();

    if (!rows.length) {
        alert("No rows to export.");
        return;
    }

    const headers = Object.keys(rows[0]);

    const csv = [
        headers.join(","),
        ...rows.map(function(row) {
            return headers.map(function(h) {
                const value = row[h] === null || row[h] === undefined ? "" : String(row[h]);
                return '"' + value.replaceAll('"', '""') + '"';
            }).join(",");
        })
    ].join("\\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "Intune-Dashboard-Visible-Devices.csv";
    a.click();

    URL.revokeObjectURL(url);
}

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
