#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation detection script for Windows cumulative update compliance.

.DESCRIPTION
    Checks the current Windows build branch and UBR against configured minimum values.

.EXIT CODES
    0 = compliant
    1 = non-compliant or detection error
#>

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
$LogFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath   = Join-Path $LogFolder "WindowsUpdate-Compliance-Detect.log"

$MinimumRequiredQualityByBuild = @{
    '26100' = 7462
    '26200' = 7462
    '26300' = 7462
}

$AllowHigherBuildBranches = $false

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
function Initialize-Logging {
    try {
        if (-not (Test-Path -Path $LogFolder)) {
            New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
        }

        if (-not (Test-Path -Path $LogPath)) {
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
        }
    }
    catch {
        Write-Output "Logging init failed: $($_.Exception.Message)"
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp - $Message"

    Write-Output $line

    try {
        Add-Content -Path $LogPath -Value $line -ErrorAction Stop
    }
    catch {
        Write-Output "$timestamp - LOG WRITE FAILED: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
function Get-OSBuildInfo {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop

        return [PSCustomObject]@{
            ProductName    = $cv.ProductName
            DisplayVersion = $cv.DisplayVersion
            CurrentBuild   = [int]$cv.CurrentBuildNumber
            UBR            = [int]$cv.UBR
            FullVersion    = "10.0.$($cv.CurrentBuildNumber).$($cv.UBR)"
        }
    }
    catch {
        throw "Unable to read OS version from registry: $($_.Exception.Message)"
    }
}

function Test-QualityCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$CurrentOS
    )

    $currentBuildString = [string]$CurrentOS.CurrentBuild
    $currentUBR = [int]$CurrentOS.UBR

    Write-Log "Current build string: $currentBuildString"
    Write-Log "Current UBR: $currentUBR"

    if ($MinimumRequiredQualityByBuild.ContainsKey($currentBuildString)) {
        $requiredUBR = [int]$MinimumRequiredQualityByBuild[$currentBuildString]

        Write-Log "Matched configured build branch: $currentBuildString"
        Write-Log "Required UBR for build $currentBuildString : $requiredUBR"

        if ($currentUBR -ge $requiredUBR) {
            return @{
                Compliant     = $true
                Reason        = "OK"
                RequiredBuild = $currentBuildString
                RequiredUBR   = $requiredUBR
            }
        }
        else {
            return @{
                Compliant     = $false
                Reason        = "UBR_TOO_LOW"
                RequiredBuild = $currentBuildString
                RequiredUBR   = $requiredUBR
            }
        }
    }

    $configuredBuilds = @($MinimumRequiredQualityByBuild.Keys | ForEach-Object { [int]$_ } | Sort-Object)
    $highestConfiguredBuild = $configuredBuilds | Select-Object -Last 1
    $fallbackRequiredUBR = [int]$MinimumRequiredQualityByBuild[[string]$highestConfiguredBuild]

    Write-Log "Build $currentBuildString not found directly in configured branches"

    if ($AllowHigherBuildBranches -and ([int]$CurrentOS.CurrentBuild -gt $highestConfiguredBuild)) {
        Write-Log "Higher build branch logic enabled. Highest configured build: $highestConfiguredBuild, fallback required UBR: $fallbackRequiredUBR"

        if ($currentUBR -ge $fallbackRequiredUBR) {
            return @{
                Compliant     = $true
                Reason        = "HIGHER_BRANCH_OK"
                RequiredBuild = [string]$highestConfiguredBuild
                RequiredUBR   = $fallbackRequiredUBR
            }
        }
        else {
            return @{
                Compliant     = $false
                Reason        = "HIGHER_BRANCH_UBR_TOO_LOW"
                RequiredBuild = [string]$highestConfiguredBuild
                RequiredUBR   = $fallbackRequiredUBR
            }
        }
    }

    return @{
        Compliant     = $false
        Reason        = "WRONG_BRANCH"
        RequiredBuild = $null
        RequiredUBR   = $null
    }
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
Initialize-Logging
Write-Log "===== DETECTION SCRIPT START ====="
Write-Log "SCRIPT VERSION: 2026-03-30 DETECTION-V1"

try {
    if (-not $MinimumRequiredQualityByBuild -or $MinimumRequiredQualityByBuild.Count -eq 0) {
        throw "No minimum required build/quality mappings are configured."
    }

    $configuredBuildsText = (($MinimumRequiredQualityByBuild.GetEnumerator() |
        Sort-Object Name |
        ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')

    Write-Log "Configured minimum required quality by build: $configuredBuildsText"
    Write-Log "Allow higher build branches: $AllowHigherBuildBranches"

    $osInfo = Get-OSBuildInfo
    Write-Log "Detected OS: ProductName='$($osInfo.ProductName)', DisplayVersion='$($osInfo.DisplayVersion)', FullVersion='$($osInfo.FullVersion)'"

    $complianceResult = Test-QualityCompliance -CurrentOS $osInfo

    Write-Log "Returned compliance object: Compliant='$($complianceResult.Compliant)' Reason='$($complianceResult.Reason)' RequiredBuild='$($complianceResult.RequiredBuild)' RequiredUBR='$($complianceResult.RequiredUBR)'"

    if ([bool]$complianceResult.Compliant -eq $true) {
        Write-Log "STATUS: COMPLIANT - current OS version '$($osInfo.FullVersion)' meets required minimum."
        Write-Output "Compliant: $($osInfo.FullVersion)"
        Write-Log "===== DETECTION SCRIPT END ====="
        exit 0
    }

    switch ($complianceResult.Reason) {
        "UBR_TOO_LOW" {
            Write-Log "STATUS: NON-COMPLIANT - current OS version '$($osInfo.FullVersion)' is below required minimum 10.0.$($complianceResult.RequiredBuild).$($complianceResult.RequiredUBR)."
            Write-Output "Non-compliant: current version $($osInfo.FullVersion), required minimum 10.0.$($complianceResult.RequiredBuild).$($complianceResult.RequiredUBR)"
        }
        "HIGHER_BRANCH_UBR_TOO_LOW" {
            Write-Log "STATUS: NON-COMPLIANT - higher unconfigured build branch but below fallback minimum 10.0.$($complianceResult.RequiredBuild).$($complianceResult.RequiredUBR)."
            Write-Output "Non-compliant: higher build branch, but UBR too low"
        }
        "WRONG_BRANCH" {
            $allowedBranches = @()
            foreach ($key in ($MinimumRequiredQualityByBuild.Keys | Sort-Object)) {
                $allowedBranches += "10.0.$key.$($MinimumRequiredQualityByBuild[$key])"
            }

            Write-Log "STATUS: NON-COMPLIANT - current OS version '$($osInfo.FullVersion)' is not on an allowed build branch. Allowed minimum versions: $($allowedBranches -join ', ')"
            Write-Output "Non-compliant: wrong build branch. Allowed minimum versions: $($allowedBranches -join ', ')"
        }
        default {
            Write-Log "STATUS: NON-COMPLIANT - Reason: $($complianceResult.Reason)"
            Write-Output "Non-compliant: $($complianceResult.Reason)"
        }
    }

    Write-Log "===== DETECTION SCRIPT END ====="
    exit 1
}
catch {
    $errorMessage = "FATAL ERROR: $($_.Exception.Message)"
    $errorDetails = "Error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.GetType().FullName)"

    Write-Log $errorMessage
    Write-Log $errorDetails
    Write-Output $errorMessage
    Write-Log "===== DETECTION SCRIPT END ====="

    exit 1
}
