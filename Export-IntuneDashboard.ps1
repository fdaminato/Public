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
      - Storage
      - User / model / serial
      - Last check-in filtering
      - Dynamic quick cards and charts

.REQUIREMENTS
    PowerShell 7 recommended
    Microsoft.Graph.Authentication

.PERMISSIONS
    DeviceManagementManagedDevices.Read.All
    DeviceManagementScripts.Read.All
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

    [string]$BitLockerRemediationName = "Monitoring - Detection - Bitlocker - Get status",

    [int]$MaxBitLockerRunStates = 3500,

    [int]$MaxDefenderDetailQueries = 5000,

    [string]$RebootPendingRemediationName = "Monitoring - Detection - RebootPending - Get status",

    [string]$FirmwareInventoryRemediationName = "Monitoring - Detection - Firmware - Get status",

    [int]$MaxInventoryRunStates = 5000,

    [string]$LenovoSecureBootBiosCsvPath,

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
$SecureBootRawPath = Join-Path $OutputFolder "Intune-SecureBoot-Simple-Raw-$Timestamp.json"
$BitLockerRawPath = Join-Path $OutputFolder "Intune-BitLocker-Remediation-Raw-$Timestamp.json"
$DeviceEncryptionRawPath = Join-Path $OutputFolder "Intune-DeviceEncryption-Report-Raw-$Timestamp.json"
$DefenderRawPath = Join-Path $OutputFolder "Intune-Defender-WindowsProtectionState-Raw-$Timestamp.json"
$RebootPendingRawPath = Join-Path $OutputFolder "Intune-RebootPending-Remediation-Raw-$Timestamp.json"
$FirmwareInventoryRawPath = Join-Path $OutputFolder "Intune-FirmwareInventory-Remediation-Raw-$Timestamp.json"
$AutopilotRawPath = Join-Path $OutputFolder "Intune-AutopilotDevices-Raw-$Timestamp.json"
$LenovoSecureBootBiosRawPath = Join-Path $OutputFolder "Lenovo-SecureBoot2023-BIOS-Requirements-Raw-$Timestamp.json"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Intune Windows Dashboard Export" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output folder: $OutputFolder"
Write-Host ""

$EmbeddedLenovoSecureBoot2023BiosCsv = @'
Product,Model,Minimum BIOS version (1.xx)
11e 5th Gen,"20LQ, 20LR",R1DET31W (v1.24)
11e Yoga Gen 6,"20SE, 20SF",R18ET34W (v1.18)
E14 Gen 2,"20TA, 20TB",R1EET63W (v1.63)
E14 Gen 2,"20T6, 20T7",R1AET55W (v1.31)
E14 Gen 3 AMD,"20YG, 20YH, 20YJ, 20YK",R1OET45W (v1.24)
E14 Gen 4,"21E3, 21E4",R1SET62W (v1.33)
E14 Gen 4 AMD,"21EB, 21EC",R20ET40W (v1.20)
E14 Gen 5,"21JK, 21JL",R2AET61W (v1.36)
E14 Gen 5 AMD,"21JR, 21JS",R2CET40W (v1.22)
E14 Gen 6,"21M7, 21M8",R2JET39W (v1.16)
E14 Gen 6 AMD,"21M3, 21M4",R2KET29W (v1.12)
E15 Gen 2,"20TD, 20TE",R1EET63W (v1.63)
E15 Gen 2,"20T8, 20T9",R1AET55W (v1.31)
E15 Gen 3 AMD,"20YG, 20YH, 20YJ, 20YK",R1OET45W (v1.24)
E15 Gen 4,"21E6, 21E7",R1SET62W (v1.33)
E15 Gen 4 AMD,"21ED, 21EE",R20ET40W (v1.20)
E16 Gen 1 AMD,"21JT, 21JU",R2CET40W (v1.22)
E16 Gen 1 Intel,"21JN, 21JQ",R2AET61W (v1.36)
E16 Gen 2 AMD,"21M5, 21M6",R2KET29W (v1.12)
E16 Gen 2 Intel,"21MA, 21MB",R2JET39W (v1.16)
E490,"20N8, 20N9",R0YET55W (v1.38)
E490s,20NG,R0YET55W (v1.38)
E495,20NE,R11ET50W (v1.30)
E590,"20NB, 20NC",R0YET55W (v1.38)
E595,20NF,R11ET50W (v1.30)
L13,"20R3, 20R4",R15ET60W (v1.41)
L13 2-in-1 Gen 5,"21LM, 21LN",R2GET25W (v1.07)
L13 Gen 2 AMD,"21AB, 21AC",R1QET52W (v1.38)
L13 Gen 2 non-vPro,"20VH, 20VJ",R1FET57W (v1.31)
L13 Gen 2 vPro,"20VH, 20VJ",R1PET37W (v1.29)
L13 Gen 3,"21B3, 21B4",R1UET46W (v1.23)
L13 Gen 3 AMD,"21B9, 21BA",R1TET46W (v1.25)
L13 Gen 4,"21FN, 21FQ",R26ET37W (v1.15)
L13 Gen 4,"21FG, 21FH",R27ET32W (v1.17)
L13 Gen 5,"21LB, 21LC",R2GET25W (v1.07)
L13 Yoga,"20R5, 20R6",R15ET60W (v1.41)
L13 Yoga Gen 2 AMD,"21AD, 21AE",R1QET52W (v1.38)
L13 Yoga Gen 2 non-vPro,"20VK, 20VL",R1FET57W (v1.31)
L13 Yoga Gen 2 vPro,"20VK, 20VL",R1PET37W (v1.29)
L13 Yoga Gen 3,"21B5, 21B6",R1UET46W (v1.23)
L13 Yoga Gen 3 AMD,"21BB, 21BC",R1TET46W (v1.25)
L13 Yoga Gen 4,"21FR, 21FS",R26ET37W (v1.15)
L13 Yoga Gen 4,"21FJ, 21FK",R27ET32W (v1.17)
L14 Gen 1,"20U1, 20U2",R17ET41W (v1.24)
L14 Gen 1 AMD,"20U5, 20U6",R19ET55W (v1.39)
L14 Gen 2,"20X1, 20X2",R1JET69W (v1.69)
L14 Gen 2 AMD,"20X5, 20X6",R1KET50W (v1.35)
L14 Gen 3 AMD,"21C5, 21C6",R1YET54W (v1.31)
L14 Gen 4,"21H5, 21H6",R25ET35W (v1.16)
L14 Gen 4,"21H1, 21H2",R24ET38W (v1.21)
L14 Gen 5,"21L1, 21L2",R2HET29W (v1.08)
L14 Gen 5 AMD,"21L5, 21L6",R2IET32W (v1.32) 
L14 Gen3,"21C1, 21C2",R1XET53W (v1.35)
L15 Gen 1,"20U3, 20U4",R17ET41W (v1.24)
L15 Gen 1 AMD,"20U7, 20U8",R19ET55W (v1.39)
L15 Gen 2,"20X3, 20X4",R1JET69W (v1.69)
L15 Gen 2 AMD,"20X7, 20X8",R1KET50W (v1.35)
L15 Gen 3 AMD,"21C7, 21C8",R1YET54W (v1.31)
L15 Gen 4,"21H7, 21H8",R25ET35W (v1.16)
L15 Gen 4,"21H3, 21H4",R24ET38W (v1.21)
L15 Gen3,"21C3, 21C4",R1XET53W (v1.35)
L16 Gen 1,"21L3, 21L4",R2HET29W (v1.08)
L16 Gen1 AMD,"21L7, 21L8",R2IET30W (v1.30) 
L380,"20M5, 20M6",R0RET53W (v1.35)
L380 Yoga,"20M7, 20M8",R0RET53W (v1.35)
L390,"20NR, 20NS",R10ET61W (v1.46)
L490,"20Q5, 20Q6",R0ZET60W (v1.38)
L590,"20Q7, 20Q8",R0ZET60W (v1.38)
P1,"20MD, 20ME",N2EET64W (v1.46)
P1 Gen 2,"20QT, 20QU",N2OET63W (v1.50)
P1 Gen 3,"20TH, 20TJ",N2VET47W (v1.32)
P1 Gen 4,"20Y3, 20Y4",N40ET45W (v1.27)
P1 Gen 5,"21DC, 21DD",N3JET38W (v1.22)
P1 Gen 6,"21FV, 21FW",N3ZET33W (v1.20)
P1 Gen 7,"21KV, 21KW",N48ET11W (v0.08)
P14s Gen 1 AMD,"20Y1, 20Y2",R1BET85W (v1.54)
P14s Gen 2,"20VX, 20VY",N3WET21W (v1.13)
P14s Gen 2,"20VX, 20VY",N34ET61W (v1.61)
P14s Gen 2 AMD,"21A0, 21A1",R1MET63W (v1.33)
P14s Gen 3,"21AK, 21AL",N3BET60W (v1.38)
P14s Gen 3 AMD,"21J5, 21J6",R23ET86W (v1.62)
P14s Gen 4,"21HF, 21HG",N3QET44W (v1.44)
P14s Gen 5,"21G2, 21G3",R2DET39W (v1.24)
P14s Gen 5 AMD,"21ME, 21MF",R2LET35W (v1.16)
P14s Gen4 AMD,"21K5, 21K6",R2FET65W (v1.45)
P15 Gen 1,"20ST, 20SU",N30ET53W (v1.36)
P15 Gen 2,"20YQ, 20YR",N37ET52W (v1.33)
P15s Gen 2,"20W6, 20W7",N34ET61W (v1.61)
P15s Gen 2,"20W6, 20W7",N3WET21W (v1.13)
P15v Gen 1,"20TQ, 20TR",N30ET53W (v1.36)
P15v Gen 3,"21D8, 21D9",N3EET39W (v1.25)
P15v Gen2,"21A9, 21AA",N38ET45W (v1.26)
P15v Gen3 AMD,"21EM, 21EN",N3KET42W (v1.20)
P16 Gen 1,"21D6, 21D7",N3FET43W (v1.28)
P16 Gen 2,"21FA, 21FB",N3TET56W (v1.56)
P16s Gen 1,"21BT, 21BU",N3MET19W (v1.18)
P16s Gen 1 AMD,"21CK, 21CL",R23ET86W (v1.62)
P16s Gen 2,"21HK, 21HL",N3QET44W (v1.44)
P16s Gen 3,"21KS, 21KT",R2DET39W (v1.24)
P16s Gen2 AMD,"21K9, 21KA",R2FET65W (v1.45)
P16v Gen 1,"21FE, 21FF",N3VET50W (v1.50)
P16v Gen 1 ,"21FC, 21FD",N3UET30W (v1.30)
P16v Gen 2 ,"21KX, 21KY",N44ET18W (v1.01)
P17 Gen 1,"20SN, 20SQ",N30ET53W (v1.36)
P17 Gen 2,"20YU, 20YV",N37ET52W (v1.33)
P43s,"20RH, 20RJ",N2IETA4W (v1.82)
P52,"20M9, 20MA",N2CET70W (v1.53)
P52s,"20LB, 20LC",N27ET53W (v1.39)
P53,"20QN, 20QQ",N2NET59W (v1.44)
P53s,"20N6, 20N7",N2IETA4W (v1.82)
P72,"20MB, 20MC",N2CET70W (v1.53)
P73,"20QR, 20QS",N2NET59W (v1.44)
S2 Gen 3,20L1,R0RET53W (v1.35)
S2 Gen 4,20NV,R10ET61W (v1.46)
S2 Gen 9,21LQ,R2GET25W (v1.07)
T14 Gen 1,"20S0, 20S1",N2XET41W (v1.31)
T14 Gen 1 AMD,"20UD, 20UE",R1BET85W (v1.54)
T14 Gen 2,"20W0, 20W1",N34ET61W (v1.61)
T14 Gen 2 AMD,"20XK, 20XL",R1MET63W (v1.33)
T14 Gen 3,"21AH, 21AJ",N3BET60W (v1.38)
T14 Gen 3 AMD,"21CF, 21CG",R23ET86W (v1.62)
T14 Gen 4,"21HD, 21HE",N3QET44W (v1.44)
T14 Gen 4 AMD,"21K3, 21K4",R2FET65W (v1.45)
T14 Gen 5,"21ML, 21MM",N47ET12W (v1.01)
T14 Gen 5 AMD,"21MC, 21MD",R2LET35W (v1.16)
T14p Gen 2,21KU,R2DET39W (v1.24)
T14s Gen 1,"20T0, 20T1",N2YET47W (v1.36)
T14s Gen 1 AMD,"20UH, 20UJ",R1CET85W (v1.54)
T14s Gen 2,"20WM, 20WN",N35ET58W (v1.58)
T14s Gen 2 AMD,"20XF, 20XG",R1NET66W (v1.36)
T14s Gen 3,"21BR, 21BS",N3CET62W (v1.43)
T14s Gen 3 AMD,"21CQ, 21CR",R22ET80W (v1.50)
T14s Gen 4 ,"21F6, 21F7",N3PET24W (v1.15)
T14s Gen 4 AMD,"21F8, 21F9",R2EET45W (v1.26)
T14s Gen 5 ,"21LS, 21LT",N46ET15W (v1.05)
T14s Gen 6,"21N1, 21N2",N3YET58W (v1.23)
T14s Gen 6 AMD,"21M1, 21M2",R2NET41W (v1.15)
T15 Gen 1,"20S6, 20S7",N2XET41W (v1.31)
T15 Gen 2,"20W4, 20W5",N3WET21W (v1.13)
T15g Gen 1,"20UR, 20US",N30ET53W (v1.36)
T15g Gen 2,"20YS, 20YT",N37ET52W (v1.33)
T15p Gen 1,"20TN, 20TM",N30ET53W (v1.36)
T15p Gen 3,"21DA, 21DB",N3EET39W (v1.25)
T16 Gen 1,"21BV, 21BW",N3MET19W (v1.18)
T16 Gen 1 AMD,"21CH, 21CJ",R23ET86W (v1.62)
T16 Gen 2,"21HH, 21HJ",N3QET44W (v1.44)
T16 Gen2 AMD,"21K7, 21K8",R2FET65W (v1.45)
T16 Gen3,"21MN, 21MQ",N47ET12W (v1.01)
T480,"20L5, 20L6",N24ET76W (v1.51)
T480s,"20L7, 20L8",N22ET80W (v1.57)
T490,"20N2, 20N3, 20Q9, 20QH",N2IETA4W (v1.82)
T490 CML,"20RY, 20RX",N2RET30W (v1.24)
T490s,"20NX, 20NY",N2JETA8W (v1.86)
T495 AMD,"20NJ, 20NK",R12ET66W (v1.36)
T495s AMD,"20QJ, 20QK",R13ET58W (v1.32)
T580,"20L9, 20LA",N27ET53W (v1.39)
T590,"20N4, 20N5",N2IETA4W (v1.82)
X1 2-in-1 Gen 9,"21KE, 21KF",N3YET58W (v1.23)
X1 Carbon Gen 10,"21CB, 21CC",N3AET80W (v1.45)
X1 Carbon Gen 11,"21HM, 21HN",N3XET51W (v1.26)
X1 Carbon Gen 12,"21KC, 21KD",N3YET58W (v1.23)
X1 Carbon Gen 6,"20KH, 20KG",N23ET88W (v1.63)
X1 Carbon Gen 7,"20R1, 20R2",N2QET55W (v1.49)
X1 Carbon Gen 7,"20QD, 20QE",N2HET77W (v1.60)
X1 Carbon Gen 8,"20U9, 20UA",N2WET45W (v1.35)
X1 Carbon Gen 9,"20XW, 20XX",N32ET91W (v1.67)
X1 Extreme,"20MF, 20MG",N2EET64W (v1.46)
X1 Extreme Gen 2,"20QV, 20QW",N2OET63W (v1.50)
X1 Extreme Gen 3,"20TK, 20TL",N2VET47W (v1.32)
X1 Extreme Gen 4,"20Y5, 20Y6",N40ET45W (v1.27)
X1 Extreme Gen 5,"21DE, 21DF",N3JET38W (v1.22)
X1 Fold 16 Gen 1,"21ES, 21ET",N3LET38W (v1.19)
X1 Fold Gen 1,"20RK, 20RL",N2PET58W (v1.30)
X1 Nano Gen 1,"20UN, 20UQ",N2TET84W (v1.62)
X1 Nano Gen 2,"21E8, 21E9",N3IET45W (v1.25)
X1 Nano Gen 3,"21K1, 21K2",N3NET33W (v1.17)
X1 Tablet Gen 3,"20KJ, 20KK",N1ZET95W (v1.51)
X1 Titanium,"20QA, 20QB",N2MET66W (v1.31)
X1 Yoga Gen 3,"20LD, 20LE, 20LF, 20LG",N25ET67W (v1.53)
X1 Yoga Gen 4,"20SA, 20SB",N2QET55W (v1.49)
X1 Yoga Gen 4,"20QF, 20QG",N2HET77W (v1.60)
X1 Yoga Gen 6,"20XY, 20Y0",N32ET91W (v1.67)
X1 Yoga Gen 7,"21CD, 21CE",N3AET80W (v1.45)
X1 Yoga Gen 8,"21HQ, 21HR",N3XET51W (v1.26)
X12 Detachable,"20UW, 20UV",R1GET61W (v1.36)
X12 Detachable Gen 2,"21LK, 21LL",N43ET27W (v1.10)
X13 2-in-1 Gen 5,"21LW, 21LX",N45ET18W (v1.08)
X13 AMD Gen 4,"21J3, 21J4",R29ET60W (v1.34)
X13 Gen  2,"20WK, 20WL",N35ET58W (v1.58)
X13 Gen 1,"20T2, 20T3",N2YET47W (v1.36)
X13 Gen 2 AMD,"20XH, 20XJ",R1NET66W (v1.36)
X13 Gen 3,"21BN, 21BQ",N3CET62W (v1.43)
X13 Gen 3 AMD,"21CM, 21CN",R22ET80W (v1.50)
X13 Gen 4,"21EX, 21EY",N3oET31W (v1.14)
X13 Gen 5,"21LU, 21LV",N45ET18W (v1.08)
X13 Gen1 AMD,"20UF, 20UG",R1CET85W (v1.54)
X13 Yoga Gen 1,"20SX, 20SY",N2UET71W (v1.51)
X13 Yoga Gen 2,"20W8, 20W9",N39ET66W (v1.45)
X13 Yoga Gen 3,"21AW, 21AX",R1ZET51W (v1.18)
X13 Yoga Gen 4,"21F2, 21F3",N3oET31W (v1.14)
X13s Gen 1 ,"21BX, 21BY",N3HET95W (v1.65)
X280,"20KE, 20KF",N20ET68W (v1.53)
X380 Yoga,"20LH, 20LJ",R0SET56W (v1.40)
X390,"20SC, 20SD",N2SET37W (v1.31)　
X390,"20Q0, 20Q1",N2JETA8W (v1.86)
X390 Yoga,"20NN, 20NQ",N2LET99W (v1.99)
X395 AMD,"20NL, 20NM",R13ET58W (v1.32)
Yoga 11e 5th Gen,"20LM, 20LN",R0VET46W (v1.31)
Yoga Gen 5,"20UB, 20UC",N2WET45W (v1.35)
Z13 Gen 1 ,"21D2, 21D3",N3GET71W (v1.71)
Z13 Gen 2,"21JV, 21JW",N41ET53W (v1.30)
Z16 Gen 1,"21D4, 21D5",N3GET71W (v1.71)
Z16 Gen 2,"21JX, 21JY",N41ET53W (v1.30)

'@

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
    "DeviceManagementScripts.Read.All",
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

    # Normalize strings coming from Intune reports / Lenovo CSV.
    # Some Lenovo CSV rows contain regular spaces, non-breaking spaces,
    # or full-width spaces around model prefixes like "20XK, 20XL".
    # Without trimming, the prefix becomes " 20XL" and will not match
    # a device reporting "20XLS1R900".
    return ([string]$Value).Replace([char]0x00A0, ' ').Replace([char]0x3000, ' ').Trim()
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


function Get-RawPropertyValue {
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string[]]$PropertyNames
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($PropertyName in $PropertyNames) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.ContainsKey($PropertyName)) {
                return $Object[$PropertyName]
            }
        }

        if ($Object.PSObject.Properties.Name -contains $PropertyName) {
            return $Object.$PropertyName
        }
    }

    return $null
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

function Get-NumericPercentFromText {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }

    $Clean = ([string]$Value) -replace '[^0-9\.]', ''
    if ([string]::IsNullOrWhiteSpace($Clean)) { return $null }

    $Number = 0.0
    if ([double]::TryParse($Clean, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$Number)) { return $Number }
    return $null
}

function Get-EffectiveDiskState {
    param(
        [string]$DiskEncryptionPercentage,
        [string]$VolumeStatus,
        [string]$ProtectionStatus,
        [string]$ProtectionState,
        [string]$IntuneEncryptionState
    )

    $Pct = Get-NumericPercentFromText -Value $DiskEncryptionPercentage
    $Volume = Normalize-Value $VolumeStatus
    $Protection = Normalize-Value $ProtectionStatus
    $ProtState = Normalize-Value $ProtectionState

    $VolumeLower = $Volume.ToLowerInvariant()
    $ProtectionLower = $Protection.ToLowerInvariant()
    $ProtStateLower = $ProtState.ToLowerInvariant()

    $HasRemediationData = $false
    if (-not [string]::IsNullOrWhiteSpace($Volume) -or -not [string]::IsNullOrWhiteSpace($Protection) -or -not [string]::IsNullOrWhiteSpace($ProtState) -or $null -ne $Pct) { $HasRemediationData = $true }

    if (-not $HasRemediationData) { return [pscustomobject]@{ State = 'Missing remediation result'; Category = 'missing' } }
    if ($VolumeLower -match 'encryptionsuspended') { return [pscustomobject]@{ State = 'Encryption suspended'; Category = 'suspended' } }
    if ($VolumeLower -match 'decryptioninprogress') { return [pscustomobject]@{ State = 'Decrypting'; Category = 'decrypting' } }
    if ($VolumeLower -match 'encryptioninprogress') { return [pscustomobject]@{ State = 'Encrypting'; Category = 'encrypting' } }
    if ($null -ne $Pct -and $Pct -gt 0 -and $Pct -lt 100) { return [pscustomobject]@{ State = 'Encrypting'; Category = 'encrypting' } }
    if ($VolumeLower -match 'fullydecrypted' -or ($null -ne $Pct -and $Pct -le 0)) { return [pscustomobject]@{ State = 'Not encrypted'; Category = 'notEncrypted' } }

    if ($VolumeLower -match 'fullyencrypted' -or ($null -ne $Pct -and $Pct -ge 100)) {
        $IsProtectionOn = $false
        if ($ProtStateLower -eq 'on' -or $ProtectionLower -match '\(on\)' -or $ProtectionLower -eq 'on') { $IsProtectionOn = $true }
        if ($IsProtectionOn) { return [pscustomobject]@{ State = 'Encrypted + Protected'; Category = 'encryptedProtected' } }
        return [pscustomobject]@{ State = 'Encrypted - Protection Off'; Category = 'encryptedProtectionOff' }
    }

    return [pscustomobject]@{ State = 'Review / unknown'; Category = 'review' }
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


function ConvertTo-SafeFileName {
    param([string]$Value)

    $Name = Normalize-Value $Value

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return "report"
    }

    return ($Name -replace '[^a-zA-Z0-9\-_\.]', '_')
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

    if ($null -eq $Object) {
        return ""
    }

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

        $SafeReportName = ConvertTo-SafeFileName $ReportName
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

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return "Unknown"
    }

    switch -Regex ($Status.ToLowerInvariant()) {
        "^(enabled|yes|on|true|1)$" { return "Enabled" }
        "^(disabled|no|off|false|0)$" { return "Disabled" }
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
        DeviceName          = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceName", "Device name", "Device Name")
        DeviceId            = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceId", "Device ID", "IntuneDeviceId", "Intune Device Id")
        AzureADDeviceId     = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("AadDeviceId", "AzureADDeviceId", "Azure AD Device ID", "Microsoft Entra device ID", "MicrosoftEntraDeviceId", "ReferenceId")
        SecureBootStatus    = Convert-SecureBootStatus $SecureBootRaw
        SecureBootRaw       = Normalize-Value $SecureBootRaw
        SecureBootSource    = $ReportName
    }
}

function Get-SecureBootRecordFromManagedDevice {
    param(
        [Parameter(Mandatory)]
        $ManagedDevice
    )

    $Dha = $ManagedDevice.deviceHealthAttestationState
    $SecureBootRaw = ""

    if ($null -ne $Dha) {
        $SecureBootRaw = Get-PropertyValue -Object $Dha -PropertyNames @("secureBoot")
    }

    if ([string]::IsNullOrWhiteSpace($SecureBootRaw)) {
        $SecureBootRaw = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("secureBoot", "secureBootStatus", "secureBootState")
    }

    return [pscustomobject]@{
        SecureBootStatus = Convert-SecureBootStatus $SecureBootRaw
        SecureBootRaw    = Normalize-Value $SecureBootRaw
        SecureBootSource = "managedDevice health attestation"
    }
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
        $BatchResponses = @(Get-RawPropertyValue -Object $Response -PropertyNames @("responses"))

        foreach ($BatchResponse in $BatchResponses) {
            $Processed++
            $BatchResponseId = Get-PropertyValue -Object $BatchResponse -PropertyNames @("id")
            $BatchStatus = Get-PropertyValue -Object $BatchResponse -PropertyNames @("status")
            $RequestInfo = $RequestMap[$BatchResponseId]
            $DeviceId = Normalize-Value $RequestInfo.DeviceId
            $DeviceName = Normalize-Value $RequestInfo.DeviceName
            $PrimaryUser = "None"
            $PrimaryUserDisplayName = ""
            $PrimaryUserUPN = ""
            $PrimaryUserEmail = ""
            $PrimaryUserId = ""
            $LookupStatus = "OK"

            if ([int]$BatchStatus -ge 200 -and [int]$BatchStatus -lt 300) {
                $Body = Get-RawPropertyValue -Object $BatchResponse -PropertyNames @("body")
                $Users = @(Get-RawPropertyValue -Object $Body -PropertyNames @("value"))

                if ($Users.Count -gt 0) {
                    $User = $Users[0]
                    $PrimaryUserDisplayName = Get-PropertyValue -Object $User -PropertyNames @("displayName")
                    $PrimaryUserUPN = Get-PropertyValue -Object $User -PropertyNames @("userPrincipalName")
                    $PrimaryUserEmail = Get-PropertyValue -Object $User -PropertyNames @("mail")
                    $PrimaryUserId = Get-PropertyValue -Object $User -PropertyNames @("id")

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
                $LookupStatus = "HTTP $BatchStatus"
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

                # The batch request can return either a single user object or a collection response
                # when using /users?$filter=userPrincipalName eq '...'. Normalize to one user object.
                $UserBody = $Body

                if ($Body -is [System.Collections.IDictionary] -and $Body.ContainsKey("value")) {
                    $UsersFromBody = @($Body["value"])
                    if ($UsersFromBody.Count -gt 0) { $UserBody = $UsersFromBody[0] }
                }
                elseif ($Body -and $Body.PSObject.Properties.Name -contains "value") {
                    $UsersFromBody = @($Body.value)
                    if ($UsersFromBody.Count -gt 0) { $UserBody = $UsersFromBody[0] }
                }

                $AccountEnabled = Get-PropertyValue -Object $UserBody -PropertyNames @("accountEnabled")
                $UserIdFromGraph = Get-PropertyValue -Object $UserBody -PropertyNames @("id")
                $UPNFromGraph = Get-PropertyValue -Object $UserBody -PropertyNames @("userPrincipalName")
                $DisplayNameFromGraph = Get-PropertyValue -Object $UserBody -PropertyNames @("displayName")

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

        # Prefer UPN first. In Graph batch, /users/{encodedUPN} can return HTTP 400 in some tenants.
        # Use a collection filter instead: /users?$filter=userPrincipalName eq 'upn'.
        $Identifier = if (-not [string]::IsNullOrWhiteSpace($UPN)) { $UPN } else { $UserId }
        $SeenKey = $Identifier.ToLowerInvariant()
        if ($SeenUsers.ContainsKey($SeenKey)) { continue }
        $SeenUsers[$SeenKey] = $true

        $RequestNumber++
        $RequestId = [string]$RequestNumber

        if (-not [string]::IsNullOrWhiteSpace($UPN)) {
            $SafeUPN = $UPN.Replace("'", "''")
            $Filter = "userPrincipalName eq '$SafeUPN'"
            $EncodedFilter = [System.Uri]::EscapeDataString($Filter)
            $RequestUrl = "/users?`$filter=$EncodedFilter&`$select=id,displayName,userPrincipalName,accountEnabled&`$top=1"
        }
        else {
            $EncodedIdentifier = [System.Uri]::EscapeDataString($UserId)
            $RequestUrl = "/users/$EncodedIdentifier?`$select=id,displayName,userPrincipalName,accountEnabled"
        }

        $Requests += @{
            id     = $RequestId
            method = "GET"
            url    = $RequestUrl
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


function Convert-IntuneDeviceEncryptionStatus {
    param($Value)

    $Status = Normalize-Value $Value

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return "Unknown"
    }

    switch -Regex ($Status.ToLowerInvariant()) {
        "^(true|yes|encrypted|compliant|succeeded|success)$" { return "Encrypted" }
        "^(false|no|notencrypted|not encrypted|not_encrypted)$" { return "Not encrypted" }
        "encrypting|inprogress|in progress" { return "Encrypting" }
        "decrypting" { return "Decrypting" }
        "suspended" { return "Encryption suspended" }
        "unknown" { return "Unknown" }
        default { return $Status }
    }
}

function Get-DeviceEncryptionRecordFromReportRow {
    param(
        [Parameter(Mandatory)]
        $ReportRow,

        [string]$ReportName
    )

    $EncryptionRaw = Get-ReportFieldValue -Object $ReportRow -PropertyNames @(
        "Encryption status",
        "EncryptionStatus",
        "Encryption state",
        "EncryptionState",
        "Device encryption status",
        "DeviceEncryptionStatus",
        "Status"
    )

    $Readiness = Get-ReportFieldValue -Object $ReportRow -PropertyNames @(
        "Encryption readiness",
        "EncryptionReadiness",
        "Readiness"
    )

    $ProfileState = Get-ReportFieldValue -Object $ReportRow -PropertyNames @(
        "Profile state summary",
        "ProfileStateSummary",
        "Profile state",
        "Policy state",
        "PolicyState"
    )

    $StatusDetails = Get-ReportFieldValue -Object $ReportRow -PropertyNames @(
        "Status details",
        "StatusDetails",
        "Details"
    )

    return [pscustomobject]@{
        DeviceName               = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceName", "Device name", "Device Name")
        DeviceId                 = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("DeviceId", "Device ID", "IntuneDeviceId", "Intune Device Id", "ManagedDeviceId", "Managed Device Id")
        AzureADDeviceId          = Get-ReportFieldValue -Object $ReportRow -PropertyNames @("AadDeviceId", "AzureADDeviceId", "Azure AD Device ID", "Microsoft Entra device ID", "MicrosoftEntraDeviceId", "ReferenceId")
        EncryptionStatus         = Convert-IntuneDeviceEncryptionStatus $EncryptionRaw
        EncryptionRaw            = Normalize-Value $EncryptionRaw
        EncryptionReadiness      = Normalize-Value $Readiness
        ProfileStateSummary      = Normalize-Value $ProfileState
        StatusDetails            = Normalize-Value $StatusDetails
        Source                   = $ReportName
    }
}

function Get-IntuneDeviceEncryptionReportRecords {
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [Parameter(Mandatory)]
        [string]$Timestamp,

        [int]$TimeoutSeconds = 300,

        [string]$RawExportPath
    )

    $ByDeviceName = @{}
    $ByManagedDeviceId = @{}
    $ByAzureADDeviceId = @{}
    $Records = @()

    # Report names can vary / be unavailable by tenant. Try common Intune export names, then fall back to managedDevice.isEncrypted.
    $ReportNames = @(
        "DeviceEncryptionReport",
        "WindowsDeviceEncryptionReport",
        "EncryptionReport",
        "ManagedDeviceEncryptionReport"
    )

    foreach ($ReportName in $ReportNames) {
        $ReportResult = Invoke-IntuneReportExport `
            -ReportName $ReportName `
            -OutputFolder $OutputFolder `
            -Timestamp $Timestamp `
            -TimeoutSeconds $TimeoutSeconds `
            -AllowFailure

        if ($ReportResult.Succeeded -and $ReportResult.Rows.Count -gt 0) {
            Write-Host "Device encryption report rows found from ${ReportName}: $($ReportResult.Rows.Count)" -ForegroundColor Green

            foreach ($ReportRow in $ReportResult.Rows) {
                $Record = Get-DeviceEncryptionRecordFromReportRow -ReportRow $ReportRow -ReportName $ReportName
                $Records += $Record

                if (-not [string]::IsNullOrWhiteSpace($Record.DeviceId)) {
                    $ByManagedDeviceId[$Record.DeviceId.ToLowerInvariant()] = $Record
                }

                if (-not [string]::IsNullOrWhiteSpace($Record.AzureADDeviceId)) {
                    $ByAzureADDeviceId[$Record.AzureADDeviceId.ToLowerInvariant()] = $Record
                }

                if (-not [string]::IsNullOrWhiteSpace($Record.DeviceName)) {
                    $ByDeviceName[$Record.DeviceName.ToLowerInvariant()] = $Record
                }
            }

            break
        }
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
            $Records | ConvertTo-Json -Depth 10 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Device encryption report raw mapping exported: $RawExportPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not export Device Encryption report raw mapping."
        Write-Warning $_.Exception.Message
    }

    return [pscustomobject]@{
        ByDeviceName      = $ByDeviceName
        ByManagedDeviceId = $ByManagedDeviceId
        ByAzureADDeviceId = $ByAzureADDeviceId
        Records           = $Records
        Count             = $Records.Count
    }
}

function Get-BitLockerFallbackFromIntuneEncryption {
    param(
        $Device,
        $DeviceEncryptionRecord
    )

    $Source = ""
    $Raw = ""
    $Status = "Unknown"

    if ($DeviceEncryptionRecord) {
        $Status = Convert-IntuneDeviceEncryptionStatus $DeviceEncryptionRecord.EncryptionStatus
        $Raw = Normalize-Value $DeviceEncryptionRecord.EncryptionRaw
        $Source = "Intune device encryption report"

        if ([string]::IsNullOrWhiteSpace($Raw)) {
            $Raw = Normalize-Value $DeviceEncryptionRecord.EncryptionStatus
        }
    }
    else {
        $IsEncrypted = Get-PropertyValue -Object $Device -PropertyNames @("isEncrypted")
        $Status = Convert-IntuneDeviceEncryptionStatus $IsEncrypted
        $Raw = $IsEncrypted
        $Source = "managedDevice.isEncrypted"
    }

    switch ($Status.ToLowerInvariant()) {
        "encrypted" {
            return [pscustomobject]@{
                State    = "Encrypted (Intune)"
                Category = "intuneEncrypted"
                Source   = $Source
                Raw      = $Raw
            }
        }
        "not encrypted" {
            return [pscustomobject]@{
                State    = "Not encrypted (Intune)"
                Category = "notEncrypted"
                Source   = $Source
                Raw      = $Raw
            }
        }
        "encrypting" {
            return [pscustomobject]@{
                State    = "Encrypting (Intune)"
                Category = "encrypting"
                Source   = $Source
                Raw      = $Raw
            }
        }
        "decrypting" {
            return [pscustomobject]@{
                State    = "Decrypting (Intune)"
                Category = "decrypting"
                Source   = $Source
                Raw      = $Raw
            }
        }
        "encryption suspended" {
            return [pscustomobject]@{
                State    = "Encryption suspended (Intune)"
                Category = "suspended"
                Source   = $Source
                Raw      = $Raw
            }
        }
        default {
            return [pscustomobject]@{
                State    = "Missing remediation result"
                Category = "missing"
                Source   = $Source
                Raw      = $Raw
            }
        }
    }
}



function Convert-DefenderBoolStatus {
    param($Value)

    $Text = Normalize-Value $Value

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return "Unknown"
    }

    switch -Regex ($Text.ToLowerInvariant()) {
        "^(true|yes|enabled|on|1)$" { return "Enabled" }
        "^(false|no|disabled|off|0)$" { return "Disabled" }
        default { return $Text }
    }
}

function Get-DefenderDeploymentStatus {
    param($WindowsProtectionState)

    if ($null -eq $WindowsProtectionState) {
        return [pscustomobject]@{
            DefenderStatusCategory = "unknown"
            DefenderStatus         = "Unknown"
            DefenderReason         = "No Windows protection state returned by Intune"
        }
    }

    $MalwareProtection = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("malwareProtectionEnabled")
    $RealTimeProtection = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("realTimeProtectionEnabled")
    $EngineVersion = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("engineVersion")
    $SignatureVersion = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("signatureVersion")
    $AntiMalwareVersion = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("antiMalwareVersion")
    $DeviceState = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("deviceState", "managedDeviceHealthState")
    $AttentionRequired = Get-PropertyValue -Object $WindowsProtectionState -PropertyNames @("attentionRequired")

    $MalwareLower = $MalwareProtection.ToLowerInvariant()
    $RealTimeLower = $RealTimeProtection.ToLowerInvariant()
    $AttentionLower = $AttentionRequired.ToLowerInvariant()
    $DeviceStateLower = $DeviceState.ToLowerInvariant()

    $HasDefenderVersion =
        -not [string]::IsNullOrWhiteSpace($EngineVersion) -or
        -not [string]::IsNullOrWhiteSpace($SignatureVersion) -or
        -not [string]::IsNullOrWhiteSpace($AntiMalwareVersion)

    if ($AttentionLower -eq "true" -or $DeviceStateLower -match "critical|rebootpending|fullscanpending|manualstepspending|offlinescanpending") {
        return [pscustomobject]@{
            DefenderStatusCategory = "attention"
            DefenderStatus         = "Needs attention"
            DefenderReason         = "Windows protection state requires attention"
        }
    }

    if ($MalwareLower -eq "true" -or $RealTimeLower -eq "true" -or $HasDefenderVersion) {
        return [pscustomobject]@{
            DefenderStatusCategory = "deployed"
            DefenderStatus         = "Deployed"
            DefenderReason         = "Defender protection state or version data is present"
        }
    }

    if ($MalwareLower -eq "false" -and $RealTimeLower -eq "false" -and -not $HasDefenderVersion) {
        return [pscustomobject]@{
            DefenderStatusCategory = "notDeployed"
            DefenderStatus         = "Not deployed"
            DefenderReason         = "No Defender protection state or version data reported"
        }
    }

    return [pscustomobject]@{
        DefenderStatusCategory = "unknown"
        DefenderStatus         = "Unknown"
        DefenderReason         = "Incomplete Windows protection state"
    }
}

function Get-DefenderRecordFromManagedDevice {
    param(
        [Parameter(Mandatory)]
        $ManagedDevice
    )

    $Protection = Get-RawPropertyValue -Object $ManagedDevice -PropertyNames @("windowsProtectionState")
    $Deployment = Get-DefenderDeploymentStatus -WindowsProtectionState $Protection

    return [pscustomobject]@{
        DeviceName                       = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("deviceName")
        DeviceId                         = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("id")
        AzureADDeviceId                  = Get-PropertyValue -Object $ManagedDevice -PropertyNames @("azureADDeviceId")

        DefenderStatus                   = $Deployment.DefenderStatus
        DefenderStatusCategory           = $Deployment.DefenderStatusCategory
        DefenderReason                   = $Deployment.DefenderReason

        DefenderHealthState              = Get-PropertyValue -Object $Protection -PropertyNames @("deviceState", "managedDeviceHealthState")
        MalwareProtectionEnabled         = Convert-DefenderBoolStatus (Get-PropertyValue -Object $Protection -PropertyNames @("malwareProtectionEnabled"))
        RealTimeProtectionEnabled        = Convert-DefenderBoolStatus (Get-PropertyValue -Object $Protection -PropertyNames @("realTimeProtectionEnabled"))
        NetworkInspectionSystemEnabled   = Convert-DefenderBoolStatus (Get-PropertyValue -Object $Protection -PropertyNames @("networkInspectionSystemEnabled"))
        SignatureUpdateOverdue           = Convert-DefenderBoolStatus (Get-PropertyValue -Object $Protection -PropertyNames @("signatureUpdateOverdue"))
        RebootRequired                   = Convert-DefenderBoolStatus (Get-PropertyValue -Object $Protection -PropertyNames @("rebootRequired"))
        DefenderEngineVersion            = Get-PropertyValue -Object $Protection -PropertyNames @("engineVersion")
        DefenderSignatureVersion         = Get-PropertyValue -Object $Protection -PropertyNames @("signatureVersion")
        DefenderAntiMalwareVersion       = Get-PropertyValue -Object $Protection -PropertyNames @("antiMalwareVersion")
        DefenderLastReportedDateTime     = Get-PropertyValue -Object $Protection -PropertyNames @("lastReportedDateTime", "lastRefreshedDateTime")
    }
}

function Get-DefenderWindowsProtectionStates {
    param(
        [array]$ManagedDevices,

        [int]$MaxDetailQueries = 5000,

        [string]$RawExportPath
    )

    $ByDeviceName = @{}
    $ByManagedDeviceId = @{}
    $ByAzureADDeviceId = @{}
    $Records = @()
    $DetailQueries = 0
    $DetailFailures = 0

    function Add-DefenderRecordToMaps {
        param($Record)

        if ($null -eq $Record) { return }

        $script:Records += $Record

        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceId)) {
            $script:ByManagedDeviceId[$Record.DeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($Record.AzureADDeviceId)) {
            $script:ByAzureADDeviceId[$Record.AzureADDeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceName)) {
            $script:ByDeviceName[$Record.DeviceName.ToLowerInvariant()] = $Record
        }
    }

    try {
        Write-Host "Retrieving Windows Defender protection state from Intune..." -ForegroundColor Cyan

        # First try relationship expansion. In some tenants this returns the device rows,
        # but the windowsProtectionState object is empty, which causes Unknown values.
        $Uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem%20eq%20'Windows'&`$select=id,deviceName,azureADDeviceId&`$expand=windowsProtectionState&`$top=100"
        $DevicesWithProtection = @(Invoke-GraphGetAll -Uri $Uri -AllowFailure)

        foreach ($Device in $DevicesWithProtection) {
            $Record = Get-DefenderRecordFromManagedDevice -ManagedDevice $Device
            Add-DefenderRecordToMaps -Record $Record
        }
    }
    catch {
        Write-Warning "Could not retrieve Defender Windows protection state using expand."
        Write-Warning $_.Exception.Message
    }

    # Fallback: per-device relationship call.
    # This is slower, but much more reliable when $expand does not hydrate windowsProtectionState.
    if ($ManagedDevices -and $MaxDetailQueries -gt 0) {
        Write-Host "Checking Defender detail fallback for devices with Unknown Defender status..." -ForegroundColor Cyan

        foreach ($Device in $ManagedDevices) {
            if ($DetailQueries -ge $MaxDetailQueries) {
                Write-Host "Reached MaxDefenderDetailQueries limit: $MaxDetailQueries" -ForegroundColor Yellow
                break
            }

            $DeviceId = Normalize-Value $Device.id
            $DeviceName = Normalize-Value $Device.deviceName
            $AzureADDeviceId = Normalize-Value $Device.azureADDeviceId

            if ([string]::IsNullOrWhiteSpace($DeviceId)) { continue }

            $ExistingRecord = $null
            $DeviceIdKey = $DeviceId.ToLowerInvariant()

            if ($ByManagedDeviceId.ContainsKey($DeviceIdKey)) {
                $ExistingRecord = $ByManagedDeviceId[$DeviceIdKey]
            }

            if ($ExistingRecord -and $ExistingRecord.DefenderStatusCategory -ne "unknown") {
                continue
            }

            $DetailQueries++

            try {
                $ProtectionUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId/windowsProtectionState"
                $Protection = Invoke-MgGraphRequest -Method GET -Uri $ProtectionUri -ErrorAction Stop

                $PseudoDevice = [pscustomobject]@{
                    id                     = $DeviceId
                    deviceName             = $DeviceName
                    azureADDeviceId         = $AzureADDeviceId
                    windowsProtectionState = $Protection
                }

                $Record = Get-DefenderRecordFromManagedDevice -ManagedDevice $PseudoDevice

                # Override the previous Unknown record.
                if (-not [string]::IsNullOrWhiteSpace($Record.DeviceId)) {
                    $ByManagedDeviceId[$Record.DeviceId.ToLowerInvariant()] = $Record
                }

                if (-not [string]::IsNullOrWhiteSpace($Record.AzureADDeviceId)) {
                    $ByAzureADDeviceId[$Record.AzureADDeviceId.ToLowerInvariant()] = $Record
                }

                if (-not [string]::IsNullOrWhiteSpace($Record.DeviceName)) {
                    $ByDeviceName[$Record.DeviceName.ToLowerInvariant()] = $Record
                }

                $Records += $Record
            }
            catch {
                $DetailFailures++

                if ($DetailFailures -le 5) {
                    Write-Host "Defender detail fallback failed for $DeviceName : $($_.Exception.Message)" -ForegroundColor DarkGray
                }
            }

            if (($DetailQueries % 100) -eq 0) {
                Write-Host "Defender detail fallback queries completed: $DetailQueries" -ForegroundColor DarkGray
            }
        }
    }

    $FinalRecords = @()
    foreach ($Key in $ByManagedDeviceId.Keys) {
        $FinalRecords += $ByManagedDeviceId[$Key]
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
            $FinalRecords | Sort-Object DeviceName | ConvertTo-Json -Depth 10 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Defender raw mapping exported: $RawExportPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not export Defender raw mapping."
        Write-Warning $_.Exception.Message
    }

    Write-Host "Defender detail fallback queries completed: $DetailQueries" -ForegroundColor Green
    Write-Host "Defender detail fallback failures: $DetailFailures" -ForegroundColor Yellow

    return [pscustomobject]@{
        ByDeviceName      = $ByDeviceName
        ByManagedDeviceId = $ByManagedDeviceId
        ByAzureADDeviceId = $ByAzureADDeviceId
        Records           = $FinalRecords
        Count             = $FinalRecords.Count
        DetailQueries     = $DetailQueries
        DetailFailures    = $DetailFailures
    }
}


function ConvertTo-YesNoUnknown {
    param($Value)

    $Text = Normalize-Value $Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return "Unknown" }

    switch -Regex ($Text.ToLowerInvariant()) {
        "^(true|yes|enabled|on|1)$" { return "Yes" }
        "^(false|no|disabled|off|0)$" { return "No" }
        default { return $Text }
    }
}

function ConvertFrom-GenericInventoryOutput {
    param(
        [string]$Output,
        [string]$InventoryType
    )

    $Parsed = Parse-KeyValueOutput -Output $Output

    if ($InventoryType -eq "RebootPending") {
        $RebootPendingRaw = ""
        foreach ($Key in @("RebootPending","PendingReboot","IsRebootPending","ComputerRebootPending")) {
            if ($Parsed.Contains($Key)) { $RebootPendingRaw = $Parsed[$Key]; break }
        }

        $RebootPending = ConvertTo-YesNoUnknown $RebootPendingRaw

        if ($RebootPending -eq "Unknown") {
            foreach ($Key in @("CBSRebootPending","WindowsUpdateRebootRequired","PendingFileRename","ComputerRenamePending","CCMRebootPending")) {
                if ($Parsed.Contains($Key) -and (ConvertTo-YesNoUnknown $Parsed[$Key]) -eq "Yes") {
                    $RebootPending = "Yes"
                    break
                }
            }
        }

        return [pscustomobject]@{
            RebootPending                 = $RebootPending
            RebootPendingRaw              = $RebootPendingRaw
            CBSRebootPending              = ConvertTo-YesNoUnknown $Parsed["CBSRebootPending"]
            WindowsUpdateRebootRequired   = ConvertTo-YesNoUnknown $Parsed["WindowsUpdateRebootRequired"]
            PendingFileRename             = ConvertTo-YesNoUnknown $Parsed["PendingFileRename"]
            ComputerRenamePending         = ConvertTo-YesNoUnknown $Parsed["ComputerRenamePending"]
            CCMRebootPending              = ConvertTo-YesNoUnknown $Parsed["CCMRebootPending"]
            Output                        = $Output
        }
    }

    if ($InventoryType -eq "Firmware") {
        return [pscustomobject]@{
            FirmwareManufacturer          = Use-ValueOrUnknown $Parsed["FirmwareManufacturer"] ""
            FirmwareVersion               = Use-ValueOrUnknown $Parsed["FirmwareVersion"] ""
            FirmwareReleaseDate           = Use-ValueOrUnknown $Parsed["FirmwareReleaseDate"] ""
            BiosVersion                   = Use-ValueOrUnknown $Parsed["BiosVersion"] ""
            BiosReleaseDate               = Use-ValueOrUnknown $Parsed["BiosReleaseDate"] ""
            BiosMode                      = Use-ValueOrUnknown $Parsed["BiosMode"] ""
            DeviceSKU                     = Use-ValueOrUnknown $Parsed["DeviceSKU"] ""
            SystemBoardModel              = Use-ValueOrUnknown $Parsed["SystemBoardModel"] ""
            TPMVersion                    = Use-ValueOrUnknown $Parsed["TPMVersion"] ""
            TpmSpecVersion                = Use-ValueOrUnknown $Parsed["TpmSpecVersion"] ""
            TpmReady                      = ConvertTo-YesNoUnknown $Parsed["TpmReady"]
            Output                        = $Output
        }
    }

    return [pscustomobject]@{ Output = $Output }
}

function Get-GenericRemediationInventoryResults {
    param(
        [Parameter(Mandatory)]
        [string]$RemediationName,

        [Parameter(Mandatory)]
        [ValidateSet("RebootPending","Firmware")]
        [string]$InventoryType,

        [int]$Top = 50,

        [int]$MaxRunStates = 5000,

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
    Write-Host "Retrieving $InventoryType remediation device run states..." -ForegroundColor Cyan

    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$RemediationId/deviceRunStates?`$top=$Top"

    $SafeResult = Invoke-GraphGetAllSafe -Uri $Uri -MaxItems $MaxRunStates
    $RunStates = @($SafeResult["Results"])

    if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
        try {
            $RunStates | ConvertTo-Json -Depth 30 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Raw $InventoryType run states exported: $RawExportPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export raw $InventoryType run states."
        }
    }

    foreach ($RunState in $RunStates) {
        $OutputInfo = Get-BestDetectionOutput -RunState $RunState
        $Output = Normalize-Value $OutputInfo.Output

        $RunStateId = Get-PropertyValue -Object $RunState -PropertyNames @("id")
        $DeviceName = Get-PropertyValue -Object $RunState -PropertyNames @("deviceName", "managedDeviceName")
        $ManagedDeviceId = Get-PropertyValue -Object $RunState -PropertyNames @("managedDeviceId", "deviceId", "managedDeviceID")

        if ([string]::IsNullOrWhiteSpace($ManagedDeviceId)) {
            $ManagedDeviceId = Get-ManagedDeviceIdFromRunStateId -RunStateId $RunStateId -ScriptId $RemediationId
        }

        $Parsed = ConvertFrom-GenericInventoryOutput -Output $Output -InventoryType $InventoryType

        $Record = [ordered]@{
            DeviceName            = $DeviceName
            IntuneDeviceId        = $ManagedDeviceId
            RunStateId            = $RunStateId
            LastRunDateTime       = Get-PropertyValue -Object $RunState -PropertyNames @("lastStateUpdateDateTime","lastSyncDateTime")
            DetectionState        = Get-PropertyValue -Object $RunState -PropertyNames @("detectionState")
            RemediationState      = Get-PropertyValue -Object $RunState -PropertyNames @("remediationState")
            OutputField           = $OutputInfo.OutputField
            Output                = $Output
            InventoryType         = $InventoryType
        }

        foreach ($Property in $Parsed.PSObject.Properties) {
            $Record[$Property.Name] = $Property.Value
        }

        $RecordObject = [pscustomobject]$Record

        if (-not [string]::IsNullOrWhiteSpace($ManagedDeviceId)) {
            $ResultsByDeviceId[$ManagedDeviceId.ToLowerInvariant()] = $RecordObject
        }

        if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
            $ResultsByDeviceName[$DeviceName.ToLowerInvariant()] = $RecordObject
        }
    }

    return [pscustomobject]@{
        ByDeviceId   = $ResultsByDeviceId
        ByDeviceName = $ResultsByDeviceName
        Count        = $RunStates.Count
    }
}

function Get-AutopilotDeviceInventory {
    param([string]$RawExportPath)

    $BySerial = @{}
    $ByAzureADDeviceId = @{}
    $ByDeviceName = @{}
    $Records = @()

    try {
        Write-Host ""
        Write-Host "Retrieving Windows Autopilot device identities..." -ForegroundColor Cyan

        $Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=100"
        $Records = @(Invoke-GraphGetAll -Uri $Uri -AllowFailure)

        foreach ($Record in $Records) {
            $Serial = Normalize-Value (Get-PropertyValue -Object $Record -PropertyNames @("serialNumber"))
            $AzureId = Normalize-Value (Get-PropertyValue -Object $Record -PropertyNames @("azureActiveDirectoryDeviceId","azureADDeviceId"))
            $DeviceName = Normalize-Value (Get-PropertyValue -Object $Record -PropertyNames @("displayName","deviceName","managedDeviceName"))

            if (-not [string]::IsNullOrWhiteSpace($Serial)) { $BySerial[$Serial.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($AzureId)) { $ByAzureADDeviceId[$AzureId.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $ByDeviceName[$DeviceName.ToLowerInvariant()] = $Record }
        }

        if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
            $Records | ConvertTo-Json -Depth 20 | Out-File -FilePath $RawExportPath -Encoding UTF8
            Write-Host "Autopilot raw inventory exported: $RawExportPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not retrieve Windows Autopilot device identities."
        Write-Warning $_.Exception.Message
    }

    return [pscustomobject]@{
        BySerial          = $BySerial
        ByAzureADDeviceId = $ByAzureADDeviceId
        ByDeviceName      = $ByDeviceName
        Records           = $Records
        Count             = $Records.Count
    }
}


function Get-LenovoSecureBoot2023BiosRequirements {
    param(
        [string]$CsvPath,
        [string]$RawExportPath
    )

    $CandidatePaths = @()
    if (-not [string]::IsNullOrWhiteSpace($CsvPath)) { $CandidatePaths += $CsvPath }
    $CandidatePaths += (Join-Path $ScriptRootSafe "Lenovo-SecureBoot2023-BIOS-Requirements.csv")
    $CandidatePaths += (Join-Path $ScriptRootSafe "lenovo.csv")
    $CandidatePaths += (Join-Path (Get-Location).Path "Lenovo-SecureBoot2023-BIOS-Requirements.csv")
    $CandidatePaths += (Join-Path (Get-Location).Path "lenovo.csv")
    $CandidatePaths += (Join-Path $OutputFolder "lenovo.csv")

    $CsvRows = @()
    $UsedSource = "Embedded Lenovo CSV"

    foreach ($Path in $CandidatePaths) {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path $Path)) {
            try {
                $CsvRows = @(Import-Csv -Path $Path)
                $UsedSource = $Path
                break
            }
            catch {
                Write-Warning "Could not import Lenovo BIOS CSV from $Path"
                Write-Warning $_.Exception.Message
            }
        }
    }

    if ($CsvRows.Count -eq 0) {
        $CsvRows = @($EmbeddedLenovoSecureBoot2023BiosCsv | ConvertFrom-Csv)
    }

    $Requirements = @()
    $Seen = @{}

    foreach ($Row in $CsvRows) {
        $Product = Get-PropertyValue -Object $Row -PropertyNames @("Product")
        $ModelText = Get-PropertyValue -Object $Row -PropertyNames @("Model")
        $RequiredBios = Get-PropertyValue -Object $Row -PropertyNames @("Minimum BIOS version (1.xx)", "Minimum BIOS version", "Minimum BIOS", "BIOS")

        if ([string]::IsNullOrWhiteSpace($ModelText) -or [string]::IsNullOrWhiteSpace($RequiredBios)) {
            continue
        }

        # Important fix:
        # Lenovo publishes model lists as values like "20XK, 20XL".
        # Import-Csv preserves the space after the comma, so the second value becomes " 20XL".
        # If not trimmed, devices such as 20XLS1R900 are incorrectly marked as "Not in Lenovo list".
        $Prefixes = @(
            $ModelText -split "," | ForEach-Object {
                $Candidate = (Normalize-Value $_).ToUpperInvariant()

                # Keep only credible 4-character Lenovo machine-type prefixes.
                # Examples: 20XL, 21MD, 21CG.
                if ($Candidate -match '([0-9]{2}[A-Z0-9]{2})') {
                    $Matches[1]
                }
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )

        foreach ($Prefix in $Prefixes) {
            $Key = "$Prefix|$RequiredBios"
            if ($Seen.ContainsKey($Key)) { continue }
            $Seen[$Key] = $true

            $ParsedRequired = Get-LenovoBiosParts -BiosText $RequiredBios
            $Requirements += [pscustomobject]@{
                Product              = $Product
                ModelPrefix          = $Prefix
                RequiredBios         = $RequiredBios
                RequiredBiosCode     = $ParsedRequired.Code
                RequiredBiosVersion  = $ParsedRequired.VersionText
                RequiredBiosBase     = $ParsedRequired.CodeBase
                RequiredBiosSequence = $ParsedRequired.Sequence
                RequiredBiosSuffix   = $ParsedRequired.CodeSuffix
                Source               = $UsedSource
            }
        }
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($RawExportPath)) {
            $Requirements |
                Sort-Object ModelPrefix, Product |
                ConvertTo-Json -Depth 10 |
                Out-File -FilePath $RawExportPath -Encoding UTF8

            Write-Host "Lenovo Secure Boot 2023 BIOS requirement mapping exported: $RawExportPath" -ForegroundColor Green
        }
    }
    catch {}

    Write-Host "Lenovo Secure Boot 2023 BIOS requirement rows imported: $($Requirements.Count)" -ForegroundColor Green
    Write-Host "Lenovo BIOS source: $UsedSource" -ForegroundColor Green
    return $Requirements
}

function Get-LenovoValidPrefixLookup {
    param([array]$Requirements)

    $Lookup = @{}

    foreach ($Req in @($Requirements)) {
        $Prefix = (Normalize-Value $Req.ModelPrefix).ToUpperInvariant()
        if (-not [string]::IsNullOrWhiteSpace($Prefix)) {
            $Lookup[$Prefix] = $true
        }
    }

    return $Lookup
}

function Get-LenovoDeviceModelPrefix {
    param(
        [string[]]$Values,
        [hashtable]$ValidPrefixLookup
    )

    $AllCandidates = @()

    foreach ($Value in $Values) {
        $Text = (Normalize-Value $Value).ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($Text)) { continue }

        # Strong match: value starts directly with a Lenovo machine type.
        # Example: 20XLS1R900 -> 20XL.
        if ($Text -match '^([0-9]{2}[A-Z0-9]{2})') {
            $Candidate = $Matches[1]
            if ($ValidPrefixLookup -and $ValidPrefixLookup.ContainsKey($Candidate)) { return $Candidate }
            $AllCandidates += $Candidate
        }

        # Embedded match: Intune/BIOS may return strings like
        # LENOVO_MT_20XL_BU_Think_FM_ThinkPad_T14_Gen_2.
        $MatchesFound = [regex]::Matches($Text, '([0-9]{2}[A-Z0-9]{2})')
        foreach ($Match in $MatchesFound) {
            $Candidate = $Match.Groups[1].Value
            if ($ValidPrefixLookup -and $ValidPrefixLookup.ContainsKey($Candidate)) { return $Candidate }
            $AllCandidates += $Candidate
        }
    }

    # If no known Lenovo prefix was found, return the first candidate only for diagnostics.
    # The readiness function will report this as review / no Lenovo match instead of falsely
    # treating random strings from device names or serials as reliable model prefixes.
    $FirstCandidate = @($AllCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($FirstCandidate.Count -gt 0) { return $FirstCandidate[0] }

    return ""
}

function Get-LenovoBiosParts { param([string]$BiosText)
    $Text=Normalize-Value $BiosText; $Code=""; $VersionText=""; $CodeBase=""; $CodeSuffix=""; $Sequence=$null
    if($Text -match '([A-Z0-9]{6,})'){ $Code=$Matches[1].ToUpperInvariant() }
    if($Text -match '\((?:v)?([0-9]+(?:\.[0-9]+)+)\)'){ $VersionText=$Matches[1] } elseif($Text -match '(?:^|\s|v)([0-9]+(?:\.[0-9]+)+)(?:\s|$)'){ $VersionText=$Matches[1] }
    if(-not [string]::IsNullOrWhiteSpace($Code) -and $Code -match '^(.+?)([0-9]+)([A-Z]*)$'){ $CodeBase=$Matches[1]; $Sequence=[int]$Matches[2]; $CodeSuffix=$Matches[3] }
    return [pscustomobject]@{ Raw=$Text; Code=$Code; VersionText=$VersionText; CodeBase=$CodeBase; Sequence=$Sequence; CodeSuffix=$CodeSuffix }
}
function ConvertTo-VersionObjectSafe { param([string]$Value)
    $Text=Normalize-Value $Value; if([string]::IsNullOrWhiteSpace($Text)){return $null}
    try{return [version]$Text}catch{try{if(($Text -split '\.').Count -eq 1){return [version]("$Text.0")}}catch{}}
    return $null
}
function Compare-LenovoBiosVersion { param($Current,$Required)
    $CurrentVersion=ConvertTo-VersionObjectSafe $Current.VersionText; $RequiredVersion=ConvertTo-VersionObjectSafe $Required.VersionText
    if($CurrentVersion -and $RequiredVersion){ if($CurrentVersion -ge $RequiredVersion){return [pscustomobject]@{IsReady=$true;Method="Version";Detail="$($Current.VersionText) >= $($Required.VersionText)"}}; return [pscustomobject]@{IsReady=$false;Method="Version";Detail="$($Current.VersionText) < $($Required.VersionText)"}}
    if(-not [string]::IsNullOrWhiteSpace($Current.CodeBase) -and -not [string]::IsNullOrWhiteSpace($Required.CodeBase) -and $Current.CodeBase -eq $Required.CodeBase -and $Current.CodeSuffix -eq $Required.CodeSuffix -and $null -ne $Current.Sequence -and $null -ne $Required.Sequence){ if($Current.Sequence -ge $Required.Sequence){return [pscustomobject]@{IsReady=$true;Method="BIOS code sequence";Detail="$($Current.Code) >= $($Required.Code)"}}; return [pscustomobject]@{IsReady=$false;Method="BIOS code sequence";Detail="$($Current.Code) < $($Required.Code)"}}
    return [pscustomobject]@{IsReady=$null;Method="Unknown";Detail="Could not compare BIOS version/code"}
}
function Get-LenovoSecureBoot2023Readiness {
    param(
        [string]$DeviceModel,
        [string]$DeviceSKU,
        [string]$SystemBoardModel,
        [string]$FirmwareVersion,
        [array]$Requirements,
        [string[]]$AdditionalValues
    )

    $CurrentBiosText = Normalize-Value $FirmwareVersion
    $ValidPrefixLookup = Get-LenovoValidPrefixLookup -Requirements $Requirements

    $IdentityValues = @()
    $IdentityValues += $DeviceSKU
    $IdentityValues += $SystemBoardModel
    $IdentityValues += $DeviceModel

    if ($AdditionalValues) {
        foreach ($Value in $AdditionalValues) { $IdentityValues += $Value }
    }

    $IdentityValues = @(
        $IdentityValues |
            ForEach-Object { Normalize-Value $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    $IdentityText = (($IdentityValues -join " ") -replace '\s+', ' ').ToUpperInvariant()
    $Requirement = $null
    $MatchMethod = ""
    $ModelPrefix = ""

    # 1. Best match: find a prefix that actually exists in the Lenovo table.
    # This fixes the "20XL" / "21MD" issue caused by CSV values with leading spaces.
    $ModelPrefix = Get-LenovoDeviceModelPrefix -Values $IdentityValues -ValidPrefixLookup $ValidPrefixLookup

    if (-not [string]::IsNullOrWhiteSpace($ModelPrefix) -and $ValidPrefixLookup.ContainsKey($ModelPrefix)) {
        $Requirement = @($Requirements | Where-Object { (Normalize-Value $_.ModelPrefix).ToUpperInvariant() -eq $ModelPrefix } | Select-Object -First 1)
        if ($Requirement.Count -gt 0) {
            $Requirement = $Requirement[0]
            $MatchMethod = "Known Lenovo model prefix"
        }
        else {
            $Requirement = $null
        }
    }

    # 2. Scan identity text for every known Lenovo model prefix from the CSV.
    # Example: model/system SKU contains 20XLS1R900, and requirement prefix is 20XL.
    if ($null -eq $Requirement -and -not [string]::IsNullOrWhiteSpace($IdentityText)) {
        foreach ($Req in @($Requirements)) {
            $Prefix = (Normalize-Value $Req.ModelPrefix).ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($Prefix)) { continue }

            if ($IdentityText.Contains($Prefix)) {
                $Requirement = $Req
                $ModelPrefix = $Prefix
                $MatchMethod = "Identity contains known Lenovo prefix"
                break
            }
        }
    }

    # 3. BIOS-code fallback: if current BIOS code has the same BIOS family as a Lenovo requirement,
    # infer the product even if model/SKU fields are incomplete.
    if ($null -eq $Requirement -and -not [string]::IsNullOrWhiteSpace($CurrentBiosText)) {
        $CurrentForInference = Get-LenovoBiosParts -BiosText $CurrentBiosText

        if (-not [string]::IsNullOrWhiteSpace($CurrentForInference.CodeBase)) {
            $BiosMatches = @(
                $Requirements | Where-Object {
                    $_.RequiredBiosBase -eq $CurrentForInference.CodeBase -and
                    $_.RequiredBiosSuffix -eq $CurrentForInference.CodeSuffix
                }
            )

            if ($BiosMatches.Count -eq 1) {
                $Requirement = $BiosMatches[0]
                $ModelPrefix = Normalize-Value $Requirement.ModelPrefix
                $MatchMethod = "BIOS code family"
            }
            elseif ($BiosMatches.Count -gt 1) {
                foreach ($Req in $BiosMatches) {
                    $Prefix = (Normalize-Value $Req.ModelPrefix).ToUpperInvariant()
                    if (-not [string]::IsNullOrWhiteSpace($Prefix) -and $IdentityText.Contains($Prefix)) {
                        $Requirement = $Req
                        $ModelPrefix = $Prefix
                        $MatchMethod = "BIOS code family + identity prefix"
                        break
                    }
                }

                if ($null -eq $Requirement) {
                    $Requirement = $BiosMatches[0]
                    $ModelPrefix = Normalize-Value $Requirement.ModelPrefix
                    $MatchMethod = "BIOS code family, multiple possible models"
                }
            }
        }
    }

    if ($null -eq $Requirement) {
        $DetectedCandidate = Get-LenovoDeviceModelPrefix -Values $IdentityValues -ValidPrefixLookup $null

        $Status = "Review - model type missing"
        $Category = "review"
        $Detail = "No known Lenovo model prefix from the Lenovo CSV was found in identity fields. Identity scanned: $IdentityText"

        if (-not [string]::IsNullOrWhiteSpace($DetectedCandidate)) {
            $Status = "Not in Lenovo list"
            $Category = "notListed"
            $ModelPrefix = $DetectedCandidate
            $Detail = "Detected candidate prefix '$DetectedCandidate', but it is not present in the Lenovo Secure Boot 2023 BIOS requirement table. Identity scanned: $IdentityText"
        }

        return [pscustomobject]@{
            Status        = $Status
            Category      = $Category
            ModelPrefix   = $ModelPrefix
            Product       = ""
            RequiredBios  = ""
            CurrentBios   = $CurrentBiosText
            CompareMethod = "No Lenovo requirement match"
            CompareDetail = $Detail
        }
    }

    if ([string]::IsNullOrWhiteSpace($CurrentBiosText)) {
        return [pscustomobject]@{
            Status        = "Review - BIOS missing"
            Category      = "review"
            ModelPrefix   = $ModelPrefix
            Product       = $Requirement.Product
            RequiredBios  = $Requirement.RequiredBios
            CurrentBios   = ""
            CompareMethod = $MatchMethod
            CompareDetail = "Matched $ModelPrefix to $($Requirement.Product), but firmware inventory did not return BIOS version. Identity scanned: $IdentityText"
        }
    }

    $Current = Get-LenovoBiosParts -BiosText $CurrentBiosText
    $Required = [pscustomobject]@{
        Code        = $Requirement.RequiredBiosCode
        VersionText = $Requirement.RequiredBiosVersion
        CodeBase    = $Requirement.RequiredBiosBase
        Sequence    = $Requirement.RequiredBiosSequence
        CodeSuffix  = $Requirement.RequiredBiosSuffix
    }

    $Compare = Compare-LenovoBiosVersion -Current $Current -Required $Required
    $DetailPrefix = if ([string]::IsNullOrWhiteSpace($MatchMethod)) { "" } else { "Matched by $MatchMethod. " }

    if ($Compare.IsReady -eq $true) {
        return [pscustomobject]@{
            Status        = "Ready"
            Category      = "ready"
            ModelPrefix   = $ModelPrefix
            Product       = $Requirement.Product
            RequiredBios  = $Requirement.RequiredBios
            CurrentBios   = $CurrentBiosText
            CompareMethod = $Compare.Method
            CompareDetail = $DetailPrefix + $Compare.Detail
        }
    }

    if ($Compare.IsReady -eq $false) {
        return [pscustomobject]@{
            Status        = "Update BIOS"
            Category      = "update"
            ModelPrefix   = $ModelPrefix
            Product       = $Requirement.Product
            RequiredBios  = $Requirement.RequiredBios
            CurrentBios   = $CurrentBiosText
            CompareMethod = $Compare.Method
            CompareDetail = $DetailPrefix + $Compare.Detail
        }
    }

    return [pscustomobject]@{
        Status        = "Review - cannot compare"
        Category      = "review"
        ModelPrefix   = $ModelPrefix
        Product       = $Requirement.Product
        RequiredBios  = $Requirement.RequiredBios
        CurrentBios   = $CurrentBiosText
        CompareMethod = $Compare.Method
        CompareDetail = $DetailPrefix + $Compare.Detail
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
# Retrieve simple Secure Boot status
# ============================================================

Write-Host ""
Write-Host "Retrieving simple Secure Boot status from Intune report..." -ForegroundColor Cyan

$SecureBootByDeviceName = @{}
$SecureBootByManagedDeviceId = @{}
$SecureBootByAzureADDeviceId = @{}
$SecureBootRecords = @()

# This report can return BadRequest when explicit column selection is used in some tenants.
# Use the default export directly to avoid the noisy failed first attempt.
$SecureBootReportResult = Invoke-IntuneReportExport `
    -ReportName "WindowsDeviceHealthAttestationReport" `
    -OutputFolder $OutputFolder `
    -Timestamp $Timestamp `
    -TimeoutSeconds $ReportExportTimeoutSeconds `
    -AllowFailure

if ($SecureBootReportResult.Succeeded -and $SecureBootReportResult.Rows.Count -gt 0) {
    Write-Host "Secure Boot report rows found: $($SecureBootReportResult.Rows.Count)" -ForegroundColor Green

    foreach ($ReportRow in $SecureBootReportResult.Rows) {
        $Record = Get-SecureBootRecordFromReportRow -ReportRow $ReportRow -ReportName $SecureBootReportResult.ReportName
        $SecureBootRecords += $Record

        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceId)) {
            $SecureBootByManagedDeviceId[$Record.DeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($Record.AzureADDeviceId)) {
            $SecureBootByAzureADDeviceId[$Record.AzureADDeviceId.ToLowerInvariant()] = $Record
        }

        if (-not [string]::IsNullOrWhiteSpace($Record.DeviceName)) {
            $SecureBootByDeviceName[$Record.DeviceName.ToLowerInvariant()] = $Record
        }
    }
}
else {
    Write-Warning "No Secure Boot report rows were retrieved. Trying managedDevice health attestation fallback."

    try {
        $SecureBootSelect = @("id", "deviceName", "azureADDeviceId", "deviceHealthAttestationState") -join ","
        $SecureBootUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem%20eq%20'Windows'&`$select=$SecureBootSelect&`$top=100"
        $SecureBootDevices = @(Invoke-GraphGetAll -Uri $SecureBootUri -AllowFailure)

        foreach ($SecureBootDevice in $SecureBootDevices) {
            $Record = Get-SecureBootRecordFromManagedDevice -ManagedDevice $SecureBootDevice
            $DeviceId = Normalize-Value $SecureBootDevice.id
            $DeviceName = Normalize-Value $SecureBootDevice.deviceName
            $AzureADDeviceId = Normalize-Value $SecureBootDevice.azureADDeviceId

            $ExportRecord = [pscustomobject]@{
                DeviceName       = $DeviceName
                DeviceId         = $DeviceId
                AzureADDeviceId  = $AzureADDeviceId
                SecureBootStatus = $Record.SecureBootStatus
                SecureBootRaw    = $Record.SecureBootRaw
                SecureBootSource = $Record.SecureBootSource
            }

            $SecureBootRecords += $ExportRecord

            if (-not [string]::IsNullOrWhiteSpace($DeviceId)) { $SecureBootByManagedDeviceId[$DeviceId.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($AzureADDeviceId)) { $SecureBootByAzureADDeviceId[$AzureADDeviceId.ToLowerInvariant()] = $Record }
            if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $SecureBootByDeviceName[$DeviceName.ToLowerInvariant()] = $Record }
        }
    }
    catch {
        Write-Warning "ManagedDevice Secure Boot fallback failed."
        Write-Warning $_.Exception.Message
    }
}

try {
    $SecureBootRecords | ConvertTo-Json -Depth 10 | Out-File -FilePath $SecureBootRawPath -Encoding UTF8
    Write-Host "Secure Boot raw mapping exported: $SecureBootRawPath" -ForegroundColor Green
}
catch {
    Write-Warning "Could not export Secure Boot raw mapping."
}



# ============================================================
# Retrieve Defender deployment/protection state
# ============================================================

Write-Host ""
$DefenderResults = Get-DefenderWindowsProtectionStates -ManagedDevices $ManagedDevices -MaxDetailQueries $MaxDefenderDetailQueries -RawExportPath $DefenderRawPath
$DefenderByDeviceId = $DefenderResults.ByManagedDeviceId
$DefenderByDeviceName = $DefenderResults.ByDeviceName
$DefenderByAzureADDeviceId = $DefenderResults.ByAzureADDeviceId

Write-Host "Defender protection state rows imported: $($DefenderResults.Count)" -ForegroundColor Green

# ============================================================
# Retrieve BitLocker status from Intune remediation output
# ============================================================

Write-Host ""
Write-Host "Retrieving BitLocker status from remediation output..." -ForegroundColor Cyan

$BitLockerResults = Get-BitLockerRemediationResults `
    -RemediationName $BitLockerRemediationName `
    -MaxRunStates $MaxBitLockerRunStates `
    -RawExportPath $BitLockerRawPath

$BitLockerByDeviceId = $BitLockerResults.ByDeviceId
$BitLockerByDeviceName = $BitLockerResults.ByDeviceName

Write-Host "BitLocker remediation run states imported: $($BitLockerResults.Count)" -ForegroundColor Green

# ============================================================
# Retrieve Intune Device Encryption report fallback
# ============================================================

Write-Host ""
Write-Host "Retrieving Intune Device Encryption report fallback..." -ForegroundColor Cyan

$DeviceEncryptionResults = Get-IntuneDeviceEncryptionReportRecords `
    -OutputFolder $OutputFolder `
    -Timestamp $Timestamp `
    -TimeoutSeconds $ReportExportTimeoutSeconds `
    -RawExportPath $DeviceEncryptionRawPath

$DeviceEncryptionByDeviceName = $DeviceEncryptionResults.ByDeviceName
$DeviceEncryptionByManagedDeviceId = $DeviceEncryptionResults.ByManagedDeviceId
$DeviceEncryptionByAzureADDeviceId = $DeviceEncryptionResults.ByAzureADDeviceId

Write-Host "Device encryption report rows imported: $($DeviceEncryptionResults.Count)" -ForegroundColor Green
Write-Host "Devices without BitLocker remediation will fall back to Intune encryption state when available." -ForegroundColor Yellow



# ============================================================
# Retrieve Reboot Pending remediation inventory
# ============================================================

Write-Host ""
Write-Host "Retrieving reboot pending remediation inventory..." -ForegroundColor Cyan

$RebootPendingResults = Get-GenericRemediationInventoryResults `
    -RemediationName $RebootPendingRemediationName `
    -InventoryType "RebootPending" `
    -MaxRunStates $MaxInventoryRunStates `
    -RawExportPath $RebootPendingRawPath

$RebootPendingByDeviceId = $RebootPendingResults.ByDeviceId
$RebootPendingByDeviceName = $RebootPendingResults.ByDeviceName

Write-Host "Reboot pending remediation run states imported: $($RebootPendingResults.Count)" -ForegroundColor Green

# ============================================================
# Retrieve Firmware / BIOS remediation inventory
# ============================================================

Write-Host ""
Write-Host "Retrieving firmware / BIOS remediation inventory..." -ForegroundColor Cyan

$FirmwareInventoryResults = Get-GenericRemediationInventoryResults `
    -RemediationName $FirmwareInventoryRemediationName `
    -InventoryType "Firmware" `
    -MaxRunStates $MaxInventoryRunStates `
    -RawExportPath $FirmwareInventoryRawPath

$FirmwareByDeviceId = $FirmwareInventoryResults.ByDeviceId
$FirmwareByDeviceName = $FirmwareInventoryResults.ByDeviceName

Write-Host "Firmware remediation run states imported: $($FirmwareInventoryResults.Count)" -ForegroundColor Green

# ============================================================
# Retrieve Lenovo Secure Boot 2023 BIOS requirements
# ============================================================

Write-Host ""
Write-Host "Loading Lenovo Secure Boot 2023 BIOS requirement table..." -ForegroundColor Cyan
$LenovoSecureBoot2023BiosRequirements = Get-LenovoSecureBoot2023BiosRequirements `
    -CsvPath $LenovoSecureBootBiosCsvPath `
    -RawExportPath $LenovoSecureBootBiosRawPath

# ============================================================
# Retrieve Autopilot inventory
# ============================================================

$AutopilotResults = Get-AutopilotDeviceInventory -RawExportPath $AutopilotRawPath
$AutopilotBySerial = $AutopilotResults.BySerial
$AutopilotByAzureADDeviceId = $AutopilotResults.ByAzureADDeviceId
$AutopilotByDeviceName = $AutopilotResults.ByDeviceName

Write-Host "Autopilot device identities imported: $($AutopilotResults.Count)" -ForegroundColor Green

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

    $DefenderRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $DefenderByDeviceId.ContainsKey($DeviceIdKey)) {
        $DefenderRecord = $DefenderByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($AzureADDeviceIdKey) -and $DefenderByAzureADDeviceId.ContainsKey($AzureADDeviceIdKey)) {
        $DefenderRecord = $DefenderByAzureADDeviceId[$AzureADDeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $DefenderByDeviceName.ContainsKey($DeviceKey)) {
        $DefenderRecord = $DefenderByDeviceName[$DeviceKey]
    }

    $BitLockerRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $BitLockerByDeviceId.ContainsKey($DeviceIdKey)) {
        $BitLockerRecord = $BitLockerByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $BitLockerByDeviceName.ContainsKey($DeviceKey)) {
        $BitLockerRecord = $BitLockerByDeviceName[$DeviceKey]
    }

    $DeviceEncryptionRecord = $null

    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $DeviceEncryptionByManagedDeviceId.ContainsKey($DeviceIdKey)) {
        $DeviceEncryptionRecord = $DeviceEncryptionByManagedDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($AzureADDeviceIdKey) -and $DeviceEncryptionByAzureADDeviceId.ContainsKey($AzureADDeviceIdKey)) {
        $DeviceEncryptionRecord = $DeviceEncryptionByAzureADDeviceId[$AzureADDeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $DeviceEncryptionByDeviceName.ContainsKey($DeviceKey)) {
        $DeviceEncryptionRecord = $DeviceEncryptionByDeviceName[$DeviceKey]
    }

    $RebootPendingRecord = $null
    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $RebootPendingByDeviceId.ContainsKey($DeviceIdKey)) {
        $RebootPendingRecord = $RebootPendingByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $RebootPendingByDeviceName.ContainsKey($DeviceKey)) {
        $RebootPendingRecord = $RebootPendingByDeviceName[$DeviceKey]
    }

    $FirmwareRecord = $null
    if (-not [string]::IsNullOrWhiteSpace($DeviceIdKey) -and $FirmwareByDeviceId.ContainsKey($DeviceIdKey)) {
        $FirmwareRecord = $FirmwareByDeviceId[$DeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $FirmwareByDeviceName.ContainsKey($DeviceKey)) {
        $FirmwareRecord = $FirmwareByDeviceName[$DeviceKey]
    }

    $AutopilotRecord = $null
    $SerialKey = (Normalize-Value $Device.serialNumber).ToLowerInvariant()

    if (-not [string]::IsNullOrWhiteSpace($AzureADDeviceIdKey) -and $AutopilotByAzureADDeviceId.ContainsKey($AzureADDeviceIdKey)) {
        $AutopilotRecord = $AutopilotByAzureADDeviceId[$AzureADDeviceIdKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($SerialKey) -and $AutopilotBySerial.ContainsKey($SerialKey)) {
        $AutopilotRecord = $AutopilotBySerial[$SerialKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($DeviceKey) -and $AutopilotByDeviceName.ContainsKey($DeviceKey)) {
        $AutopilotRecord = $AutopilotByDeviceName[$DeviceKey]
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
    $SecureBootSource = ""

    $DefenderStatus = "Unknown"
    $DefenderStatusCategory = "unknown"
    $DefenderHealthState = ""
    $DefenderMalwareProtectionEnabled = ""
    $DefenderRealTimeProtectionEnabled = ""
    $DefenderNetworkInspectionSystemEnabled = ""
    $DefenderSignatureUpdateOverdue = ""
    $DefenderRebootRequired = ""
    $DefenderEngineVersion = ""
    $DefenderSignatureVersion = ""
    $DefenderAntiMalwareVersion = ""
    $DefenderLastReportedDateTime = ""
    $DefenderReason = ""

    $RebootPending = "Unknown"
    $RebootPendingSource = ""
    $CBSRebootPending = ""
    $WindowsUpdateRebootRequired = ""
    $PendingFileRename = ""
    $ComputerRenamePending = ""
    $FirmwareVersion = ""
    $FirmwareReleaseDate = ""
    $FirmwareManufacturer = ""
    $BiosMode = ""
    $DeviceSKU = ""
    $SystemBoardModel = ""
    $TPMVersion = ""
    $TpmReady = ""
    $LenovoSB2023Readiness = "Review - not evaluated"
    $LenovoSB2023Category = "review"
    $LenovoSB2023Product = ""
    $LenovoSB2023ModelPrefix = ""
    $LenovoSB2023RequiredBios = ""
    $LenovoSB2023CurrentBios = ""
    $LenovoSB2023CompareMethod = ""
    $LenovoSB2023CompareDetail = ""
    $AutopilotEnrolled = "No"
    $AutopilotProfile = ""
    $AutopilotGroupTag = ""
    $AutopilotDeploymentProfileAssignmentStatus = ""
    $AutopilotEnrollmentState = ""
    $AutopilotLastContactedDateTime = ""
    $EnrollmentAgeDays = $null
    $EnrollmentQuality = "Unknown"
    $EnrollmentQualityCategory = "unknown"

    $BitLockerStatus = "Missing remediation result"
    $BitLockerStatusCategory = "missing"
    $DiskEncryptionPercentage = ""
    $BitLockerVolumeStatus = ""
    $BitLockerProtectionStatus = ""
    $BitLockerProtectionState = ""
    $BitLockerMountPoint = ""
    $BitLockerKeyProtectors = ""
    $BitLockerEncryptionMethod = ""
    $BitLockerLastRunDateTime = ""
    $BitLockerDetectionState = ""
    $BitLockerRemediationState = ""
    $BitLockerSource = "Remediation output"
    $IntuneDeviceEncryptionStatus = ""
    $IntuneDeviceEncryptionRaw = ""
    $IntuneDeviceEncryptionSource = ""

    if ($SecureBootRecord) {
        $SecureBootStatus = Use-ValueOrUnknown $SecureBootRecord.SecureBootStatus
        $SecureBootRaw = Normalize-Value $SecureBootRecord.SecureBootRaw
        $SecureBootSource = Normalize-Value $SecureBootRecord.SecureBootSource
    }

    if ($DefenderRecord) {
        $DefenderStatus = Use-ValueOrUnknown $DefenderRecord.DefenderStatus
        $DefenderStatusCategory = Use-ValueOrUnknown $DefenderRecord.DefenderStatusCategory "unknown"
        $DefenderHealthState = Normalize-Value $DefenderRecord.DefenderHealthState
        $DefenderMalwareProtectionEnabled = Normalize-Value $DefenderRecord.MalwareProtectionEnabled
        $DefenderRealTimeProtectionEnabled = Normalize-Value $DefenderRecord.RealTimeProtectionEnabled
        $DefenderNetworkInspectionSystemEnabled = Normalize-Value $DefenderRecord.NetworkInspectionSystemEnabled
        $DefenderSignatureUpdateOverdue = Normalize-Value $DefenderRecord.SignatureUpdateOverdue
        $DefenderRebootRequired = Normalize-Value $DefenderRecord.RebootRequired
        $DefenderEngineVersion = Normalize-Value $DefenderRecord.DefenderEngineVersion
        $DefenderSignatureVersion = Normalize-Value $DefenderRecord.DefenderSignatureVersion
        $DefenderAntiMalwareVersion = Normalize-Value $DefenderRecord.DefenderAntiMalwareVersion
        $DefenderLastReportedDateTime = Normalize-Value $DefenderRecord.DefenderLastReportedDateTime
        $DefenderReason = Normalize-Value $DefenderRecord.DefenderReason
    }

    if ($BitLockerRecord) {
        $DiskEncryptionPercentage = Normalize-Value $BitLockerRecord.DiskEncryptionPercentage
        $BitLockerVolumeStatus = Normalize-Value $BitLockerRecord.VolumeStatus
        $BitLockerProtectionStatus = Normalize-Value $BitLockerRecord.ProtectionStatus
        $BitLockerProtectionState = Normalize-Value $BitLockerRecord.ProtectionState
        $BitLockerMountPoint = Normalize-Value $BitLockerRecord.MountPoint
        $BitLockerKeyProtectors = Normalize-Value $BitLockerRecord.KeyProtectors
        $BitLockerEncryptionMethod = Normalize-Value $BitLockerRecord.EncryptionMethod
        $BitLockerLastRunDateTime = Normalize-Value $BitLockerRecord.LastRunDateTime
        $BitLockerDetectionState = Normalize-Value $BitLockerRecord.DetectionState
        $BitLockerRemediationState = Normalize-Value $BitLockerRecord.RemediationState
    }

    if ($RebootPendingRecord) {
        $RebootPending = Use-ValueOrUnknown $RebootPendingRecord.RebootPending
        $CBSRebootPending = Normalize-Value $RebootPendingRecord.CBSRebootPending
        $WindowsUpdateRebootRequired = Normalize-Value $RebootPendingRecord.WindowsUpdateRebootRequired
        $PendingFileRename = Normalize-Value $RebootPendingRecord.PendingFileRename
        $ComputerRenamePending = Normalize-Value $RebootPendingRecord.ComputerRenamePending
        $RebootPendingSource = "Remediation output"
    }

    if ($FirmwareRecord) {
        $FirmwareManufacturer = Normalize-Value $FirmwareRecord.FirmwareManufacturer
        $FirmwareVersion = Normalize-Value $FirmwareRecord.FirmwareVersion
        if ([string]::IsNullOrWhiteSpace($FirmwareVersion)) { $FirmwareVersion = Normalize-Value $FirmwareRecord.BiosVersion }
        $FirmwareReleaseDate = Normalize-Value $FirmwareRecord.FirmwareReleaseDate
        if ([string]::IsNullOrWhiteSpace($FirmwareReleaseDate)) { $FirmwareReleaseDate = Normalize-Value $FirmwareRecord.BiosReleaseDate }
        $BiosMode = Normalize-Value $FirmwareRecord.BiosMode
        $DeviceSKU = Normalize-Value $FirmwareRecord.DeviceSKU
        $SystemBoardModel = Normalize-Value $FirmwareRecord.SystemBoardModel
        $TPMVersion = Normalize-Value $FirmwareRecord.TPMVersion
        if ([string]::IsNullOrWhiteSpace($TPMVersion)) { $TPMVersion = Normalize-Value $FirmwareRecord.TpmSpecVersion }
        $TpmReady = Normalize-Value $FirmwareRecord.TpmReady
    }

    $LenovoSB2023Result = Get-LenovoSecureBoot2023Readiness `
        -DeviceModel (Normalize-Value $Device.model) `
        -DeviceSKU $DeviceSKU `
        -SystemBoardModel $SystemBoardModel `
        -FirmwareVersion $FirmwareVersion `
        -Requirements $LenovoSecureBoot2023BiosRequirements `
        -AdditionalValues @(
            # Keep only fields that can realistically contain Lenovo machine-type/model data.
            # Do not use serial number, TPM version, or random device name characters for prefix detection.
            (Normalize-Value $Device.manufacturer),
            $FirmwareManufacturer,
            $FirmwareVersion
        )

    $LenovoSB2023Readiness = Normalize-Value $LenovoSB2023Result.Status
    $LenovoSB2023Category = Normalize-Value $LenovoSB2023Result.Category
    $LenovoSB2023Product = Normalize-Value $LenovoSB2023Result.Product
    $LenovoSB2023ModelPrefix = Normalize-Value $LenovoSB2023Result.ModelPrefix
    $LenovoSB2023RequiredBios = Normalize-Value $LenovoSB2023Result.RequiredBios
    $LenovoSB2023CurrentBios = Normalize-Value $LenovoSB2023Result.CurrentBios
    $LenovoSB2023CompareMethod = Normalize-Value $LenovoSB2023Result.CompareMethod
    $LenovoSB2023CompareDetail = Normalize-Value $LenovoSB2023Result.CompareDetail

    if ($AutopilotRecord) {
        $AutopilotEnrolled = "Yes"
        $AutopilotProfile = Get-PropertyValue -Object $AutopilotRecord -PropertyNames @("deploymentProfileDisplayName","profileName")
        $AutopilotGroupTag = Get-PropertyValue -Object $AutopilotRecord -PropertyNames @("groupTag")
        $AutopilotDeploymentProfileAssignmentStatus = Get-PropertyValue -Object $AutopilotRecord -PropertyNames @("deploymentProfileAssignmentStatus")
        $AutopilotEnrollmentState = Get-PropertyValue -Object $AutopilotRecord -PropertyNames @("enrollmentState")
        $AutopilotLastContactedDateTime = Get-PropertyValue -Object $AutopilotRecord -PropertyNames @("lastContactedDateTime")
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($Device.enrolledDateTime)) {
            $EnrollmentAgeDays = [math]::Floor(((Get-Date).ToUniversalTime() - ([datetime]$Device.enrolledDateTime).ToUniversalTime()).TotalDays)
        }
    }
    catch {
        $EnrollmentAgeDays = $null
    }

    if ($AutopilotEnrolled -eq "Yes" -and (Normalize-Value $Device.managedDeviceOwnerType).ToLowerInvariant() -eq "company") {
        $EnrollmentQuality = "Good"
        $EnrollmentQualityCategory = "good"
    }
    elseif ((Normalize-Value $Device.managedDeviceOwnerType).ToLowerInvariant() -ne "company") {
        $EnrollmentQuality = "Review ownership"
        $EnrollmentQualityCategory = "review"
    }
    elseif ($AutopilotEnrolled -eq "No") {
        $EnrollmentQuality = "Not Autopilot"
        $EnrollmentQualityCategory = "notAutopilot"
    }
    else {
        $EnrollmentQuality = "Review"
        $EnrollmentQualityCategory = "review"
    }

    $EffectiveDiskState = Get-EffectiveDiskState `
        -DiskEncryptionPercentage $DiskEncryptionPercentage `
        -VolumeStatus $BitLockerVolumeStatus `
        -ProtectionStatus $BitLockerProtectionStatus `
        -ProtectionState $BitLockerProtectionState `
        -IntuneEncryptionState ""

    $BitLockerStatus = $EffectiveDiskState.State
    $BitLockerStatusCategory = $EffectiveDiskState.Category

    if ($BitLockerStatusCategory -eq "missing") {
        $IntuneEncryptionFallback = Get-BitLockerFallbackFromIntuneEncryption -Device $Device -DeviceEncryptionRecord $DeviceEncryptionRecord

        if ($IntuneEncryptionFallback.Category -ne "missing") {
            $BitLockerStatus = $IntuneEncryptionFallback.State
            $BitLockerStatusCategory = $IntuneEncryptionFallback.Category
            $BitLockerSource = $IntuneEncryptionFallback.Source
            $IntuneDeviceEncryptionRaw = $IntuneEncryptionFallback.Raw
            $IntuneDeviceEncryptionStatus = $BitLockerStatus
            $IntuneDeviceEncryptionSource = $IntuneEncryptionFallback.Source
        }
        else {
            $BitLockerSource = "No remediation result / no Intune encryption state"
            $IntuneDeviceEncryptionRaw = $IntuneEncryptionFallback.Raw
            $IntuneDeviceEncryptionSource = $IntuneEncryptionFallback.Source
        }
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
        SecureBootSource                = $SecureBootSource

        DefenderStatus                  = $DefenderStatus
        DefenderStatusCategory          = $DefenderStatusCategory
        DefenderHealthState             = $DefenderHealthState
        DefenderMalwareProtection       = $DefenderMalwareProtectionEnabled
        DefenderRealTimeProtection      = $DefenderRealTimeProtectionEnabled
        DefenderNetworkInspection       = $DefenderNetworkInspectionSystemEnabled
        DefenderSignatureUpdateOverdue  = $DefenderSignatureUpdateOverdue
        DefenderRebootRequired          = $DefenderRebootRequired
        DefenderEngineVersion           = $DefenderEngineVersion
        DefenderSignatureVersion        = $DefenderSignatureVersion
        DefenderAntiMalwareVersion      = $DefenderAntiMalwareVersion
        DefenderLastReportedDateTime    = $DefenderLastReportedDateTime
        DefenderReason                  = $DefenderReason

        RebootPending                   = $RebootPending
        RebootPendingSource             = $RebootPendingSource
        CBSRebootPending                = $CBSRebootPending
        WindowsUpdateRebootRequired     = $WindowsUpdateRebootRequired
        PendingFileRename               = $PendingFileRename
        ComputerRenamePending           = $ComputerRenamePending

        FirmwareManufacturer            = $FirmwareManufacturer
        FirmwareVersion                 = $FirmwareVersion
        FirmwareReleaseDate             = $FirmwareReleaseDate
        BiosMode                        = $BiosMode
        DeviceSKU                       = $DeviceSKU
        SystemBoardModel                = $SystemBoardModel
        TPMVersion                      = $TPMVersion
        TpmReady                        = $TpmReady
        LenovoSB2023Readiness           = $LenovoSB2023Readiness
        LenovoSB2023Category            = $LenovoSB2023Category
        LenovoSB2023Product             = $LenovoSB2023Product
        LenovoSB2023ModelPrefix         = $LenovoSB2023ModelPrefix
        LenovoSB2023RequiredBios        = $LenovoSB2023RequiredBios
        LenovoSB2023CurrentBios         = $LenovoSB2023CurrentBios
        LenovoSB2023CompareMethod       = $LenovoSB2023CompareMethod
        LenovoSB2023CompareDetail       = $LenovoSB2023CompareDetail

        AutopilotEnrolled               = $AutopilotEnrolled
        AutopilotProfile                = $AutopilotProfile
        AutopilotGroupTag               = $AutopilotGroupTag
        AutopilotDeploymentStatus       = $AutopilotDeploymentProfileAssignmentStatus
        AutopilotEnrollmentState        = $AutopilotEnrollmentState
        AutopilotLastContactedDateTime  = $AutopilotLastContactedDateTime
        EnrollmentAgeDays               = $EnrollmentAgeDays
        EnrollmentQuality               = $EnrollmentQuality
        EnrollmentQualityCategory       = $EnrollmentQualityCategory

        BitLockerStatus                 = $BitLockerStatus
        BitLockerStatusCategory         = $BitLockerStatusCategory
        DiskEncryptionPercentage        = $DiskEncryptionPercentage
        BitLockerVolumeStatus           = $BitLockerVolumeStatus
        BitLockerProtectionStatus       = $BitLockerProtectionStatus
        BitLockerProtectionState        = $BitLockerProtectionState
        BitLockerMountPoint             = $BitLockerMountPoint
        BitLockerKeyProtectors          = $BitLockerKeyProtectors
        BitLockerEncryptionMethod       = $BitLockerEncryptionMethod
        BitLockerLastRunDateTime        = $BitLockerLastRunDateTime
        BitLockerDetectionState         = $BitLockerDetectionState
        BitLockerRemediationState       = $BitLockerRemediationState
        BitLockerSource                 = $BitLockerSource
        IntuneDeviceEncryptionStatus    = $IntuneDeviceEncryptionStatus
        IntuneDeviceEncryptionRaw       = $IntuneDeviceEncryptionRaw
        IntuneDeviceEncryptionSource    = $IntuneDeviceEncryptionSource

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

# ============================================================
# Calculate operational health, duplicates, storage status, and risk
# ============================================================

$NowForHealth = Get-Date

$DeviceNameCounts = @{}
$SerialCounts = @{}

foreach ($Row in $Rows) {
    $NameKey = (Normalize-Value $Row.DeviceName).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($NameKey)) {
        if (-not $DeviceNameCounts.ContainsKey($NameKey)) { $DeviceNameCounts[$NameKey] = 0 }
        $DeviceNameCounts[$NameKey]++
    }

    $SerialKey = (Normalize-Value $Row.SerialNumber).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($SerialKey)) {
        if (-not $SerialCounts.ContainsKey($SerialKey)) { $SerialCounts[$SerialKey] = 0 }
        $SerialCounts[$SerialKey]++
    }
}

foreach ($Row in $Rows) {
    $DaysSinceCheckIn = $null
    $CheckInHealth = "Unknown"
    $CheckInHealthCategory = "unknown"

    if (-not [string]::IsNullOrWhiteSpace($Row.LastSyncDateTime)) {
        try {
            $LastSync = [datetime]$Row.LastSyncDateTime
            $DaysSinceCheckIn = [math]::Floor(($NowForHealth.ToUniversalTime() - $LastSync.ToUniversalTime()).TotalDays)

            if ($DaysSinceCheckIn -le 7) {
                $CheckInHealth = "Healthy"
                $CheckInHealthCategory = "healthy"
            }
            elseif ($DaysSinceCheckIn -le 30) {
                $CheckInHealth = "Aging"
                $CheckInHealthCategory = "aging"
            }
            elseif ($DaysSinceCheckIn -le 60) {
                $CheckInHealth = "Stale >30 days"
                $CheckInHealthCategory = "stale30"
            }
            elseif ($DaysSinceCheckIn -le 90) {
                $CheckInHealth = "Stale >60 days"
                $CheckInHealthCategory = "stale60"
            }
            else {
                $CheckInHealth = "Stale >90 days"
                $CheckInHealthCategory = "stale90"
            }
        }
        catch {
            $CheckInHealth = "Invalid date"
            $CheckInHealthCategory = "unknown"
        }
    }
    else {
        $CheckInHealth = "Never / blank"
        $CheckInHealthCategory = "never"
    }

    $StorageStatus = "Unknown"
    $StorageStatusCategory = "unknown"
    if ($null -ne $Row.FreeStoragePercent -and $Row.FreeStoragePercent -ne "") {
        try {
            $FreeStoragePercentNumber = [double]$Row.FreeStoragePercent

            if ($FreeStoragePercentNumber -lt 10) {
                $StorageStatus = "Critical <10%"
                $StorageStatusCategory = "critical"
            }
            elseif ($FreeStoragePercentNumber -lt 20) {
                $StorageStatus = "Low <20%"
                $StorageStatusCategory = "low"
            }
            else {
                $StorageStatus = "OK"
                $StorageStatusCategory = "ok"
            }
        }
        catch {
            $StorageStatus = "Unknown"
            $StorageStatusCategory = "unknown"
        }
    }

    $DeviceNameKey = (Normalize-Value $Row.DeviceName).ToLowerInvariant()
    $SerialKey = (Normalize-Value $Row.SerialNumber).ToLowerInvariant()

    $DuplicateDeviceName = "No"
    $DuplicateSerial = "No"

    if (-not [string]::IsNullOrWhiteSpace($DeviceNameKey) -and $DeviceNameCounts.ContainsKey($DeviceNameKey) -and $DeviceNameCounts[$DeviceNameKey] -gt 1) {
        $DuplicateDeviceName = "Yes"
    }

    if (-not [string]::IsNullOrWhiteSpace($SerialKey) -and $SerialCounts.ContainsKey($SerialKey) -and $SerialCounts[$SerialKey] -gt 1) {
        $DuplicateSerial = "Yes"
    }

    $RiskScore = 0
    $RiskReasons = @()

    if ((Normalize-Value $Row.ComplianceState).ToLowerInvariant() -eq "noncompliant") {
        $RiskScore += 40
        $RiskReasons += "Non-compliant"
    }

    if ($Row.BitLockerStatusCategory -in @("notEncrypted", "decrypting")) {
        $RiskScore += 40
        $RiskReasons += "BitLocker not encrypted"
    }
    elseif ($Row.BitLockerStatusCategory -in @("encryptedProtectionOff", "suspended", "review", "missing")) {
        $RiskScore += 25
        $RiskReasons += "BitLocker review"
    }

    if ((Normalize-Value $Row.DefenderStatusCategory) -eq "notDeployed") {
        $RiskScore += 35
        $RiskReasons += "Defender not deployed"
    }
    elseif ((Normalize-Value $Row.DefenderStatusCategory) -eq "attention") {
        $RiskScore += 25
        $RiskReasons += "Defender needs attention"
    }
    elseif ((Normalize-Value $Row.DefenderStatusCategory) -eq "unknown") {
        $RiskScore += 10
        $RiskReasons += "Defender unknown"
    }

    if ((Normalize-Value $Row.SecureBootStatus).ToLowerInvariant() -eq "disabled") {
        $RiskScore += 25
        $RiskReasons += "Secure Boot disabled"
    }
    elseif ((Normalize-Value $Row.SecureBootStatus).ToLowerInvariant() -notin @("enabled", "disabled")) {
        $RiskScore += 5
        $RiskReasons += "Secure Boot unknown"
    }

    if ((Normalize-Value $Row.PrimaryUserAccountStatus) -eq "Disabled") {
        $RiskScore += 20
        $RiskReasons += "Primary user disabled"
    }
    elseif ((Normalize-Value $Row.PrimaryUserAccountStatus) -eq "No primary user") {
        $RiskScore += 10
        $RiskReasons += "No primary user"
    }

    if ((Normalize-Value $Row.RebootPending) -eq "Yes") {
        $RiskScore += 15
        $RiskReasons += "Reboot pending"
    }

    if ((Normalize-Value $Row.EnrollmentQualityCategory) -in @("review","notAutopilot")) {
        $RiskScore += 10
        $RiskReasons += "Enrollment quality review"
    }

    if ((Normalize-Value $Row.LenovoSB2023Category) -eq "update") {
        $RiskScore += 25
        $RiskReasons += "Lenovo BIOS update required for Secure Boot 2023"
    }
    elseif ((Normalize-Value $Row.LenovoSB2023Category) -eq "review") {
        $RiskScore += 5
        $RiskReasons += "Lenovo Secure Boot 2023 BIOS readiness review"
    }

    if ((Normalize-Value $Row.OSUBRStatus) -eq "Below target") {
        $RiskScore += 15
        $RiskReasons += "Below UBR target"
    }

    if ($CheckInHealthCategory -eq "stale90") {
        $RiskScore += 35
        $RiskReasons += "Stale >90 days"
    }
    elseif ($CheckInHealthCategory -eq "stale60") {
        $RiskScore += 25
        $RiskReasons += "Stale >60 days"
    }
    elseif ($CheckInHealthCategory -eq "stale30") {
        $RiskScore += 15
        $RiskReasons += "Stale >30 days"
    }
    elseif ($CheckInHealthCategory -eq "never") {
        $RiskScore += 20
        $RiskReasons += "Never checked in"
    }

    if ($StorageStatusCategory -eq "critical") {
        $RiskScore += 20
        $RiskReasons += "Low disk <10%"
    }
    elseif ($StorageStatusCategory -eq "low") {
        $RiskScore += 10
        $RiskReasons += "Low disk <20%"
    }

    if ($DuplicateDeviceName -eq "Yes") {
        $RiskScore += 10
        $RiskReasons += "Duplicate device name"
    }

    if ($DuplicateSerial -eq "Yes") {
        $RiskScore += 10
        $RiskReasons += "Duplicate serial"
    }

    $RiskLevel = "Low"
    $RiskCategory = "low"

    if ($RiskScore -ge 80) {
        $RiskLevel = "Critical"
        $RiskCategory = "critical"
    }
    elseif ($RiskScore -ge 50) {
        $RiskLevel = "High"
        $RiskCategory = "high"
    }
    elseif ($RiskScore -ge 20) {
        $RiskLevel = "Medium"
        $RiskCategory = "medium"
    }

    if ($RiskReasons.Count -eq 0) {
        $RiskReasons += "No major issue detected"
    }

    $Row | Add-Member -NotePropertyName DaysSinceCheckIn -NotePropertyValue $DaysSinceCheckIn -Force
    $Row | Add-Member -NotePropertyName CheckInHealth -NotePropertyValue $CheckInHealth -Force
    $Row | Add-Member -NotePropertyName CheckInHealthCategory -NotePropertyValue $CheckInHealthCategory -Force
    $Row | Add-Member -NotePropertyName StorageStatus -NotePropertyValue $StorageStatus -Force
    $Row | Add-Member -NotePropertyName StorageStatusCategory -NotePropertyValue $StorageStatusCategory -Force
    $Row | Add-Member -NotePropertyName DuplicateDeviceName -NotePropertyValue $DuplicateDeviceName -Force
    $Row | Add-Member -NotePropertyName DuplicateSerial -NotePropertyValue $DuplicateSerial -Force
    $Row | Add-Member -NotePropertyName RiskScore -NotePropertyValue $RiskScore -Force
    $Row | Add-Member -NotePropertyName RiskLevel -NotePropertyValue $RiskLevel -Force
    $Row | Add-Member -NotePropertyName RiskCategory -NotePropertyValue $RiskCategory -Force
    $Row | Add-Member -NotePropertyName RiskReasons -NotePropertyValue ($RiskReasons -join "; ") -Force
}

$RowsWithCriticalRisk = @($Rows | Where-Object { $_.RiskCategory -eq "critical" }).Count
$RowsWithHighRisk = @($Rows | Where-Object { $_.RiskCategory -eq "high" }).Count
$RowsWithMediumRisk = @($Rows | Where-Object { $_.RiskCategory -eq "medium" }).Count
$RowsWithStale30 = @($Rows | Where-Object { $_.CheckInHealthCategory -in @("stale30","stale60","stale90","never") }).Count
$RowsWithLowStorage = @($Rows | Where-Object { $_.StorageStatusCategory -in @("critical","low") }).Count
$RowsWithDuplicateSerial = @($Rows | Where-Object { $_.DuplicateSerial -eq "Yes" }).Count
$RowsWithDuplicateDeviceName = @($Rows | Where-Object { $_.DuplicateDeviceName -eq "Yes" }).Count
$RowsLenovoSBReady = @($Rows | Where-Object { $_.LenovoSB2023Category -eq "ready" }).Count
$RowsLenovoSBUpdate = @($Rows | Where-Object { $_.LenovoSB2023Category -eq "update" }).Count
$RowsLenovoSBReview = @($Rows | Where-Object { $_.LenovoSB2023Category -eq "review" }).Count

Write-Host "Critical risk devices: $RowsWithCriticalRisk" -ForegroundColor Red
Write-Host "High risk devices: $RowsWithHighRisk" -ForegroundColor Yellow
Write-Host "Medium risk devices: $RowsWithMediumRisk" -ForegroundColor Yellow
Write-Host "Stale devices >30 days or never: $RowsWithStale30" -ForegroundColor Yellow
Write-Host "Low storage devices: $RowsWithLowStorage" -ForegroundColor Yellow
Write-Host "Duplicate serial devices: $RowsWithDuplicateSerial" -ForegroundColor Yellow
Write-Host "Duplicate device name devices: $RowsWithDuplicateDeviceName" -ForegroundColor Yellow
Write-Host "Lenovo Secure Boot 2023 BIOS ready: $RowsLenovoSBReady" -ForegroundColor Green
Write-Host "Lenovo Secure Boot 2023 BIOS update required: $RowsLenovoSBUpdate" -ForegroundColor Yellow
Write-Host "Lenovo Secure Boot 2023 BIOS review: $RowsLenovoSBReview" -ForegroundColor Yellow


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

$RowsWithDefenderDeployed = @($Rows | Where-Object { $_.DefenderStatusCategory -eq "deployed" }).Count
$RowsWithDefenderAttention = @($Rows | Where-Object { $_.DefenderStatusCategory -eq "attention" }).Count
$RowsWithDefenderNotDeployed = @($Rows | Where-Object { $_.DefenderStatusCategory -eq "notDeployed" }).Count
$RowsWithDefenderUnknown = @($Rows | Where-Object { $_.DefenderStatusCategory -ne "deployed" -and $_.DefenderStatusCategory -ne "attention" -and $_.DefenderStatusCategory -ne "notDeployed" }).Count

Write-Host "Defender deployed: $RowsWithDefenderDeployed" -ForegroundColor Green
Write-Host "Defender needs attention: $RowsWithDefenderAttention" -ForegroundColor Yellow
Write-Host "Defender not deployed: $RowsWithDefenderNotDeployed" -ForegroundColor Red
Write-Host "Defender unknown: $RowsWithDefenderUnknown" -ForegroundColor Yellow

$RowsWithBitLockerProtected = @($Rows | Where-Object { $_.BitLockerStatusCategory -eq "encryptedProtected" }).Count
$RowsWithBitLockerNotEncrypted = @($Rows | Where-Object { $_.BitLockerStatusCategory -eq "notEncrypted" }).Count
$RowsWithBitLockerMissing = @($Rows | Where-Object { $_.BitLockerStatusCategory -eq "missing" }).Count

Write-Host "BitLocker encrypted + protected: $RowsWithBitLockerProtected" -ForegroundColor Green
Write-Host "BitLocker not encrypted: $RowsWithBitLockerNotEncrypted" -ForegroundColor Yellow
Write-Host "BitLocker missing remediation result: $RowsWithBitLockerMissing" -ForegroundColor Yellow

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

    .issue-list { display: grid; gap: 10px; margin-top: 10px; }
    .issue-row {
        display: grid;
        grid-template-columns: 34px 1fr auto;
        gap: 10px;
        align-items: center;
        padding: 11px 12px;
        background: #ffffff;
        border: 1px solid var(--border);
        border-radius: 14px;
    }
    .issue-icon { font-size: 18px; }
    .issue-title { font-weight: 700; color: #0f172a; }
    .issue-subtitle { color: var(--muted); font-size: 12px; margin-top: 2px; }
    .issue-count { font-size: 20px; font-weight: 800; }
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

    .clickable-row { cursor: pointer; }
    .clickable-row:hover { background: #eef6ff !important; }

    .drawer-backdrop {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(15,23,42,0.45);
        z-index: 100;
    }

    .drawer-backdrop.open { display: block; }

    .device-drawer {
        position: fixed;
        top: 0;
        right: -760px;
        width: min(760px, 94vw);
        height: 100vh;
        background: #ffffff;
        z-index: 101;
        box-shadow: -24px 0 60px rgba(15,23,42,0.25);
        transition: right .2s ease;
        display: flex;
        flex-direction: column;
        border-left: 1px solid var(--border);
    }

    .device-drawer.open { right: 0; }

    .drawer-header {
        padding: 20px;
        border-bottom: 1px solid var(--border);
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 16px;
        background: #f8fbff;
    }

    .drawer-title { font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 4px; }
    .drawer-subtitle { color: var(--muted); font-size: 13px; }
    .drawer-close { min-width: auto; padding: 8px 12px; }

    .drawer-content {
        padding: 18px;
        overflow: auto;
        display: grid;
        gap: 14px;
    }

    .drawer-section {
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 14px;
        background: #ffffff;
    }

    .drawer-section h3 {
        margin: 0 0 10px 0;
        font-size: 15px;
        color: #0f172a;
    }

    .drawer-kv {
        display: grid;
        grid-template-columns: 220px 1fr;
        gap: 8px 14px;
        font-size: 13px;
    }

    .drawer-kv .k { color: var(--muted); font-weight: 600; }
    .drawer-kv .v { color: #0f172a; overflow-wrap: anywhere; }

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
                <h1>🖥️ Intune Windows Dashboard</h1>
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
            <div class="card-title">🧭 Filtered Devices</div>
            <div class="card-value" id="cardTotalDevices">0</div>
            <div class="card-note" id="cardTotalNote">Showing 0 of $TotalDevices devices</div>
        </div>

        <div class="card">
            <div class="card-title">✅ Compliant</div>
            <div class="card-value good" id="cardCompliant">0</div>
            <div class="card-note" id="cardCompliantNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">⚠️ Non-Compliant</div>
            <div class="card-value bad" id="cardNonCompliant">0</div>
            <div class="card-note" id="cardNonCompliantNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">👤 Primary Users Enabled</div>
            <div class="card-value good" id="cardPrimaryEnabled">0</div>
            <div class="card-note" id="cardPrimaryEnabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">🚫 Disabled Primary Users</div>
            <div class="card-value bad" id="cardPrimaryDisabled">0</div>
            <div class="card-note" id="cardPrimaryDisabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">🛡️ Secure Boot Enabled</div>
            <div class="card-value good" id="cardSecureBootEnabled">0</div>
            <div class="card-note" id="cardSecureBootEnabledNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">🛡️ Defender Deployed</div>
            <div class="card-value good" id="cardDefenderDeployed">0</div>
            <div class="card-note" id="cardDefenderDeployedNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">🔐 BitLocker Protected</div>
            <div class="card-value good" id="cardBitLockerProtected">0</div>
            <div class="card-note" id="cardBitLockerProtectedNote">0% of filtered devices</div>
        </div>

        <div class="card">
            <div class="card-title">📋 BitLocker from Intune</div>
            <div class="card-value info" id="cardBitLockerIntuneFallback">0</div>
            <div class="card-note">Fallback when remediation is missing</div>
        </div>

        <div class="card">
            <div class="card-title">🚨 Critical Risk</div>
            <div class="card-value bad" id="cardCriticalRisk">0</div>
            <div class="card-note">Highest priority devices</div>
        </div>

        <div class="card">
            <div class="card-title">🔥 High Risk</div>
            <div class="card-value warn" id="cardHighRisk">0</div>
            <div class="card-note">Needs review soon</div>
        </div>

        <div class="card">
            <div class="card-title">🧟 Stale Devices</div>
            <div class="card-value warn" id="cardStaleDevices">0</div>
            <div class="card-note">No check-in >30 days or never</div>
        </div>

        <div class="card">
            <div class="card-title">💾 Low Storage</div>
            <div class="card-value warn" id="cardLowStorage">0</div>
            <div class="card-note">Free storage below 20%</div>
        </div>

        <div class="card">
            <div class="card-title">🔁 Reboot Pending</div>
            <div class="card-value warn" id="cardRebootPending">0</div>
            <div class="card-note">From remediation inventory</div>
        </div>

        <div class="card">
            <div class="card-title">🧬 Firmware Inventory</div>
            <div class="card-value info" id="cardFirmwareInventory">0</div>
            <div class="card-note">Devices with BIOS/firmware details</div>
        </div>

        <div class="card">
            <div class="card-title">✅ Lenovo SB Certificate 2023 Ready</div>
            <div class="card-value good" id="cardLenovoSBReady">0</div>
            <div class="card-note">BIOS meets Lenovo minimum</div>
        </div>

        <div class="card">
            <div class="card-title">⚠️ Lenovo BIOS Update</div>
            <div class="card-value warn" id="cardLenovoSBUpdate">0</div>
            <div class="card-note">Below Lenovo minimum BIOS</div>
        </div>

        <div class="card">
            <div class="card-title">📦 Autopilot Enrolled</div>
            <div class="card-value good" id="cardAutopilotEnrolled">0</div>
            <div class="card-note">Matched by Entra ID / serial / name</div>
        </div>

        <div class="card">
            <div class="card-title">⬇️ Below OS Target</div>
            <div class="card-value warn" id="cardBelowTarget">0</div>
            <div class="card-note">UBR below configured threshold</div>
        </div>
    </div>

    <div class="section">
        <h2>🚨 Top Issues</h2>
        <div class="issue-list" id="topIssuesList"></div>
    </div>

    <div class="section">
        <h2>📊 Quick Look</h2>

        <div class="mini-grid">
            <div class="card chart-card">
                <div class="pie" id="pieCompliance"><div class="pie-center" id="pieComplianceCenter">0%</div></div>
                <div>
                    <div class="card-title">✅ Compliance</div>
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
                    <div class="card-title">👥 Primary User Status</div>
                    <div class="legend">
                        <div class="legend-row"><span class="dot green"></span><span>Enabled</span><strong id="legendPrimaryEnabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot red"></span><span>Disabled</span><strong id="legendPrimaryDisabled">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot orange"></span><span>No primary user</span><strong id="legendNoPrimaryUser">0 / 0%</strong></div>
                        <div class="legend-row"><span class="dot gray"></span><span>Unknown</span><strong id="legendPrimaryUnknown">0 / 0%</strong></div>
                    </div>
                </div>
            </div>

            <div class="card chart-card">
                <div class="pie" id="pieOS"><div class="pie-center" id="pieOSCenter">0%</div></div>
                <div>
                    <div class="card-title">🪟 Windows OS Branch</div>
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
        <h2>🧾 Device Details</h2>

        <div class="toolbar">
            <input id="searchBox" type="text" placeholder="🔎 Search device, user, model, serial, OS..." oninput="renderDashboard()">

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

            <details class="check-filter" id="riskFilterMenu">
                <summary><span id="riskFilterSummary">All risk levels</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="riskFilter" value="critical" data-label="Critical" onchange="onCheckboxFilterChanged()"> Critical</label>
                    <label><input type="checkbox" name="riskFilter" value="high" data-label="High" onchange="onCheckboxFilterChanged()"> High</label>
                    <label><input type="checkbox" name="riskFilter" value="medium" data-label="Medium" onchange="onCheckboxFilterChanged()"> Medium</label>
                    <label><input type="checkbox" name="riskFilter" value="low" data-label="Low" onchange="onCheckboxFilterChanged()"> Low</label>
                </div>
            </details>

            <details class="check-filter" id="checkInHealthFilterMenu">
                <summary><span id="checkInHealthFilterSummary">All check-in health</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="checkInHealthFilter" value="healthy" data-label="Healthy" onchange="onCheckboxFilterChanged()"> Healthy</label>
                    <label><input type="checkbox" name="checkInHealthFilter" value="aging" data-label="Aging 8-30 days" onchange="onCheckboxFilterChanged()"> Aging 8-30 days</label>
                    <label><input type="checkbox" name="checkInHealthFilter" value="stale30" data-label="Stale >30 days" onchange="onCheckboxFilterChanged()"> Stale >30 days</label>
                    <label><input type="checkbox" name="checkInHealthFilter" value="stale60" data-label="Stale >60 days" onchange="onCheckboxFilterChanged()"> Stale >60 days</label>
                    <label><input type="checkbox" name="checkInHealthFilter" value="stale90" data-label="Stale >90 days" onchange="onCheckboxFilterChanged()"> Stale >90 days</label>
                    <label><input type="checkbox" name="checkInHealthFilter" value="never" data-label="Never / blank" onchange="onCheckboxFilterChanged()"> Never / blank</label>
                </div>
            </details>

            <details class="check-filter" id="storageFilterMenu">
                <summary><span id="storageFilterSummary">All storage states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="storageFilter" value="critical" data-label="Critical <10%" onchange="onCheckboxFilterChanged()"> Critical &lt;10%</label>
                    <label><input type="checkbox" name="storageFilter" value="low" data-label="Low <20%" onchange="onCheckboxFilterChanged()"> Low &lt;20%</label>
                    <label><input type="checkbox" name="storageFilter" value="ok" data-label="OK" onchange="onCheckboxFilterChanged()"> OK</label>
                    <label><input type="checkbox" name="storageFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                </div>
            </details>

            <details class="check-filter" id="duplicateFilterMenu">
                <summary><span id="duplicateFilterSummary">All duplicate states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="duplicateFilter" value="duplicateName" data-label="Duplicate device name" onchange="onCheckboxFilterChanged()"> Duplicate device name</label>
                    <label><input type="checkbox" name="duplicateFilter" value="duplicateSerial" data-label="Duplicate serial" onchange="onCheckboxFilterChanged()"> Duplicate serial</label>
                    <label><input type="checkbox" name="duplicateFilter" value="clean" data-label="No duplicate" onchange="onCheckboxFilterChanged()"> No duplicate</label>
                </div>
            </details>

            <details class="check-filter" id="rebootFilterMenu">
                <summary><span id="rebootFilterSummary">All reboot states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="rebootFilter" value="yes" data-label="Reboot pending" onchange="onCheckboxFilterChanged()"> Reboot pending</label>
                    <label><input type="checkbox" name="rebootFilter" value="no" data-label="No reboot pending" onchange="onCheckboxFilterChanged()"> No reboot pending</label>
                    <label><input type="checkbox" name="rebootFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                </div>
            </details>

            <details class="check-filter" id="autopilotFilterMenu">
                <summary><span id="autopilotFilterSummary">All Autopilot states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="autopilotFilter" value="yes" data-label="Autopilot enrolled" onchange="onCheckboxFilterChanged()"> Autopilot enrolled</label>
                    <label><input type="checkbox" name="autopilotFilter" value="no" data-label="Not Autopilot" onchange="onCheckboxFilterChanged()"> Not Autopilot</label>
                </div>
            </details>

            <details class="check-filter" id="enrollmentQualityFilterMenu">
                <summary><span id="enrollmentQualityFilterSummary">All enrollment quality</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="enrollmentQualityFilter" value="good" data-label="Good" onchange="onCheckboxFilterChanged()"> Good</label>
                    <label><input type="checkbox" name="enrollmentQualityFilter" value="review" data-label="Review" onchange="onCheckboxFilterChanged()"> Review</label>
                    <label><input type="checkbox" name="enrollmentQualityFilter" value="notAutopilot" data-label="Not Autopilot" onchange="onCheckboxFilterChanged()"> Not Autopilot</label>
                    <label><input type="checkbox" name="enrollmentQualityFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                </div>
            </details>

            <details class="check-filter" id="biosModeFilterMenu">
                <summary><span id="biosModeFilterSummary">All BIOS modes</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="biosModeFilter" value="uefi" data-label="UEFI" onchange="onCheckboxFilterChanged()"> UEFI</label>
                    <label><input type="checkbox" name="biosModeFilter" value="bios" data-label="Legacy BIOS" onchange="onCheckboxFilterChanged()"> Legacy BIOS</label>
                    <label><input type="checkbox" name="biosModeFilter" value="unknown" data-label="Unknown / blank" onchange="onCheckboxFilterChanged()"> Unknown / blank</label>
                </div>
            </details>

            <details class="check-filter" id="lenovoSB2023FilterMenu">
                <summary><span id="lenovoSB2023FilterSummary">All Lenovo SB Certificate 2023 states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="lenovoSB2023Filter" value="ready" data-label="Ready" onchange="onCheckboxFilterChanged()"> Ready</label>
                    <label><input type="checkbox" name="lenovoSB2023Filter" value="update" data-label="Update BIOS" onchange="onCheckboxFilterChanged()"> Update BIOS</label>
                    <label><input type="checkbox" name="lenovoSB2023Filter" value="review" data-label="Review" onchange="onCheckboxFilterChanged()"> Review</label>
                    <label><input type="checkbox" name="lenovoSB2023Filter" value="notListed" data-label="Not in Lenovo list" onchange="onCheckboxFilterChanged()"> Not in Lenovo list</label>
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

            <details class="check-filter" id="defenderFilterMenu">
                <summary><span id="defenderFilterSummary">All Defender states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="defenderFilter" value="deployed" data-label="Deployed" onchange="onCheckboxFilterChanged()"> Deployed</label>
                    <label><input type="checkbox" name="defenderFilter" value="attention" data-label="Needs attention" onchange="onCheckboxFilterChanged()"> Needs attention</label>
                    <label><input type="checkbox" name="defenderFilter" value="notDeployed" data-label="Not deployed" onchange="onCheckboxFilterChanged()"> Not deployed</label>
                    <label><input type="checkbox" name="defenderFilter" value="unknown" data-label="Unknown" onchange="onCheckboxFilterChanged()"> Unknown</label>
                </div>
            </details>

            <details class="check-filter" id="bitLockerFilterMenu">
                <summary><span id="bitLockerFilterSummary">All BitLocker states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="bitLockerFilter" value="encryptedProtected" data-label="Encrypted + Protected" onchange="onCheckboxFilterChanged()"> Encrypted + Protected</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="encryptedProtectionOff" data-label="Encrypted - Protection Off" onchange="onCheckboxFilterChanged()"> Encrypted - Protection Off</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="intuneEncrypted" data-label="Encrypted from Intune fallback" onchange="onCheckboxFilterChanged()"> Encrypted from Intune fallback</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="encrypting" data-label="Encrypting" onchange="onCheckboxFilterChanged()"> Encrypting</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="suspended" data-label="Suspended" onchange="onCheckboxFilterChanged()"> Suspended</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="notEncrypted" data-label="Not encrypted" onchange="onCheckboxFilterChanged()"> Not encrypted</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="decrypting" data-label="Decrypting" onchange="onCheckboxFilterChanged()"> Decrypting</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="missing" data-label="Missing remediation result" onchange="onCheckboxFilterChanged()"> Missing remediation result</label>
                    <label><input type="checkbox" name="bitLockerFilter" value="review" data-label="Review / unknown" onchange="onCheckboxFilterChanged()"> Review / unknown</label>
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

            <details class="check-filter" id="ubrStatusFilterMenu">
                <summary><span id="ubrStatusFilterSummary">All UBR states</span></summary>
                <div class="check-filter-panel">
                    <label><input type="checkbox" name="ubrStatusFilter" value="ok" data-label="OK" onchange="onCheckboxFilterChanged()"> OK</label>
                    <label><input type="checkbox" name="ubrStatusFilter" value="below target" data-label="Below target" onchange="onCheckboxFilterChanged()"> Below target</label>
                    <label><input type="checkbox" name="ubrStatusFilter" value="review" data-label="Review" onchange="onCheckboxFilterChanged()"> Review</label>
                    <label><input type="checkbox" name="ubrStatusFilter" value="unknown" data-label="Unknown / blank" onchange="onCheckboxFilterChanged()"> Unknown / blank</label>
                </div>
            </details>

            <details class="check-filter" id="manufacturerFilterMenu">
                <summary><span id="manufacturerFilterSummary">All manufacturers</span></summary>
                <div class="check-filter-panel" id="manufacturerFilterPanel"></div>
            </details>

            <details class="check-filter" id="managementAgentFilterMenu">
                <summary><span id="managementAgentFilterSummary">All mgmt agents</span></summary>
                <div class="check-filter-panel" id="managementAgentFilterPanel"></div>
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

            <button onclick="clearAllFilters()">🧹 Clear filters</button>
            <button onclick="downloadVisibleCsv()">⬇️ Download visible CSV</button>
        </div>

        <div class="card-note" id="visibleCount"></div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>🚦 Risk</th>
                        <th>🧠 Issues</th>
                        <th>🖥️ Device</th>
                        <th>👤 User</th>
                        <th>👥 Primary User</th>
                        <th>🚦 Primary User Status</th>
                        <th>✉️ Email</th>
                        <th>🛡️ Secure Boot</th>
                        <th>🔁 Reboot</th>
                        <th>🛡️ Defender</th>
                        <th>⚡ Real-Time</th>
                        <th>🧬 Signature</th>
                        <th>🔐 BitLocker</th>
                        <th>💽 Disk %</th>
                        <th>📦 BL Volume</th>
                        <th>🛡️ BL Protection</th>
                        <th>🔑 BL Protectors</th>
                        <th>📌 BL Source</th>
                        <th>✅ Compliance</th>
                        <th>🪟 OS</th>
                        <th>🏷️ OS Version</th>
                        <th>🔢 Build</th>
                        <th>🧩 UBR</th>
                        <th>🎯 UBR Status</th>
                        <th>🏭 Manufacturer</th>
                        <th>💻 Model</th>
                        <th>🏷️ Serial</th>
                        <th>🙋 Owner</th>
                        <th>🧰 Mgmt Agent</th>
                        <th>📝 Registration</th>
                        <th>📦 Autopilot</th>
                        <th>🎯 Enrollment Quality</th>
                        <th>📋 Autopilot Profile</th>
                        <th>🧬 Firmware</th>
                        <th>✅ Lenovo SB Certificate 2023</th>
                        <th>📌 Lenovo Required BIOS</th>
                        <th>🧩 Lenovo Product</th>
                        <th>🧭 BIOS Mode</th>
                        <th>🔒 TPM</th>
                        <th>🕒 Last Check-in</th>
                        <th>🧟 Check-in Health</th>
                        <th>📅 Days Since Check-in</th>
                        <th>💾 Free Storage %</th>
                        <th>📦 Storage Status</th>
                        <th>👯 Duplicate Name</th>
                        <th>🏷️ Duplicate Serial</th>
                    </tr>
                </thead>
                <tbody id="deviceTableBody"></tbody>
            </table>
        </div>
    </div>

</div>

<div class="drawer-backdrop" id="drawerBackdrop" onclick="closeDeviceDrawer()"></div>
<aside class="device-drawer" id="deviceDrawer">
    <div class="drawer-header">
        <div>
            <div class="drawer-title" id="drawerTitle">Device details</div>
            <div class="drawer-subtitle" id="drawerSubtitle"></div>
        </div>
        <button class="drawer-close" onclick="closeDeviceDrawer()">Close</button>
    </div>
    <div class="drawer-content" id="drawerContent"></div>
</aside>

<footer>
    Primary user status comes from Entra ID accountEnabled. Secure Boot status comes from Intune device health attestation when available. BitLocker status comes from the remediation output named Monitoring - Detection - Bitlocker - Get status.
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

function getPillEmoji(value, type) {
    const v = String(value || "").toLowerCase();

    if (type === "compliance") {
        if (v === "compliant") return "✅ ";
        if (v === "noncompliant") return "⚠️ ";
        return "❔ ";
    }

    if (type === "primaryuser") {
        if (v === "enabled") return "✅ ";
        if (v === "disabled") return "🚫 ";
        if (v === "no primary user") return "👤 ";
        return "❔ ";
    }

    if (type === "secureboot") {
        if (v === "enabled") return "🛡️ ";
        if (v === "disabled") return "⚠️ ";
        return "❔ ";
    }

    if (type === "defender") {
        if (v === "deployed") return "🛡️ ";
        if (v === "needs attention") return "⚠️ ";
        if (v === "not deployed") return "🚫 ";
        if (v === "enabled") return "✅ ";
        if (v === "disabled") return "🚫 ";
        return "❔ ";
    }

    if (type === "bitlocker") {
        if (v === "encrypted + protected" || v === "encrypted (intune)") return "🔐 ";
        if (v === "encrypted - protection off") return "🔓 ";
        if (v.includes("encrypting")) return "⏳ ";
        if (v.includes("suspended")) return "⏸️ ";
        if (v.includes("not encrypted")) return "⚠️ ";
        if (v.includes("missing")) return "❔ ";
        return "🧩 ";
    }

    if (type === "risk") {
        if (v === "critical") return "🚨 ";
        if (v === "high") return "🔥 ";
        if (v === "medium") return "⚠️ ";
        if (v === "low") return "✅ ";
        return "❔ ";
    }

    if (type === "checkin") {
        if (v === "healthy") return "✅ ";
        if (v.includes("stale") || v.includes("never")) return "🧟 ";
        if (v.includes("aging")) return "🕒 ";
        return "❔ ";
    }

    if (type === "storage") {
        if (v === "ok") return "✅ ";
        if (v.includes("critical")) return "🚨 ";
        if (v.includes("low")) return "💾 ";
        return "❔ ";
    }

    if (type === "duplicate") {
        if (v === "yes") return "👯 ";
        if (v === "no") return "✅ ";
        return "❔ ";
    }

    if (type === "reboot") {
        if (v === "yes") return "🔁 ";
        if (v === "no") return "✅ ";
        return "❔ ";
    }

    if (type === "autopilot") {
        if (v === "yes") return "📦 ";
        if (v === "no") return "⚠️ ";
        return "❔ ";
    }

    if (type === "enrollment") {
        if (v === "good") return "✅ ";
        if (v.includes("review")) return "⚠️ ";
        if (v.includes("not autopilot")) return "📦 ";
        return "❔ ";
    }

    if (type === "lenovo") {
        if (v === "ready") return "✅ ";
        if (v === "update bios") return "⚠️ ";
        if (v.includes("review")) return "🧩 ";
        if (v.includes("not in lenovo")) return "➖ ";
        return "❔ ";
    }

    if (type === "ubr") {
        if (v === "ok") return "✅ ";
        if (v === "below target") return "⬇️ ";
        return "🧩 ";
    }

    return "";
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

    if (type === "defender") {
        const v = clean.toLowerCase();
        if (v === "deployed" || v === "enabled") cls += " good";
        else if (v === "not deployed" || v === "disabled") cls += " bad";
        else cls += " warn";
    }

    if (type === "bitlocker") {
        const v = clean.toLowerCase();
        if (v === "encrypted + protected" || v === "encrypted (intune)") cls += " good";
        else if (v === "not encrypted" || v === "not encrypted (intune)" || v === "decrypting" || v === "decrypting (intune)") cls += " bad";
        else cls += " warn";
    }

    if (type === "risk") {
        const v = clean.toLowerCase();
        if (v === "low") cls += " good";
        else if (v === "critical" || v === "high") cls += " bad";
        else cls += " warn";
    }

    if (type === "checkin") {
        const v = clean.toLowerCase();
        if (v === "healthy") cls += " good";
        else if (v.includes("stale") || v.includes("never")) cls += " bad";
        else cls += " warn";
    }

    if (type === "storage") {
        const v = clean.toLowerCase();
        if (v === "ok") cls += " good";
        else if (v.includes("critical")) cls += " bad";
        else cls += " warn";
    }

    if (type === "duplicate") {
        const v = clean.toLowerCase();
        if (v === "no") cls += " good";
        else if (v === "yes") cls += " bad";
        else cls += " warn";
    }

    if (type === "reboot") {
        const v = clean.toLowerCase();
        if (v === "no") cls += " good";
        else if (v === "yes") cls += " bad";
        else cls += " warn";
    }

    if (type === "autopilot") {
        const v = clean.toLowerCase();
        if (v === "yes") cls += " good";
        else if (v === "no") cls += " warn";
        else cls += " warn";
    }

    if (type === "enrollment") {
        const v = clean.toLowerCase();
        if (v === "good") cls += " good";
        else if (v === "review ownership" || v === "review") cls += " bad";
        else cls += " warn";
    }

    if (type === "lenovo") {
        const v = clean.toLowerCase();
        if (v === "ready") cls += " good";
        else if (v === "update bios") cls += " bad";
        else cls += " warn";
    }

    if (type === "ubr") {
        if (clean.toLowerCase() === "ok") cls += " good";
        else if (clean.toLowerCase() === "below target") cls += " bad";
        else cls += " warn";
    }

    return '<span class="' + cls + '">' + getPillEmoji(clean, type) + escapeHtml(clean) + '</span>';
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
    updateFilterSummary("riskFilterSummary", "riskFilter", "All risk levels");
    updateFilterSummary("checkInHealthFilterSummary", "checkInHealthFilter", "All check-in health");
    updateFilterSummary("storageFilterSummary", "storageFilter", "All storage states");
    updateFilterSummary("duplicateFilterSummary", "duplicateFilter", "All duplicate states");
    updateFilterSummary("rebootFilterSummary", "rebootFilter", "All reboot states");
    updateFilterSummary("autopilotFilterSummary", "autopilotFilter", "All Autopilot states");
    updateFilterSummary("enrollmentQualityFilterSummary", "enrollmentQualityFilter", "All enrollment quality");
    updateFilterSummary("biosModeFilterSummary", "biosModeFilter", "All BIOS modes");
    updateFilterSummary("primaryStatusFilterSummary", "primaryStatusFilter", "All primary user states");
    updateFilterSummary("secureBootFilterSummary", "secureBootFilter", "All Secure Boot states");
    updateFilterSummary("defenderFilterSummary", "defenderFilter", "All Defender states");
    updateFilterSummary("bitLockerFilterSummary", "bitLockerFilter", "All BitLocker states");
    updateFilterSummary("osFilterSummary", "osFilter", "All OS branches");
    updateFilterSummary("ubrStatusFilterSummary", "ubrStatusFilter", "All UBR states");
    updateFilterSummary("manufacturerFilterSummary", "manufacturerFilter", "All manufacturers");
    updateFilterSummary("managementAgentFilterSummary", "managementAgentFilter", "All mgmt agents");
}

function onCheckboxFilterChanged() { renderDashboard(); }


function uniqueSortedValues(fieldName) {
    const seen = {};
    devices.forEach(function(d) {
        const value = String(d[fieldName] || "").trim();
        if (value) seen[value] = true;
    });
    return Object.keys(seen).sort(function(a, b) { return a.localeCompare(b); });
}

function populateDynamicCheckboxFilter(panelId, filterName, values, emptyLabel) {
    const panel = document.getElementById(panelId);
    if (!panel) return;

    let html = "";

    if (!values.length) {
        html += '<label><input type="checkbox" name="' + filterName + '" value="__blank__" data-label="' + escapeHtml(emptyLabel) + '" onchange="onCheckboxFilterChanged()"> ' + escapeHtml(emptyLabel) + '</label>';
    }
    else {
        values.forEach(function(value) {
            html += '<label><input type="checkbox" name="' + filterName + '" value="' + escapeHtml(value.toLowerCase()) + '" data-label="' + escapeHtml(value) + '" onchange="onCheckboxFilterChanged()"> ' + escapeHtml(value) + '</label>';
        });
        html += '<label><input type="checkbox" name="' + filterName + '" value="__blank__" data-label="' + escapeHtml(emptyLabel) + '" onchange="onCheckboxFilterChanged()"> ' + escapeHtml(emptyLabel) + '</label>';
    }

    panel.innerHTML = html;
}

function populateDynamicFilters() {
    populateDynamicCheckboxFilter("manufacturerFilterPanel", "manufacturerFilter", uniqueSortedValues("Manufacturer"), "Blank / unknown");
    populateDynamicCheckboxFilter("managementAgentFilterPanel", "managementAgentFilter", uniqueSortedValues("ManagementAgent"), "Blank / unknown");
}

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
    clearCheckboxGroup("riskFilter");
    clearCheckboxGroup("checkInHealthFilter");
    clearCheckboxGroup("storageFilter");
    clearCheckboxGroup("duplicateFilter");
    clearCheckboxGroup("rebootFilter");
    clearCheckboxGroup("autopilotFilter");
    clearCheckboxGroup("enrollmentQualityFilter");
    clearCheckboxGroup("biosModeFilter");
    clearCheckboxGroup("primaryStatusFilter");
    clearCheckboxGroup("secureBootFilter");
    clearCheckboxGroup("defenderFilter");
    clearCheckboxGroup("bitLockerFilter");
    clearCheckboxGroup("osFilter");
    clearCheckboxGroup("ubrStatusFilter");
    clearCheckboxGroup("manufacturerFilter");
    clearCheckboxGroup("managementAgentFilter");
    document.getElementById("lastSyncPreset").value = "";
    document.getElementById("lastSyncFrom").value = "";
    document.getElementById("lastSyncTo").value = "";
    renderDashboard();
}

function getFilteredDevices() {
    const search = document.getElementById("searchBox").value.toLowerCase();
    const compliance = getCheckedValues("complianceFilter");
    const risk = getCheckedValues("riskFilter");
    const checkInHealth = getCheckedValues("checkInHealthFilter");
    const storage = getCheckedValues("storageFilter");
    const duplicate = getCheckedValues("duplicateFilter");
    const reboot = getCheckedValues("rebootFilter");
    const autopilot = getCheckedValues("autopilotFilter");
    const enrollmentQuality = getCheckedValues("enrollmentQualityFilter");
    const biosMode = getCheckedValues("biosModeFilter");
    const lenovoSB2023 = getCheckedValues("lenovoSB2023Filter");
    const primaryStatus = getCheckedValues("primaryStatusFilter");
    const secureBoot = getCheckedValues("secureBootFilter");
    const defender = getCheckedValues("defenderFilter");
    const bitLocker = getCheckedValues("bitLockerFilter");
    const os = getCheckedValues("osFilter");
    const ubrStatus = getCheckedValues("ubrStatusFilter");
    const manufacturers = getCheckedValues("manufacturerFilter");
    const managementAgents = getCheckedValues("managementAgentFilter");

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

        if (risk.length) {
            const riskCategory = String(d.RiskCategory || "low").toLowerCase();
            if (!matchesAny(risk, function(value) { return riskCategory === value; })) return false;
        }

        if (checkInHealth.length) {
            const checkInCategory = String(d.CheckInHealthCategory || "unknown");
            if (!matchesAny(checkInHealth, function(value) { return checkInCategory === value; })) return false;
        }

        if (storage.length) {
            const storageCategory = String(d.StorageStatusCategory || "unknown");
            if (!matchesAny(storage, function(value) { return storageCategory === value; })) return false;
        }

        if (duplicate.length) {
            const dupName = String(d.DuplicateDeviceName || "No").toLowerCase() === "yes";
            const dupSerial = String(d.DuplicateSerial || "No").toLowerCase() === "yes";
            if (!matchesAny(duplicate, function(value) {
                if (value === "duplicateName") return dupName;
                if (value === "duplicateSerial") return dupSerial;
                if (value === "clean") return !dupName && !dupSerial;
                return false;
            })) return false;
        }

        if (reboot.length) {
            const rebootStatus = String(d.RebootPending || "unknown").toLowerCase();
            if (!matchesAny(reboot, function(value) {
                if (value === "unknown") return rebootStatus === "" || rebootStatus === "unknown";
                return rebootStatus === value;
            })) return false;
        }

        if (autopilot.length) {
            const ap = String(d.AutopilotEnrolled || "No").toLowerCase();
            if (!matchesAny(autopilot, function(value) { return ap === value; })) return false;
        }

        if (enrollmentQuality.length) {
            const quality = String(d.EnrollmentQualityCategory || "unknown");
            if (!matchesAny(enrollmentQuality, function(value) { return quality === value; })) return false;
        }

        if (biosMode.length) {
            const mode = String(d.BiosMode || "").toLowerCase();
            if (!matchesAny(biosMode, function(value) {
                if (value === "unknown") return mode === "" || mode === "unknown";
                return mode === value;
            })) return false;
        }

        if (lenovoSB2023.length) {
            const lenovoCategory = String(d.LenovoSB2023Category || "review");
            if (!matchesAny(lenovoSB2023, function(value) { return lenovoCategory === value; })) return false;
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

        if (defender.length) {
            const defenderCategory = String(d.DefenderStatusCategory || "unknown");
            if (!matchesAny(defender, function(value) {
                if (value === "unknown") return defenderCategory === "" || defenderCategory === "unknown";
                return defenderCategory === value;
            })) return false;
        }

        if (bitLocker.length) {
            const bl = String(d.BitLockerStatusCategory || "missing");
            if (!matchesAny(bitLocker, function(value) {
                return bl === value;
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

        if (ubrStatus.length) {
            const status = String(d.OSUBRStatus || "").toLowerCase();
            if (!matchesAny(ubrStatus, function(value) {
                if (value === "unknown") return status === "" || status === "unknown";
                return status === value;
            })) return false;
        }

        if (manufacturers.length) {
            const manufacturer = String(d.Manufacturer || "").trim().toLowerCase();
            if (!matchesAny(manufacturers, function(value) {
                if (value === "__blank__") return manufacturer === "";
                return manufacturer === value;
            })) return false;
        }

        if (managementAgents.length) {
            const agent = String(d.ManagementAgent || "").trim().toLowerCase();
            if (!matchesAny(managementAgents, function(value) {
                if (value === "__blank__") return agent === "";
                return agent === value;
            })) return false;
        }

        if (!matchesLastSyncFilter(d)) return false;
        return true;
    });
}

function updateTopIssues(rows) {
    const total = rows.length;

    const issues = [
        {
            icon: "🚨",
            title: "Critical risk devices",
            subtitle: "Calculated from compliance, security, stale check-in, storage, and duplicates",
            count: rows.filter(function(d) { return String(d.RiskCategory || "").toLowerCase() === "critical"; }).length
        },
        {
            icon: "🔥",
            title: "High risk devices",
            subtitle: "Multiple issues or important security signal",
            count: rows.filter(function(d) { return String(d.RiskCategory || "").toLowerCase() === "high"; }).length
        },
        {
            icon: "🔁",
            title: "Reboot pending",
            subtitle: "Devices with reboot pending inventory flag",
            count: rows.filter(function(d) { return String(d.RebootPending || "").toLowerCase() === "yes"; }).length
        },
        {
            icon: "🧬",
            title: "Lenovo BIOS update required",
            subtitle: "BIOS below Lenovo minimum for Secure Boot 2023 certificate readiness",
            count: rows.filter(function(d) { return String(d.LenovoSB2023Category || "") === "update"; }).length
        },
        {
            icon: "📦",
            title: "Autopilot / enrollment review",
            subtitle: "Not Autopilot or enrollment quality requires review",
            count: rows.filter(function(d) { return String(d.EnrollmentQualityCategory || "").toLowerCase() !== "good"; }).length
        },
        {
            icon: "🧬",
            title: "Missing firmware inventory",
            subtitle: "No BIOS / firmware version from remediation inventory",
            count: rows.filter(function(d) { return !String(d.FirmwareVersion || "").trim(); }).length
        },
        {
            icon: "🔐",
            title: "BitLocker not protected / review",
            subtitle: "Not encrypted, suspended, missing result, or needs review",
            count: rows.filter(function(d) {
                const c = String(d.BitLockerStatusCategory || "");
                return ["notEncrypted", "decrypting", "encryptedProtectionOff", "suspended", "review", "missing"].includes(c);
            }).length
        },
        {
            icon: "🛡️",
            title: "Defender not deployed or attention",
            subtitle: "Defender not reporting as deployed or needs attention",
            count: rows.filter(function(d) {
                const c = String(d.DefenderStatusCategory || "");
                return c === "notDeployed" || c === "attention" || c === "unknown";
            }).length
        },
        {
            icon: "🧟",
            title: "Stale devices",
            subtitle: "No check-in for more than 30 days or never checked in",
            count: rows.filter(function(d) {
                return ["stale30", "stale60", "stale90", "never"].includes(String(d.CheckInHealthCategory || ""));
            }).length
        },
        {
            icon: "💾",
            title: "Low storage",
            subtitle: "Free storage below 20%",
            count: rows.filter(function(d) {
                return ["critical", "low"].includes(String(d.StorageStatusCategory || ""));
            }).length
        },
        {
            icon: "👯",
            title: "Duplicate inventory records",
            subtitle: "Duplicate device name or duplicate serial",
            count: rows.filter(function(d) {
                return String(d.DuplicateDeviceName || "").toLowerCase() === "yes" || String(d.DuplicateSerial || "").toLowerCase() === "yes";
            }).length
        },
        {
            icon: "⬇️",
            title: "Below OS UBR target",
            subtitle: "Device build is below configured UBR threshold",
            count: rows.filter(function(d) { return String(d.OSUBRStatus || "").toLowerCase() === "below target"; }).length
        }
    ];

    issues.sort(function(a, b) { return b.count - a.count; });

    const container = document.getElementById("topIssuesList");
    if (!container) return;

    container.innerHTML = issues.slice(0, 8).map(function(issue) {
        return '' +
            '<div class="issue-row">' +
            '<div class="issue-icon">' + issue.icon + '</div>' +
            '<div><div class="issue-title">' + escapeHtml(issue.title) + '</div><div class="issue-subtitle">' + escapeHtml(issue.subtitle) + '</div></div>' +
            '<div class="issue-count">' + issue.count + '</div>' +
            '</div>';
    }).join("");
}

function updateQuickLook(rows) {
    const total = rows.length;

    const criticalRisk = rows.filter(function(d) { return String(d.RiskCategory || "").toLowerCase() === "critical"; }).length;
    const highRisk = rows.filter(function(d) { return String(d.RiskCategory || "").toLowerCase() === "high"; }).length;
    const staleDevices = rows.filter(function(d) { return ["stale30", "stale60", "stale90", "never"].includes(String(d.CheckInHealthCategory || "")); }).length;
    const lowStorage = rows.filter(function(d) { return ["critical", "low"].includes(String(d.StorageStatusCategory || "")); }).length;
    const rebootPending = rows.filter(function(d) { return String(d.RebootPending || "").toLowerCase() === "yes"; }).length;
    const firmwareInventory = rows.filter(function(d) { return String(d.FirmwareVersion || "").trim() !== ""; }).length;
    const lenovoSBReady = rows.filter(function(d) { return String(d.LenovoSB2023Category || "").toLowerCase() === "ready"; }).length;
    const lenovoSBUpdate = rows.filter(function(d) { return String(d.LenovoSB2023Category || "").toLowerCase() === "update"; }).length;
    const autopilotEnrolled = rows.filter(function(d) { return String(d.AutopilotEnrolled || "").toLowerCase() === "yes"; }).length;

    const compliant = rows.filter(function(d) { return String(d.ComplianceState || "").toLowerCase() === "compliant"; }).length;
    const nonCompliant = rows.filter(function(d) { return String(d.ComplianceState || "").toLowerCase() === "noncompliant"; }).length;
    const complianceOther = total - compliant - nonCompliant;

    const primaryEnabled = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "enabled"; }).length;
    const primaryDisabled = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "disabled"; }).length;
    const noPrimaryUser = rows.filter(function(d) { return String(d.PrimaryUserAccountStatus || "").toLowerCase() === "no primary user"; }).length;
    const primaryUnknown = total - primaryEnabled - primaryDisabled - noPrimaryUser;

    const secureBootEnabled = rows.filter(function(d) { return String(d.SecureBootStatus || "").toLowerCase() === "enabled"; }).length;
    const defenderDeployed = rows.filter(function(d) { return String(d.DefenderStatusCategory || "").toLowerCase() === "deployed"; }).length;
    const bitLockerProtected = rows.filter(function(d) { return String(d.BitLockerStatusCategory || "").toLowerCase() === "encryptedprotected"; }).length;
    const bitLockerIntuneFallback = rows.filter(function(d) { return String(d.BitLockerStatusCategory || "").toLowerCase() === "intuneencrypted"; }).length;

    const build26100 = rows.filter(function(d) { return Number(d.OSBuild) === 26100; }).length;
    const build26200 = rows.filter(function(d) { return Number(d.OSBuild) === 26200; }).length;
    const older = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) < 26100; }).length;
    const newer = rows.filter(function(d) { return Number(d.OSBuild) && Number(d.OSBuild) > 26200; }).length;
    const osUnknown = total - build26100 - build26200 - older - newer;
    const belowTarget = rows.filter(function(d) { return String(d.OSUBRStatus || "").toLowerCase() === "below target"; }).length;

    setText("cardTotalDevices", total);
    setText("cardTotalNote", "Showing " + total + " of " + totalDeviceCount + " devices");
    setText("cardCriticalRisk", criticalRisk);
    setText("cardHighRisk", highRisk);
    setText("cardStaleDevices", staleDevices);
    setText("cardLowStorage", lowStorage);
    setText("cardRebootPending", rebootPending);
    setText("cardFirmwareInventory", firmwareInventory);
    setText("cardLenovoSBReady", lenovoSBReady);
    setText("cardLenovoSBUpdate", lenovoSBUpdate);
    setText("cardAutopilotEnrolled", autopilotEnrolled);
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
    setText("cardDefenderDeployed", defenderDeployed);
    setText("cardDefenderDeployedNote", pct(defenderDeployed, total) + "% of filtered devices");
    setText("cardBitLockerProtected", bitLockerProtected);
    setText("cardBitLockerProtectedNote", pct(bitLockerProtected, total) + "% of filtered devices");
    setText("cardBitLockerIntuneFallback", bitLockerIntuneFallback);
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

function drawerValue(value) {
    return escapeHtml(value === null || value === undefined || value === "" ? "—" : value);
}

function drawerSection(title, rows) {
    return '<div class="drawer-section"><h3>' + escapeHtml(title) + '</h3><div class="drawer-kv">' +
        rows.map(function(row) {
            return '<div class="k">' + escapeHtml(row[0]) + '</div><div class="v">' + drawerValue(row[1]) + '</div>';
        }).join("") +
        '</div></div>';
}

function openDeviceDrawer(deviceId) {
    const id = String(deviceId || "");
    const d = devices.find(function(x) {
        return String(x.IntuneDeviceId || x.DeviceName) === id;
    });

    if (!d) return;

    document.getElementById("drawerTitle").innerText = d.DeviceName || "Device details";
    document.getElementById("drawerSubtitle").innerText = (d.UserDisplayName || d.UserPrincipalName || "") + " • " + (d.OSFriendlyVersion || "");

    const html = [
        drawerSection("🚦 Risk", [
            ["Risk level", d.RiskLevel],
            ["Risk score", d.RiskScore],
            ["Risk reasons", d.RiskReasons],
            ["Compliance", d.ComplianceState],
            ["Check-in health", d.CheckInHealth],
            ["Days since check-in", d.DaysSinceCheckIn]
        ]),
        drawerSection("👤 User / enrollment", [
            ["Primary user", d.PrimaryUser],
            ["Primary user status", d.PrimaryUserAccountStatus],
            ["User email", d.EmailAddress],
            ["Autopilot enrolled", d.AutopilotEnrolled],
            ["Autopilot profile", d.AutopilotProfile],
            ["Autopilot group tag", d.AutopilotGroupTag],
            ["Enrollment quality", d.EnrollmentQuality],
            ["Enrollment age days", d.EnrollmentAgeDays],
            ["Owner type", d.OwnerType],
            ["Registration state", d.RegistrationState],
            ["Management agent", d.ManagementAgent]
        ]),
        drawerSection("🛡️ Security", [
            ["Secure Boot", d.SecureBootStatus],
            ["Reboot pending", d.RebootPending],
            ["CBS reboot pending", d.CBSRebootPending],
            ["Windows Update reboot required", d.WindowsUpdateRebootRequired],
            ["Defender", d.DefenderStatus],
            ["Real-time protection", d.DefenderRealTimeProtection],
            ["Defender signature", d.DefenderSignatureVersion],
            ["BitLocker", d.BitLockerStatus],
            ["BitLocker source", d.BitLockerSource],
            ["Disk encryption %", d.DiskEncryptionPercentage],
            ["BL volume", d.BitLockerVolumeStatus],
            ["BL protection", d.BitLockerProtectionStatus],
            ["BL protectors", d.BitLockerKeyProtectors]
        ]),
        drawerSection("🪟 OS / hardware", [
            ["OS", d.OSFriendlyVersion],
            ["OS version", d.OSVersion],
            ["Build", d.OSBuild],
            ["UBR", d.OSUBR],
            ["UBR status", d.OSUBRStatus],
            ["Manufacturer", d.Manufacturer],
            ["Model", d.Model],
            ["Serial", d.SerialNumber],
            ["Firmware manufacturer", d.FirmwareManufacturer],
            ["Firmware version", d.FirmwareVersion],
            ["Firmware release date", d.FirmwareReleaseDate],
            ["Lenovo SB Certificate 2023 readiness", d.LenovoSB2023Readiness],
            ["Lenovo product", d.LenovoSB2023Product],
            ["Lenovo model prefix", d.LenovoSB2023ModelPrefix],
            ["Lenovo required BIOS", d.LenovoSB2023RequiredBios],
            ["Lenovo current BIOS", d.LenovoSB2023CurrentBios],
            ["Lenovo compare method", d.LenovoSB2023CompareMethod],
            ["Lenovo compare detail", d.LenovoSB2023CompareDetail],
            ["BIOS mode", d.BiosMode],
            ["Device SKU", d.DeviceSKU],
            ["System board model", d.SystemBoardModel],
            ["TPM version", d.TPMVersion],
            ["TPM ready", d.TpmReady]
        ]),
        drawerSection("💾 Storage / identity", [
            ["Free storage %", d.FreeStoragePercent],
            ["Storage status", d.StorageStatus],
            ["Total storage GB", d.TotalStorageGB],
            ["Free storage GB", d.FreeStorageGB],
            ["Duplicate device name", d.DuplicateDeviceName],
            ["Duplicate serial", d.DuplicateSerial],
            ["Intune device ID", d.IntuneDeviceId],
            ["Entra device ID", d.AzureADDeviceId],
            ["Last check-in", d.LastSyncDateTime],
            ["Enrolled date", d.EnrolledDateTime]
        ])
    ].join("");

    document.getElementById("drawerContent").innerHTML = html;
    document.getElementById("drawerBackdrop").classList.add("open");
    document.getElementById("deviceDrawer").classList.add("open");
}

function closeDeviceDrawer() {
    document.getElementById("drawerBackdrop").classList.remove("open");
    document.getElementById("deviceDrawer").classList.remove("open");
}

document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeDeviceDrawer();
});

function renderTable(rows) {
    const tbody = document.getElementById("deviceTableBody");
    document.getElementById("visibleCount").innerText = "Showing " + rows.length + " of " + devices.length + " devices";

    tbody.innerHTML = rows.map(function(d) {
        const deviceId = escapeHtml(d.IntuneDeviceId || d.DeviceName);
        return "" +
            "<tr class='clickable-row' onclick=\"openDeviceDrawer('" + deviceId + "')\">" +
            "<td>" + pill(d.RiskLevel || "Low", "risk") + "</td>" +
            "<td>" + escapeHtml(d.RiskReasons) + "</td>" +
            "<td>" + escapeHtml(d.DeviceName) + "</td>" +
            "<td>" + escapeHtml(d.UserDisplayName || d.UserPrincipalName) + "</td>" +
            "<td>" + escapeHtml(d.PrimaryUser) + "</td>" +
            "<td>" + pill(d.PrimaryUserAccountStatus, "primaryuser") + "</td>" +
            "<td>" + escapeHtml(d.EmailAddress) + "</td>" +
            "<td>" + pill(d.SecureBootStatus || "Unknown", "secureboot") + "</td>" +
            "<td>" + pill(d.RebootPending || "Unknown", "reboot") + "</td>" +
            "<td>" + pill(d.DefenderStatus || "Unknown", "defender") + "</td>" +
            "<td>" + pill(d.DefenderRealTimeProtection || "Unknown", "defender") + "</td>" +
            "<td>" + escapeHtml(d.DefenderSignatureVersion) + "</td>" +
            "<td>" + pill(d.BitLockerStatus || "Missing remediation result", "bitlocker") + "</td>" +
            "<td>" + escapeHtml(d.DiskEncryptionPercentage) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerVolumeStatus) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerProtectionStatus) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerKeyProtectors) + "</td>" +
            "<td>" + escapeHtml(d.BitLockerSource) + "</td>" +
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
            "<td>" + pill(d.AutopilotEnrolled || "No", "autopilot") + "</td>" +
            "<td>" + pill(d.EnrollmentQuality || "Unknown", "enrollment") + "</td>" +
            "<td>" + escapeHtml(d.AutopilotProfile) + "</td>" +
            "<td>" + escapeHtml(d.FirmwareVersion) + "</td>" +
            "<td>" + pill(d.LenovoSB2023Readiness || "Review", "lenovo") + "</td>" +
            "<td>" + escapeHtml(d.LenovoSB2023RequiredBios) + "</td>" +
            "<td>" + escapeHtml(d.LenovoSB2023Product) + "</td>" +
            "<td>" + escapeHtml(d.BiosMode) + "</td>" +
            "<td>" + escapeHtml(d.TPMVersion || d.TpmReady) + "</td>" +
            "<td>" + escapeHtml(d.LastSyncDateTime) + "</td>" +
            "<td>" + pill(d.CheckInHealth || "Unknown", "checkin") + "</td>" +
            "<td>" + escapeHtml(d.DaysSinceCheckIn) + "</td>" +
            "<td>" + escapeHtml(d.FreeStoragePercent) + "</td>" +
            "<td>" + pill(d.StorageStatus || "Unknown", "storage") + "</td>" +
            "<td>" + pill(d.DuplicateDeviceName || "No", "duplicate") + "</td>" +
            "<td>" + pill(d.DuplicateSerial || "No", "duplicate") + "</td>" +
            "</tr>";
    }).join("");
}

function renderDashboard() {
    const rows = getFilteredDevices();
    updateTopIssues(rows);
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

populateDynamicFilters();
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
