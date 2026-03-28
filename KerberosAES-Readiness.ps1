Import-Module ActiveDirectory

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Kerberos AES Readiness Audit रिपोर्ट"
Write-Host "=========================================" -ForegroundColor Cyan

$Results = @()
$Now = Get-Date
$OldPasswordThreshold = $Now.AddYears(-2)

# --- 1. Get all users with relevant properties ---
$Users = Get-ADUser -Filter * -Properties `
    msDS-SupportedEncryptionTypes,
    PasswordLastSet,
    ServicePrincipalName

# --- Counters ---
$NoAES = 0
$NoEncType = 0
$OldPasswords = 0
$ServiceAccounts = 0

foreach ($User in $Users) {

    $Enc = $User.'msDS-SupportedEncryptionTypes'
    $HasAES = $false
    $IsService = $false
    $IsOldPwd = $false
    $Risk = "OK"

    # Check AES (0x08 AES128, 0x10 AES256)
    if ($Enc) {
        if (($Enc -band 0x18) -ne 0) {
            $HasAES = $true
        }
    } else {
        $NoEncType++
        $Risk = "UNKNOWN"
    }

    if (-not $HasAES -and $Enc) {
        $NoAES++
        $Risk = "HIGH"
    }

    # Service account check
    if ($User.ServicePrincipalName) {
        $IsService = $true
        $ServiceAccounts++
        if (-not $HasAES) {
            $Risk = "CRITICAL"
        }
    }

    # Old password check
    if ($User.PasswordLastSet -lt $OldPasswordThreshold) {
        $IsOldPwd = $true
        $OldPasswords++
        if ($IsService) {
            $Risk = "CRITICAL"
        } else {
            $Risk = "MEDIUM"
        }
    }

    $Results += [PSCustomObject]@{
        Name = $User.Name
        SamAccountName = $User.SamAccountName
        IsServiceAccount = $IsService
        HasAES = $HasAES
        EncryptionType = $Enc
        PasswordLastSet = $User.PasswordLastSet
        OldPassword = $IsOldPwd
        Risk = $Risk
    }
}

# --- 2. RC4 usage from DC logs ---
Write-Host "`nChecking Kerberos RC4 usage (Event ID 4769)..." -ForegroundColor Yellow

$RC4Events = @()

try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4769
        StartTime=(Get-Date).AddDays(-7)
    } -ErrorAction Stop

    foreach ($Event in $Events) {
        if ($Event.Properties[8].Value -eq 0x17) {
            $RC4Events += [PSCustomObject]@{
                Time = $Event.TimeCreated
                User = $Event.Properties[0].Value
                Service = $Event.Properties[2].Value
            }
        }
    }
}
catch {
    Write-Host "⚠️ Could not read Security log (run as admin on DC)" -ForegroundColor Red
}

# --- 3. Summary ---
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " SUMMARY"
Write-Host "=========================================" -ForegroundColor Cyan

Write-Host "Total Users Checked: $($Users.Count)"
Write-Host "Service Accounts: $ServiceAccounts"
Write-Host "Accounts WITHOUT AES: $NoAES" -ForegroundColor Red
Write-Host "Accounts WITHOUT Enc Type: $NoEncType" -ForegroundColor Yellow
Write-Host "Old Passwords (>2 years): $OldPasswords" -ForegroundColor Yellow
Write-Host "RC4 Events (last 7 days): $($RC4Events.Count)" -ForegroundColor Red

# --- 4. Risk evaluation ---
$GlobalRisk = "LOW"

if ($RC4Events.Count -gt 0 -or $NoAES -gt 0) {
    $GlobalRisk = "HIGH"
}
elseif ($OldPasswords -gt 0 -or $NoEncType -gt 0) {
    $GlobalRisk = "MEDIUM"
}

Write-Host "`nGlobal Risk Level: $GlobalRisk" -ForegroundColor Magenta

# --- 5. Export detailed report ---
$ReportPath = "$env:TEMP\Kerberos_Audit_Report.csv"
$Results | Export-Csv -NoTypeInformation -Path $ReportPath

Write-Host "`nDetailed report exported to: $ReportPath" -ForegroundColor Green

# --- 6. Show top risky accounts ---
Write-Host "`nTop Risky Accounts:" -ForegroundColor Red
$Results | Where-Object {$_.Risk -in @("CRITICAL","HIGH")} |
Select Name,SamAccountName,IsServiceAccount,HasAES,OldPassword,Risk |
Format-Table -AutoSize

# --- 7. Show RC4 usage ---
if ($RC4Events.Count -gt 0) {
    Write-Host "`nRC4 Usage Detected (these MUST be fixed):" -ForegroundColor Red
    $RC4Events | Select -First 20 | Format-Table -AutoSize
}
else {
    Write-Host "`nNo RC4 usage detected 🎉" -ForegroundColor Green
}
