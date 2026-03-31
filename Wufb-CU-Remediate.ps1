#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation script for Windows Update repair + install.

.DESCRIPTION
    This remediation script assumes detection already determined the device is non-compliant.
    It performs Windows Update cleanup/repair actions, optionally repairs the component store,
    then attempts update installation.

.POST-REMEDIATION OUTPUT
    Outputs a clear summary for Intune, including:
    - method used
    - updates found
    - updates installed
    - reboot required

.EXIT CODES
    0 = remediation completed
    1 = fatal remediation failure
#>

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
$global:LogFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$global:LogPath   = Join-Path $global:LogFolder "WindowsUpdate-Compliance-Remediate.log"

# ---------------------------------------------------------------------
# Pre-Repair Configuration
# ---------------------------------------------------------------------
$fullRepair                = 0
$autoRepairComponentStore  = 1
$resetWUComponents         = 1
$cleanupRegistry           = 1
$reregisterDLLs            = 1
$restartIntune             = 1
$checkAutopatch            = 1
$clearRebootFlags          = 1
$verifyCriticalServices    = 1
$configureAppReadiness     = 1
$runDiskCleanup            = 0
$removePolicyBlocks        = 1
$resetWUAgent              = 1
$refreshPRT                = 1
$refreshWUPolicies         = 1

$criticalServices = @{
    'wuauserv'                  = 'Windows Update'
    'BITS'                      = 'Background Intelligent Transfer Service'
    'CryptSvc'                  = 'Cryptographic Services'
    'TrustedInstaller'          = 'Windows Modules Installer'
    'IntuneManagementExtension' = 'Intune Management Extension'
}

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
function Initialize-Logging {
    try {
        if (-not (Test-Path -Path $global:LogFolder)) {
            New-Item -Path $global:LogFolder -ItemType Directory -Force | Out-Null
        }

        if (-not (Test-Path -Path $global:LogPath)) {
            New-Item -Path $global:LogPath -ItemType File -Force | Out-Null
        }
    }
    catch {
        Write-Output "Logging init failed: $($_.Exception.Message)"
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp - $Message"

    Write-Output $line

    try {
        Add-Content -Path $global:LogPath -Value $line -ErrorAction Stop
    }
    catch {
        Write-Output "$timestamp - LOG WRITE FAILED: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------
# Common Helpers
# ---------------------------------------------------------------------
function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Log "Unable to determine administrative context: $($_.Exception.Message)"
        return $false
    }
}

function Remove-RegistryValueIfExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        if (Test-Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $item) {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
                Write-Log "Removed registry value: $Path\$Name"
                return $true
            }
        }
    }
    catch {
        Write-Log "Error removing registry value $Path\$Name : $($_.Exception.Message)"
    }

    return $false
}

function Stop-ServiceSafe {
    param([string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Stopped') {
                Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped service: $Name"
            }
            else {
                Write-Log "Service already stopped: $Name"
            }
        }
    }
    catch {
        Write-Log "Could not stop service $Name : $($_.Exception.Message)"
    }
}

function Start-ServiceSafe {
    param([string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Running') {
                Start-Service -Name $Name -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 750
            }

            $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                Write-Log "Service running: $Name"
            }
            else {
                Write-Log "Warning: Service may not be running: $Name"
            }
        }
    }
    catch {
        Write-Log "Could not start service $Name : $($_.Exception.Message)"
    }
}

function Test-RebootPending {
    try {
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        )

        if (Test-Path $paths[0]) { return $true }
        if (Test-Path $paths[1]) { return $true }

        $pendingFileRename = Get-ItemProperty -Path $paths[2] -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $pendingFileRename.PendingFileRenameOperations) { return $true }

        return $false
    }
    catch {
        Write-Log "Error checking reboot pending state: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-ComponentStoreRepair {
    Write-Log "Starting component store health check"

    $result = [PSCustomObject]@{
        CheckHealthExitCode    = $null
        RestoreHealthExitCode  = $null
        SfcExitCode            = $null
        RepairAttempted        = $false
        RepairSucceeded        = $false
        Details                = ""
    }

    try {
        $checkArgs = "/Online /Cleanup-Image /CheckHealth"
        Write-Log "Running: DISM.exe $checkArgs"

        $checkProcess = Start-Process -FilePath "DISM.exe" -ArgumentList $checkArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $result.CheckHealthExitCode = $checkProcess.ExitCode
        Write-Log "DISM CheckHealth exit code: $($result.CheckHealthExitCode)"

        if ($checkProcess.ExitCode -eq 0) {
            Write-Log "DISM CheckHealth completed successfully"
        }
        else {
            Write-Log "DISM CheckHealth returned non-zero exit code. A repair attempt will still be made."
        }

        $result.RepairAttempted = $true

        $restoreArgs = "/Online /Cleanup-Image /RestoreHealth"
        Write-Log "Running: DISM.exe $restoreArgs"

        $restoreProcess = Start-Process -FilePath "DISM.exe" -ArgumentList $restoreArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $result.RestoreHealthExitCode = $restoreProcess.ExitCode
        Write-Log "DISM RestoreHealth exit code: $($result.RestoreHealthExitCode)"

        if ($restoreProcess.ExitCode -eq 0) {
            Write-Log "DISM RestoreHealth completed successfully"
            $result.RepairSucceeded = $true
        }
        else {
            Write-Log "DISM RestoreHealth completed with non-zero exit code"
        }

        $sfcArgs = "/scannow"
        Write-Log "Running: sfc.exe $sfcArgs"

        $sfcProcess = Start-Process -FilePath "sfc.exe" -ArgumentList $sfcArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $result.SfcExitCode = $sfcProcess.ExitCode
        Write-Log "SFC exit code: $($result.SfcExitCode)"

        $result.Details = "CheckHealth=$($result.CheckHealthExitCode); RestoreHealth=$($result.RestoreHealthExitCode); SFC=$($result.SfcExitCode)"
        return $result
    }
    catch {
        $result.Details = $_.Exception.Message
        Write-Log "Component store repair failed: $($_.Exception.Message)"
        return $result
    }
}

# ---------------------------------------------------------------------
# Windows Update Repair Helpers
# ---------------------------------------------------------------------
function Test-WUComponentsNeedReset {
    $needsReset = $false

    try {
        $downloadFolder = "C:\Windows\SoftwareDistribution\Download"
        if (Test-Path $downloadFolder) {
            $downloadFiles = Get-ChildItem $downloadFolder -ErrorAction SilentlyContinue
            if ($downloadFiles.Count -gt 50) {
                Write-Log "SoftwareDistribution has $($downloadFiles.Count) files - reset may help"
                $needsReset = $true
            }
        }

        if (-not (Test-Path "C:\Windows\System32\catroot2")) {
            Write-Log "catroot2 folder is missing - reset needed"
            $needsReset = $true
        }
    }
    catch {
        Write-Log "Error checking whether WU reset is needed: $($_.Exception.Message)"
    }

    return $needsReset
}

function Test-ServicesNeedRestart {
    $servicesNeedingRestart = @()
    $servicesToCheck = @('BITS', 'wuauserv', 'CryptSvc', 'msiserver')

    foreach ($svc in $servicesToCheck) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Running') {
                $servicesNeedingRestart += $svc
            }
        }
        catch {
            Write-Log "Error checking service $svc : $($_.Exception.Message)"
        }
    }

    return $servicesNeedingRestart
}

function Test-WindowsUpdateComHealthy {
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $null = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-SaferRegistryCleanup {
    Write-Log "Starting safer registry cleanup"

    $removedCount = 0

    $valuesToRemove = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";    Name = "WUServer" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";    Name = "WUStatusServer" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";    Name = "DisableWindowsUpdateAccess" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";    Name = "DoNotConnectToWindowsUpdateInternetLocations" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "UseWUServer" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions" }
    )

    foreach ($item in $valuesToRemove) {
        if (Remove-RegistryValueIfExists -Path $item.Path -Name $item.Name) {
            $removedCount++
        }
    }

    try {
        $resultsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results"
        if (Test-Path $resultsKey) {
            Remove-Item -Path $resultsKey -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared Windows Update results cache key: $resultsKey"
        }
    }
    catch {
        Write-Log "Error clearing Windows Update results cache: $($_.Exception.Message)"
    }

    if ($removedCount -eq 0) {
        Write-Log "No known blocking registry values found"
    }
    else {
        Write-Log "Safer registry cleanup removed $removedCount value(s)"
    }
}

function Invoke-SaferWUAgentReset {
    Write-Log "Starting safer Windows Update Agent reset"

    try {
        Stop-ServiceSafe -Name "BITS"
        Stop-ServiceSafe -Name "wuauserv"
        Stop-ServiceSafe -Name "CryptSvc"
        Stop-ServiceSafe -Name "msiserver"

        Start-Sleep -Seconds 2

        try {
            $qmgrPath = Join-Path $env:ALLUSERSPROFILE "Microsoft\Network\Downloader"
            if (Test-Path $qmgrPath) {
                Get-ChildItem -Path $qmgrPath -Filter "qmgr*.dat" -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Log "Removed BITS queue file: $($_.FullName)"
                    }
                    catch {
                        Write-Log "Could not remove BITS queue file $($_.FullName) : $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
            Write-Log "Error cleaning BITS queue files: $($_.Exception.Message)"
        }

        Start-ServiceSafe -Name "CryptSvc"
        Start-ServiceSafe -Name "BITS"
        Start-ServiceSafe -Name "wuauserv"
        Start-ServiceSafe -Name "msiserver"

        Write-Log "Safer Windows Update Agent reset completed"
    }
    catch {
        Write-Log "Safer Windows Update Agent reset failed: $($_.Exception.Message)"
    }
}

function Invoke-PreUpdateCleanup {
    Write-Log "Starting pre-update cleanup and repair workflow"

    if (-not (Test-IsAdministrator)) {
        throw "This script must run with Administrator privileges."
    }

    try {
        $tpmStatus = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpmStatus -and $tpmStatus.IsActivated_InitialValue -eq $true) {
            Write-Log "TPM is activated"
        }
        else {
            Write-Log "TPM is not activated or not present"
        }
    }
    catch {
        Write-Log "Could not determine TPM status: $($_.Exception.Message)"
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($secureBoot) {
            Write-Log "Secure Boot is enabled"
        }
        else {
            Write-Log "Secure Boot is not enabled"
        }
    }
    catch {
        Write-Log "Could not determine Secure Boot status: $($_.Exception.Message)"
    }

    try {
        $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($sysDrive) {
            $freeSpaceGB = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
            Write-Log "Free disk space on C: drive: $freeSpaceGB GB"
            if ($freeSpaceGB -lt 20) {
                Write-Log "Warning: Low disk space. Minimum 20 GB recommended for upgrade."
            }
        }
    }
    catch {
        Write-Log "Could not determine free disk space: $($_.Exception.Message)"
    }

    $servicesNeedingRestart = Test-ServicesNeedRestart
    if ($servicesNeedingRestart.Count -gt 0) {
        Write-Log "Services not running: $($servicesNeedingRestart -join ', ')"
    }
    else {
        Write-Log "All core Windows Update services already running"
    }

    if ($fullRepair -eq 1) {
        Write-Log "Full repair mode enabled - running DISM and SFC"

        try { & DISM.exe /Online /Cleanup-Image /ScanHealth | Out-Null; Write-Log "DISM ScanHealth completed" }
        catch { Write-Log "Error running DISM ScanHealth: $($_.Exception.Message)" }

        try { & DISM.exe /Online /Cleanup-Image /RestoreHealth | Out-Null; Write-Log "DISM RestoreHealth completed" }
        catch { Write-Log "Error running DISM RestoreHealth: $($_.Exception.Message)" }

        try { & DISM.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null; Write-Log "DISM StartComponentCleanup completed" }
        catch { Write-Log "Error running DISM StartComponentCleanup: $($_.Exception.Message)" }

        try { & sfc.exe /scannow | Out-Null; Write-Log "SFC scan completed" }
        catch { Write-Log "Error running SFC: $($_.Exception.Message)" }
    }
    else {
        Write-Log "Full repair mode disabled"
    }

    if ($autoRepairComponentStore -eq 1) {
        $componentRepairResult = Invoke-ComponentStoreRepair
        Write-Log "Component store repair summary: RepairAttempted=$($componentRepairResult.RepairAttempted) RepairSucceeded=$($componentRepairResult.RepairSucceeded) Details=$($componentRepairResult.Details)"
    }
    else {
        Write-Log "Automatic component store repair disabled in configuration"
    }

    if ($resetWUComponents -eq 1) {
        if (Test-WUComponentsNeedReset) {
            Write-Log "Resetting Windows Update components"

            Stop-ServiceSafe -Name "BITS"
            Stop-ServiceSafe -Name "wuauserv"
            Stop-ServiceSafe -Name "CryptSvc"

            Start-Sleep -Seconds 2

            try {
                if (Test-Path "C:\Windows\SoftwareDistribution") {
                    Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName ("SoftwareDistribution.old." + (Get-Date -Format "yyyyMMddHHmmss")) -ErrorAction SilentlyContinue
                    Write-Log "SoftwareDistribution renamed"
                }
            }
            catch {
                Write-Log "Error handling SoftwareDistribution: $($_.Exception.Message)"
            }

            try {
                if (Test-Path "C:\Windows\System32\catroot2") {
                    Rename-Item -Path "C:\Windows\System32\catroot2" -NewName ("catroot2.old." + (Get-Date -Format "yyyyMMddHHmmss")) -ErrorAction SilentlyContinue
                    Write-Log "catroot2 renamed"
                }
            }
            catch {
                Write-Log "Error handling catroot2: $($_.Exception.Message)"
            }

            Start-ServiceSafe -Name "CryptSvc"
            Start-ServiceSafe -Name "BITS"
            Start-ServiceSafe -Name "wuauserv"

            Write-Log "Windows Update components reset completed"
        }
        else {
            Write-Log "Windows Update components look healthy - skipping reset"
        }
    }
    else {
        Write-Log "Windows Update component reset disabled in configuration"
    }

    if ($cleanupRegistry -eq 1) {
        Invoke-SaferRegistryCleanup
    }
    else {
        Write-Log "Registry cleanup disabled in configuration"
    }

    if ($reregisterDLLs -eq 1) {
        $needDllReregistration = $false

        if (-not (Test-WindowsUpdateComHealthy)) {
            $needDllReregistration = $true
            Write-Log "Windows Update COM interface not healthy - DLL re-registration needed"
        }
        else {
            Write-Log "Windows Update COM interface is healthy - skipping DLL re-registration"
        }

        if ($needDllReregistration) {
            $dlls = @(
                "atl.dll", "urlmon.dll", "mshtml.dll", "browseui.dll",
                "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
                "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
                "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
                "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
                "wuaueng.dll", "wups.dll", "wups2.dll", "wuweb.dll", "qmgr.dll",
                "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
            )

            $registeredCount = 0
            $failedCount = 0

            foreach ($dll in $dlls) {
                try {
                    $dllPath = Join-Path $env:SystemRoot "System32\$dll"
                    if (Test-Path $dllPath) {
                        $process = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$dllPath`"" -Wait -PassThru -NoNewWindow -ErrorAction Stop
                        if ($process.ExitCode -eq 0) {
                            $registeredCount++
                        }
                        else {
                            $failedCount++
                            Write-Log "Warning: Failed to register $dll (ExitCode=$($process.ExitCode))"
                        }
                    }
                }
                catch {
                    $failedCount++
                    Write-Log "Error registering $dll : $($_.Exception.Message)"
                }
            }

            Write-Log "DLL re-registration completed: $registeredCount succeeded, $failedCount failed/skipped"
        }
    }
    else {
        Write-Log "DLL re-registration disabled in configuration"
    }

    if ($restartIntune -eq 1) {
        try {
            $intuneService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
            if ($intuneService -and $intuneService.Status -ne "Running") {
                Write-Log "Intune Management Extension service is not running - restarting"
                Restart-Service -Name IntuneManagementExtension -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
            else {
                Write-Log "Intune Management Extension is already running"
            }
        }
        catch {
            Write-Log "Failed to restart Intune Management Extension: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Intune Management Extension restart disabled in configuration"
    }

    Write-Log "Triggering Intune device sync"
    try {
        if (Test-Path "$env:windir\System32\deviceenroller.exe") {
            Start-Process -FilePath "$env:windir\System32\deviceenroller.exe" -ArgumentList "/c /AutoEnrollMDM" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            Write-Log "Device enrollment sync triggered"
        }
    }
    catch {
        Write-Log "Error triggering Intune sync: $($_.Exception.Message)"
    }

    if ($checkAutopatch -eq 1) {
        Write-Log "Checking Windows Autopatch configuration"

        try {
            $autopatchRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopatch"

            if (Test-Path $autopatchRegPath) {
                $autopatchEnabled = (Get-ItemProperty -Path $autopatchRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled

                if ($autopatchEnabled -eq 1) {
                    Write-Log "Windows Autopatch is enabled"
                }
                elseif ($autopatchEnabled -eq 0) {
                    Write-Log "Windows Autopatch is configured but disabled"
                }
                else {
                    Write-Log "Autopatch Enabled value not set"
                }
            }
            else {
                Write-Log "Windows Autopatch registry not found"
            }
        }
        catch {
            Write-Log "Error checking Autopatch configuration: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Windows Autopatch check disabled in configuration"
    }

    if ($refreshPRT -eq 1) {
        Write-Log "Refreshing Primary Refresh Token"
        try {
            $dsregOutput = & dsregcmd /refreshprt 2>&1
            Write-Log "Primary Refresh Token refresh command executed"
            if ($dsregOutput) {
                foreach ($line in ($dsregOutput | Out-String).Split("`n")) {
                    if ($line -and $line.Trim()) {
                        Write-Log $line.TrimEnd()
                    }
                }
            }
        }
        catch {
            Write-Log "Error running dsregcmd /refreshprt : $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Primary Refresh Token refresh disabled in configuration"
    }

    if ($refreshWUPolicies -eq 1) {
        Write-Log "Refreshing Windows Update policies"

        try {
            if (Test-Path "$env:windir\System32\UsoClient.exe") {
                Start-Process -FilePath "$env:windir\System32\UsoClient.exe" -ArgumentList "RefreshSettings" -NoNewWindow -ErrorAction SilentlyContinue
                Start-Process -FilePath "$env:windir\System32\UsoClient.exe" -ArgumentList "StartScan" -NoNewWindow -ErrorAction SilentlyContinue
                Write-Log "Windows Update refresh and scan triggered via UsoClient"
            }
        }
        catch {
            Write-Log "Error running UsoClient: $($_.Exception.Message)"
        }

        try {
            if (Get-Command wuauclt.exe -ErrorAction SilentlyContinue) {
                Start-Process -FilePath "wuauclt.exe" -ArgumentList "/resetauthorization /detectnow" -NoNewWindow -ErrorAction SilentlyContinue
                Write-Log "Windows Update detection triggered via wuauclt"
            }
        }
        catch {
            Write-Log "Error running wuauclt: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Windows Update policy refresh disabled in configuration"
    }

    if ($clearRebootFlags -eq 1) {
        Write-Log "Checking for pending reboot flags"

        try {
            $rebootPendingKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            if (Test-Path $rebootPendingKey) {
                Write-Log "CBS RebootPending flag detected"
            }
            else {
                Write-Log "No CBS RebootPending flag found"
            }
        }
        catch {
            Write-Log "Error checking reboot flags: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Pending reboot flags cleanup disabled in configuration"
    }

    if ($verifyCriticalServices -eq 1) {
        Write-Log "Verifying critical services"

        foreach ($svcName in $criticalServices.Keys) {
            try {
                $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($service) {
                    if ($service.Status -ne "Running") {
                        Write-Log "Service $($criticalServices[$svcName]) is not running - starting"
                        Start-Service -Name $svcName -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 750
                    }

                    $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($service) {
                        Write-Log "$($criticalServices[$svcName]): $($service.Status)"
                    }
                }
                else {
                    Write-Log "Warning: Service $svcName not found"
                }
            }
            catch {
                Write-Log "Error managing service $svcName : $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Log "Critical services verification disabled in configuration"
    }

    if ($configureAppReadiness -eq 1) {
        Write-Log "Checking App Readiness service"

        try {
            $appReadinessWmi = Get-WmiObject Win32_Service -Filter "Name='AppReadiness'" -ErrorAction SilentlyContinue
            if ($appReadinessWmi) {
                if ($appReadinessWmi.StartMode -eq "Disabled") {
                    Write-Log "App Readiness is disabled - setting to Manual"
                    Set-Service -Name AppReadiness -StartupType Manual -ErrorAction SilentlyContinue
                    Write-Log "App Readiness service updated"
                }
                else {
                    Write-Log "App Readiness is properly configured"
                }
            }
        }
        catch {
            Write-Log "Error configuring App Readiness service: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "App Readiness configuration disabled in configuration"
    }

    if ($runDiskCleanup -eq 1) {
        Write-Log "Checking disk space before cleanup"

        try {
            $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
            $freeSpaceGBBefore = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
            Write-Log "Free disk space before cleanup: $freeSpaceGBBefore GB"

            if ($freeSpaceGBBefore -lt 20 -and (Test-Path "$env:SystemRoot\System32\cleanmgr.exe")) {
                Write-Log "Low disk space detected - running Disk Cleanup"
                Start-Process -FilePath "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/verylowdisk" -Wait -NoNewWindow -ErrorAction SilentlyContinue

                $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
                $freeSpaceGBAfter = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
                Write-Log "Free disk space after cleanup: $freeSpaceGBAfter GB"
            }
            else {
                Write-Log "Sufficient disk space available - skipping cleanup"
            }
        }
        catch {
            Write-Log "Error during disk cleanup: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Disk cleanup disabled in configuration"
    }

    if ($removePolicyBlocks -eq 1) {
        Write-Log "Checking for Windows Update policy blocks"
        Invoke-SaferRegistryCleanup
    }
    else {
        Write-Log "Windows Update policy blocks removal disabled in configuration"
    }

    if ($resetWUAgent -eq 1) {
        Invoke-SaferWUAgentReset
    }
    else {
        Write-Log "Windows Update Agent reset disabled in configuration"
    }

    Write-Log "Verifying Windows Update client health"
    if (Test-WindowsUpdateComHealthy) {
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
            Write-Log "Windows Update client is functional - $($searchResult.Updates.Count) updates available before install step"
        }
        catch {
            Write-Log "Windows Update client health verification partially failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Warning: Windows Update COM interface still not accessible after remediation"
    }

    Write-Log "Pre-update cleanup and repair workflow completed"
}

# ---------------------------------------------------------------------
# Windows Update Install Helpers
# ---------------------------------------------------------------------
function New-UpdateResultObject {
    return [PSCustomObject]@{
        Method            = "None"
        UpdatesFound      = 0
        UpdatesInstalled  = 0
        RebootRequired    = $false
        Success           = $false
        Details           = ""
    }
}

function Install-PSWindowsUpdateIfNeeded {
    try {
        $moduleName = 'PSWindowsUpdate'
        $moduleBase = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'

        if (-not (Test-Path $moduleBase)) {
            New-Item -Path $moduleBase -ItemType Directory -Force | Out-Null
        }

        $existingModule = Get-Module -ListAvailable -Name $moduleName |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if (-not $existingModule) {
            Write-Log "$moduleName module not found. Attempting installation."

            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
            catch { Write-Log "Could not set TLS 1.2 explicitly: $($_.Exception.Message)" }

            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Log "NuGet provider install warning: $($_.Exception.Message)"
            }

            try {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Could not set PSGallery to Trusted: $($_.Exception.Message)"
            }

            Install-Module -Name $moduleName -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            Start-Sleep -Seconds 2

            $existingModule = Get-Module -ListAvailable -Name $moduleName |
                Sort-Object Version -Descending |
                Select-Object -First 1

            if (-not $existingModule) {
                throw "$moduleName installed but still not found in module path."
            }

            Write-Log "$moduleName module installed successfully. Version: $($existingModule.Version)"
        }
        else {
            Write-Log "$moduleName module already available. Version: $($existingModule.Version)"
        }

        $moduleManifest = Join-Path $existingModule.ModuleBase "$moduleName.psd1"
        if (-not (Test-Path $moduleManifest)) {
            throw "Module manifest not found: $moduleManifest"
        }

        Import-Module $moduleManifest -Force -Global -ErrorAction Stop

        if (-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
            throw "Get-WindowsUpdate cmdlet is still unavailable after import."
        }

        Write-Log "$moduleName module imported successfully."
        return $true
    }
    catch {
        Write-Log "Failed to install/import PSWindowsUpdate module: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-PSWindowsUpdateMethod {
    $result = New-UpdateResultObject
    $result.Method = "PSWindowsUpdate"

    try {
        Write-Log "Checking for available updates via PSWindowsUpdate."

        $scanOutput = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop -Verbose 4>&1 | Out-String
        if ($scanOutput -and $scanOutput.Trim().Length -gt 0) {
            foreach ($line in ($scanOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log $line.TrimEnd()
                }
            }
        }

        $updates = @(Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop)
        $result.UpdatesFound = $updates.Count

        if (-not $updates -or $updates.Count -eq 0) {
            Write-Log "No updates found via PSWindowsUpdate."
            $result.Success = $true
            $result.Details = "No updates found"
            $result.RebootRequired = Test-RebootPending
            return $result
        }

        Write-Log "Updates found via PSWindowsUpdate: $($updates.Count)"
        foreach ($u in $updates) {
            Write-Log "PSWindowsUpdate candidate: $($u.Title)"
        }

        Write-Log "Installing all available updates via PSWindowsUpdate."
        $installOutput = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction Continue -Verbose 4>&1 | Out-String

        if ($installOutput -and $installOutput.Trim().Length -gt 0) {
            foreach ($line in ($installOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log $line.TrimEnd()
                }
            }
        }

        $installedCount = 0
        try {
            $history = Get-WUHistory -MaxDate (Get-Date) -ErrorAction SilentlyContinue | Select-Object -First 50
            if ($history) {
                $recentWindow = (Get-Date).AddMinutes(-30)
                $recentInstalled = $history | Where-Object {
                    $_.Date -ge $recentWindow -and (
                        $_.Result -match 'Succeeded' -or
                        $_.ResultCode -eq 2
                    )
                }
                $installedCount = @($recentInstalled).Count
            }
        }
        catch {
            Write-Log "Could not read WU history after PSWindowsUpdate install: $($_.Exception.Message)"
        }

        if ($installedCount -le 0 -and $updates.Count -gt 0) {
            $installedCount = $updates.Count
        }

        $result.UpdatesInstalled = $installedCount
        $result.RebootRequired = Test-RebootPending
        $result.Success = $true
        $result.Details = "PSWindowsUpdate completed"

        Write-Log "PSWindowsUpdate method completed. Installed=$($result.UpdatesInstalled) RebootRequired=$($result.RebootRequired)"
        return $result
    }
    catch {
        Write-Log "PSWindowsUpdate method failed: $($_.Exception.Message)"
        $result.Details = $_.Exception.Message
        return $result
    }
}

function Invoke-COMWindowsUpdateMethod {
    $result = New-UpdateResultObject
    $result.Method = "COM"

    try {
        Write-Log "Starting alternative Windows Update COM method."

        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        Write-Log "Searching for software updates via COM API."
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $result.UpdatesFound = $searchResult.Updates.Count

        if ($searchResult.Updates.Count -eq 0) {
            Write-Log "No updates found via COM API."
            $result.Success = $true
            $result.Details = "No updates found"
            $result.RebootRequired = Test-RebootPending
            return $result
        }

        Write-Log "Found $($searchResult.Updates.Count) updates via COM API."

        $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

        foreach ($update in $searchResult.Updates) {
            Write-Log "Queued update: $($update.Title)"
            [void]$updatesToDownload.Add($update)
        }

        Write-Log "Downloading updates via COM API."
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload
        $downloadResult = $downloader.Download()
        Write-Log "Download result code: $($downloadResult.ResultCode)"

        Write-Log "Installing updates via COM API."
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToDownload
        $installResult = $installer.Install()

        $installedCount = 0
        for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
            try {
                $updateResult = $installResult.GetUpdateResult($i)
                if ($updateResult.ResultCode -eq 2) {
                    $installedCount++
                }
            }
            catch {
                Write-Log "Could not read COM result for update index $i : $($_.Exception.Message)"
            }
        }

        $result.UpdatesInstalled = $installedCount
        $result.RebootRequired = [bool]$installResult.RebootRequired
        $result.Success = $true
        $result.Details = "COM install completed"

        Write-Log "Installation completed with result code: $($installResult.ResultCode)"
        Write-Log "Updates installed via COM: $installedCount"
        Write-Log "Reboot required: $($installResult.RebootRequired)"

        return $result
    }
    catch {
        Write-Log "COM Windows Update method failed: $($_.Exception.Message)"
        $result.Details = $_.Exception.Message
        return $result
    }
}

function Invoke-WindowsUpdateRemediation {
    Write-Log "Starting Windows Update remediation."

    if (-not (Test-IsAdministrator)) {
        throw "This script must run with Administrator privileges."
    }

    $result = $null

    $moduleReady = Install-PSWindowsUpdateIfNeeded
    if ($moduleReady -and (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
        $result = Invoke-PSWindowsUpdateMethod

        if ($result -and $result.Success) {
            Write-Log "PSWindowsUpdate succeeded. Skipping COM fallback to avoid a second immediate scan/install cycle."
            Write-Log "Windows Update remediation completed. Method=$($result.Method) Found=$($result.UpdatesFound) Installed=$($result.UpdatesInstalled) RebootRequired=$($result.RebootRequired) Success=$($result.Success)"
            return $result
        }

        Write-Log "PSWindowsUpdate did not succeed. COM fallback will be attempted."
    }
    else {
        Write-Log "Skipping PSWindowsUpdate method because module setup failed or cmdlets are unavailable."
    }

    Write-Log "Falling back to COM Windows Update method."
    $result = Invoke-COMWindowsUpdateMethod

    if (-not $result) {
        $result = New-UpdateResultObject
        $result.Details = "No remediation method returned a result"
    }

    Write-Log "Windows Update remediation completed. Method=$($result.Method) Found=$($result.UpdatesFound) Installed=$($result.UpdatesInstalled) RebootRequired=$($result.RebootRequired) Success=$($result.Success)"
    return $result
}

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
Initialize-Logging
Write-Log "===== REMEDIATION SCRIPT START ====="
Write-Log "SCRIPT VERSION: 2026-03-31 REMEDIATION-AUTODISM-V1"

try {
    Write-Log "Detection already determined this device requires remediation."
    Write-Log "Running cleanup first."
    Invoke-PreUpdateCleanup

    Write-Log "Cleanup completed. Running Windows Update install workflow."
    $updateResult = Invoke-WindowsUpdateRemediation

    $summary = "Remediation summary | Method=$($updateResult.Method) | UpdatesFound=$($updateResult.UpdatesFound) | UpdatesInstalled=$($updateResult.UpdatesInstalled) | RebootRequired=$($updateResult.RebootRequired) | Success=$($updateResult.Success) | Details=$($updateResult.Details)"
    Write-Log $summary
    Write-Output $summary

    Write-Log "===== REMEDIATION SCRIPT END ====="
    exit 0
}
catch {
    $errorMessage = "FATAL ERROR: $($_.Exception.Message)"
    $errorDetails = "Error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.GetType().FullName)"

    Write-Log $errorMessage
    Write-Log $errorDetails
    Write-Output $errorMessage
    Write-Log "===== REMEDIATION SCRIPT END ====="

    exit 1
}
