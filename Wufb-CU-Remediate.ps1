#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation script for Windows Update repair + install.

.DESCRIPTION
    This remediation script assumes detection already determined the device is non-compliant.
    It performs Windows Update cleanup/repair actions, optionally repairs the component store,
    then attempts update installation.

.POST-REMEDIATION OUTPUT
    Outputs:
    - technical remediation summary
    - friendly CU install summary
    - scheduled reboot status when a reboot is required

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
        Write-Verbose "Logging init failed: $($_.Exception.Message)"
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp - $Message"

    try {
        Add-Content -Path $global:LogPath -Value $line -ErrorAction Stop
    }
    catch {
        Write-Verbose "LOG WRITE FAILED: $($_.Exception.Message)"
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

function Get-OSBuildInfo {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        return [PSCustomObject]@{
            CurrentBuild = [string]$cv.CurrentBuildNumber
            UBR          = [string]$cv.UBR
            FullVersion  = "10.0.$($cv.CurrentBuildNumber).$($cv.UBR)"
        }
    }
    catch {
        Write-Log "Could not read current OS build info: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------
# Scheduled Reboot Helpers
# ---------------------------------------------------------------------
function Get-NextOneAM {
    try {
        $now = Get-Date
        $target = Get-Date -Hour 1 -Minute 0 -Second 0

        if ($now -ge $target) {
            $target = $target.AddDays(1)
        }

        return $target
    }
    catch {
        Write-Log "Failed to calculate next 1 AM reboot time: $($_.Exception.Message)"
        return $null
    }
}

function Test-WakeTimersEnabled {
    try {
        $output = powercfg /q SCHEME_CURRENT SUB_SLEEP RTCWAKE 2>$null | Out-String
        if ($output -match 'Current AC Power Setting Index:\s*0x0' -and $output -match 'Current DC Power Setting Index:\s*0x0') {
            return $false
        }

        return $true
    }
    catch {
        Write-Log "Could not verify wake timer settings: $($_.Exception.Message)"
        return $null
    }
}

function Enable-WakeTimersForBatteryAndAC {
    try {
        Write-Log "Configuring Allow wake timers for AC and battery."

        $beforeOutput = powercfg /q SCHEME_CURRENT SUB_SLEEP RTCWAKE 2>$null | Out-String
        if ($beforeOutput) {
            foreach ($line in ($beforeOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log "RTCWAKE BEFORE: $($line.TrimEnd())"
                }
            }
        }

        & powercfg /setacvalueindex scheme_current sub_sleep rtcwake 1 | Out-Null
        & powercfg /setdcvalueindex scheme_current sub_sleep rtcwake 1 | Out-Null
        & powercfg /S scheme_current | Out-Null

        Start-Sleep -Seconds 1

        $afterOutput = powercfg /q SCHEME_CURRENT SUB_SLEEP RTCWAKE 2>$null | Out-String
        if ($afterOutput) {
            foreach ($line in ($afterOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log "RTCWAKE AFTER: $($line.TrimEnd())"
                }
            }
        }

        $acEnabled = $false
        $dcEnabled = $false

        if ($afterOutput -match 'Current AC Power Setting Index:\s*0x00000001') {
            $acEnabled = $true
        }
        if ($afterOutput -match 'Current DC Power Setting Index:\s*0x00000001') {
            $dcEnabled = $true
        }

        if ($acEnabled -and $dcEnabled) {
            Write-Log "Allow wake timers successfully enabled for both AC and battery."
            return $true
        }

        Write-Log "Warning: Could not confirm Allow wake timers is enabled for both AC and battery."
        return $false
    }
    catch {
        Write-Log "Failed to configure Allow wake timers: $($_.Exception.Message)"
        return $false
    }
}

function Register-ForcedRebootScheduledTask {
    param(
        [string]$TaskName = "Intune-WindowsUpdate-ForcedReboot-1AM"
    )

    try {
        $nextRun = Get-NextOneAM
        if (-not $nextRun) {
            throw "Could not determine next 1 AM run time."
        }

        Write-Log "Preparing scheduled reboot task '$TaskName' for $($nextRun.ToString('yyyy-MM-dd HH:mm:ss'))"

        $wakeTimerConfigOk = Enable-WakeTimersForBatteryAndAC
        if ($wakeTimerConfigOk) {
            Write-Log "Wake timers are enabled for AC and battery before creating the reboot task."
        }
        else {
            Write-Log "Warning: Wake timers could not be fully confirmed for AC and battery. The task will still be created with WakeToRun."
        }

        $wakeTimers = Test-WakeTimersEnabled
        if ($wakeTimers -eq $false) {
            Write-Log "Warning: Wake timers appear to be disabled in the active power plan. Task may not wake the device from sleep."
        }
        elseif ($wakeTimers -eq $true) {
            Write-Log "Wake timers appear to be enabled in the active power plan."
        }
        else {
            Write-Log "Could not confirm whether wake timers are enabled."
        }

        try {
            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($existingTask) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "Removed existing scheduled task '$TaskName'"
            }
        }
        catch {
            Write-Log "Could not remove existing scheduled task '$TaskName': $($_.Exception.Message)"
        }

        $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /f /t 0"
        $trigger = New-ScheduledTaskTrigger -Once -At $nextRun
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -WakeToRun `
            -MultipleInstances IgnoreNew

        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

        Write-Log "Scheduled reboot task '$TaskName' created successfully for $($nextRun.ToString('yyyy-MM-dd HH:mm:ss')) with WakeToRun enabled"
        return $true
    }
    catch {
        Write-Log "Failed to create scheduled reboot task: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------------
# Friendly Summary Helpers
# ---------------------------------------------------------------------
function Get-RecentlyDetectedOrInstalledCUInfo {
    param(
        [datetime]$WindowStart = (Get-Date).AddMinutes(-120)
    )

    try {
        if (-not (Get-Command Get-WUHistory -ErrorAction SilentlyContinue)) {
            Write-Log "Get-WUHistory cmdlet not available; cannot determine recent CU info from PSWindowsUpdate."
            return $null
        }

        $history = Get-WUHistory -MaxDate (Get-Date) -ErrorAction SilentlyContinue | Select-Object -First 150
        if (-not $history) {
            Write-Log "No Windows Update history returned."
            return $null
        }

        $recentCU = $history | Where-Object {
            $_.Date -ge $WindowStart -and
            (
                $_.Title -match 'Cumulative Update' -or
                $_.Title -match 'KB\d{7}'
            )
        } | Select-Object -First 1

        if (-not $recentCU) {
            Write-Log "No recent cumulative update was found in WU history."
            return $null
        }

        $kbMatch = [regex]::Match($recentCU.Title, 'KB\d{7}')
        $kb = if ($kbMatch.Success) { $kbMatch.Value } else { "UnknownKB" }

        $succeeded = $false
        if ($recentCU.PSObject.Properties.Name -contains 'ResultCode') {
            if ($recentCU.ResultCode -eq 2) { $succeeded = $true }
        }
        elseif ($recentCU.PSObject.Properties.Name -contains 'Result') {
            if ($recentCU.Result -match 'Succeeded') { $succeeded = $true }
        }

        return [PSCustomObject]@{
            KB        = $kb
            Title     = $recentCU.Title
            Date      = $recentCU.Date
            Succeeded = $succeeded
        }
    }
    catch {
        Write-Log "Could not determine recent CU info: $($_.Exception.Message)"
        return $null
    }
}

function Get-FriendlyUpdateSummary {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$UpdateResult
    )

    try {
        $osInfo = Get-OSBuildInfo
        $currentVersion = if ($osInfo) { $osInfo.FullVersion } else { "UnknownVersion" }
        $recentCU = Get-RecentlyDetectedOrInstalledCUInfo

        if (-not $UpdateResult.Success) {
            if ($recentCU) {
                return "CU DETECTED $($recentCU.KB) - Download/install failed - Current version $currentVersion"
            }
            return "UPDATE REMEDIATION FAILED - $($UpdateResult.Details)"
        }

        if ($UpdateResult.UpdatesInstalled -le 0) {
            if ($recentCU -and -not $recentCU.Succeeded) {
                return "CU DETECTED $($recentCU.KB) - Download/install failed - Current version $currentVersion"
            }

            if ($UpdateResult.RebootRequired) {
                return "NO NEW UPDATES INSTALLED - Reboot still required - Current version $currentVersion"
            }

            return "NO UPDATES INSTALLED - Current version $currentVersion"
        }

        if ($recentCU) {
            if ($UpdateResult.RebootRequired) {
                return "CU INSTALLED $($recentCU.KB) - Reboot required - Current live version still $currentVersion until reboot"
            }
            else {
                return "CU INSTALLED $($recentCU.KB) - No reboot required - Current version $currentVersion"
            }
        }

        if ($UpdateResult.RebootRequired) {
            return "UPDATES INSTALLED ($($UpdateResult.UpdatesInstalled)) - Reboot required - Current live version still $currentVersion until reboot"
        }

        return "UPDATES INSTALLED ($($UpdateResult.UpdatesInstalled)) - No reboot required - Current version $currentVersion"
    }
    catch {
        return "Could not build friendly update summary: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------
# Component Store Repair
# ---------------------------------------------------------------------
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

        $result.RepairAttempted = $true

        $restoreArgs = "/Online /Cleanup-Image /RestoreHealth"
        Write-Log "Running: DISM.exe $restoreArgs"

        $restoreProcess = Start-Process -FilePath "DISM.exe" -ArgumentList $restoreArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $result.RestoreHealthExitCode = $restoreProcess.ExitCode
        Write-Log "DISM RestoreHealth exit code: $($result.RestoreHealthExitCode)"

        if ($restoreProcess.ExitCode -eq 0) {
            $result.RepairSucceeded = $true
            Write-Log "DISM RestoreHealth completed successfully"
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
        $installFailed = $false
        $installSucceeded = $false

        if ($scanOutput -and $scanOutput.Trim().Length -gt 0) {
            foreach ($line in ($scanOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log $line.TrimEnd()
                }
            }
        }

        $updates = @(Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop)
        $result.UpdatesFound = @($updates).Count

        if ($result.UpdatesFound -eq 0) {
            Write-Log "No updates found via PSWindowsUpdate."
            $result.Success = $true
            $result.Details = "No updates found"
            $result.RebootRequired = Test-RebootPending
            return $result
        }

        Write-Log "Updates found via PSWindowsUpdate: $($result.UpdatesFound)"
        foreach ($u in $updates) {
            Write-Log "PSWindowsUpdate candidate: $($u.Title)"
        }

        Write-Log "Installing all available updates via PSWindowsUpdate."
        $installOutput = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction Continue -Verbose 4>&1 | Out-String

        if ($installOutput -and $installOutput.Trim().Length -gt 0) {
            foreach ($line in ($installOutput -split "`r?`n")) {
                if ($line -and $line.Trim().Length -gt 0) {
                    Write-Log $line.TrimEnd()

                    if ($line -match 'Failed\s+KB\d{7}') {
                        $installFailed = $true
                    }
                    if ($line -match 'Installed\s+\[(\d+)\]\s+Updates') {
                        if ([int]$matches[1] -gt 0) {
                            $installSucceeded = $true
                            $result.UpdatesInstalled = [int]$matches[1]
                        }
                    }
                    if ($line -match 'Downloaded\s+\[(\d+)\]\s+Updates ready to Install') {
                        if ([int]$matches[1] -eq 0) {
                            $installFailed = $true
                        }
                    }
                }
            }
        }

        if (-not $installSucceeded) {
            try {
                if (Get-Command Get-WUHistory -ErrorAction SilentlyContinue) {
                    $history = Get-WUHistory -MaxDate (Get-Date) -ErrorAction SilentlyContinue | Select-Object -First 100
                    if ($history) {
                        $recentWindow = (Get-Date).AddMinutes(-60)
                        $recentInstalled = $history | Where-Object {
                            $_.Date -ge $recentWindow -and (
                                ($_.PSObject.Properties.Name -contains 'ResultCode' -and $_.ResultCode -eq 2) -or
                                ($_.PSObject.Properties.Name -contains 'Result' -and $_.Result -match 'Succeeded')
                            )
                        }
                        $result.UpdatesInstalled = @($recentInstalled).Count
                        if ($result.UpdatesInstalled -gt 0) {
                            $installSucceeded = $true
                        }
                    }
                }
            }
            catch {
                Write-Log "Could not read WU history after PSWindowsUpdate install: $($_.Exception.Message)"
            }
        }

        $result.RebootRequired = Test-RebootPending

        if ($installSucceeded -and $result.UpdatesInstalled -gt 0) {
            $result.Success = $true
            $result.Details = "PSWindowsUpdate completed"
        }
        elseif ($installFailed) {
            $result.Success = $false
            $result.UpdatesInstalled = 0
            $result.Details = "Update download or install failed"
        }
        else {
            $result.Success = $false
            $result.UpdatesInstalled = 0
            $result.Details = "Could not confirm update installation"
        }

        Write-Log "PSWindowsUpdate method completed. Installed=$($result.UpdatesInstalled) RebootRequired=$($result.RebootRequired) Success=$($result.Success)"
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
        $result.Success = ($installedCount -gt 0)
        if ($result.Success) {
            $result.Details = "COM install completed"
        }
        else {
            $result.Details = "COM install did not confirm any installed updates"
        }

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
Write-Log "SCRIPT VERSION: 2026-04-22 REMEDIATION-1AM-REBOOT-WAKE-BATTERY-V2"

try {
    Write-Log "Detection already determined this device requires remediation."
    Write-Log "Running cleanup first."
    Invoke-PreUpdateCleanup

    Write-Log "Cleanup completed. Running Windows Update install workflow."
    $updateResult = Invoke-WindowsUpdateRemediation

    $summary = "Remediation summary | Method=$($updateResult.Method) | UpdatesFound=$($updateResult.UpdatesFound) | UpdatesInstalled=$($updateResult.UpdatesInstalled) | RebootRequired=$($updateResult.RebootRequired) | Success=$($updateResult.Success) | Details=$($updateResult.Details)"
    $friendlySummary = Get-FriendlyUpdateSummary -UpdateResult $updateResult

    if ($updateResult.RebootRequired) {
        $taskCreated = Register-ForcedRebootScheduledTask

        if ($taskCreated) {
            $rebootMessage = "Reboot required. Scheduled forced reboot at next 1:00 AM with wake enabled."
        }
        else {
            $rebootMessage = "Reboot required, but failed to create scheduled reboot task."
        }

        Write-Log $rebootMessage
        Write-Output $rebootMessage
    }

    Write-Log $summary
    Write-Log $friendlySummary

    Write-Output $summary
    Write-Output $friendlySummary

    Write-Log "===== REMEDIATION SCRIPT END ====="
    exit 0
}
catch {
    $errorMessage = "FATAL ERROR: $($_.Exception.Message)"
    $errorDetails = "Error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.GetType().FullName)"

    Write-Log $errorMessage
    Write-Log $errorDetails
    Write-Log "===== REMEDIATION SCRIPT END ====="

    Write-Output $errorMessage
    exit 1
}
