<#
    Windows Updates
#>

param (
    [Parameter(ParameterSetName='Recurse')][switch]$recurse,
    [Parameter(ParameterSetName='Recurse',Mandatory=$true)][string]$adminUserName,
    [Parameter(ParameterSetName='Recurse',Mandatory=$true)][string]$adminPassword
)

function Clear-Winlogon {

    $RegistryWinLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $RegistryRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $RegistryRunKeyName = "Windows Updates"

    #setting registry values
    Set-ItemProperty $RegistryWinLogonPath "AutoAdminLogon" -Value "0" -type String
    Set-ItemProperty $RegistryWinLogonPath "DefaultUsername" -Value "" -type String
    Set-ItemProperty $RegistryWinLogonPath "DefaultPassword" -Value "" -type String
    Set-ItemProperty $RegistryWinLogonPath "AutoLogonCount" -Value "0" -type DWord

    Remove-ItemProperty -Name $RegistryRunKeyName -Path $RegistryRunPath

}

function Write-Log {
    $timestamp = get-date
    $line = "{0}: {1}" -f $timestamp,$args[0]
    if (Test-Path $logfilename) {
        Write-Output $line >> $logfilename
    } else {
        Write-Output $line > $logfilename
    }
}

function Set-Reboot {

    $RegistryWinLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $RegistryRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $RegistryRunKeyName = "Windows Updates"

    $DefaultUsername = $adminUserName
    $DefaultPassword = $adminPassword

    $RunCommandLine = "powershell -File `"$PSScriptRoot\InstallWindowsUpdates.ps1`""

    #setting registry values
    Write-Log "Next run: $RunCommandLine"
    Set-ItemProperty $RegistryWinLogonPath "AutoAdminLogon" -Value "1" -type String
    Set-ItemProperty $RegistryWinLogonPath "DefaultUsername" -Value "$DefaultUsername" -type String
    Set-ItemProperty $RegistryWinLogonPath "DefaultPassword" -Value "$DefaultPassword" -type String
    Set-ItemProperty $RegistryWinLogonPath "AutoLogonCount" -Value "20" -type DWord

    Set-ItemProperty $RegistryRunPath -Name $RegistryRunKeyName -Value "$RunCommandLine" -type String
}

$logfilename = "$PSScriptRoot\WindowsUpdates-log$(get-date -f yyyyMMdd_HHmm).txt"

$updatesDone = $false
$reboot = $false

Write-Log "Script started"
Write-Log "Checking for available updates"
Write-Log "Creating Update Session"
$Session = New-Object -com "Microsoft.Update.Session"

Write-Log "Searching for updates..."
$Search = $Session.CreateUpdateSearcher()
$SearchResults = $Search.Search("type='software' and IsInstalled=0 and IsHidden=0")
$AvailableUpdates = $SearchResults.Updates

$totalCount = $AvailableUpdates.count

if($totalCount -lt 1) {
    Write-Log "No available updates"
    $updatesDone = $true
} else {
    Write-Log "There are $totalCount updates available."
    $count = 1
    $AvailableUpdates | ForEach-Object {
        if ($_.InstallationBehavior.CanRequestUserInput -ne $TRUE) {
            if (!($_.EulaAccepted)) {
                $_.AcceptEula()
            }
            $DownloadCollection = New-Object -com "Microsoft.Update.UpdateColl"
            $InstallCollection = New-Object -com "Microsoft.Update.UpdateColl"
            $DownloadCollection.Add($_) | Out-Null
            $UpdateTitle =  $_.Title
            Write-Log "Downloading update ($count/$totalCount): $UpdateTitle"
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $DownloadCollection
            $Downloader.Download() | Out-Null
            if ($_.IsDownloaded) {
                Write-Log "Download complete"
                Write-Log "Installing update ($count/$totalCount): $UpdateTitle"
                $InstallCollection.Add($_) | Out-Null
                $Installer = $Session.CreateUpdateInstaller()
                $Installer.Updates = $InstallCollection
                $Results = $Installer.Install()
                Write-Log "Installation finished"
            } else {
                Write-Log "Problem downloading $UpdateTitle"
            }
            $count = $count + 1
            if ($Results.RebootRequired) {
                $reboot = $true
            }
        }
    }
}
if ($reboot) {
    if ($recurse) {
        Write-Log "Scheduling run @ Next Reboot"
        Set-Reboot
    }
    Write-Log "Reboot required.  Restarting..."
    Restart-Computer
} else {
    Write-Log "No reboot required."
    if ($recurse) {
        Clear-Winlogon
    }
    Write-Log "AllDone"
}
