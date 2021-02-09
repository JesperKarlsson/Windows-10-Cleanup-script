
# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}
RequireAdmin


    $ErrorActionPreference = "SilentlyContinue"
    If ($Error) {$Error.Clear()}


==========================================================================================================================================================================


# Wait for key press
Function WaitForKey {
        Write-Host
	Write-Host "Press Any Key To Continue..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}
WaitForKey


Write-Output " "


# Show Task Manager details
Function ShowTaskManagerDetails {
	Write-Host "Adding Task Manager Details"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Force | Out-Null
	}
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If (!($preferences)) {
		$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
		While (!($preferences)) {
			Start-Sleep -m 250
			$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
		}
		Stop-Process $taskmgr
	}
	$preferences.Preferences[28] = 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}
ShowTaskManagerDetails


# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
	Write-Host "Adding Windows Photo Viewer"
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}
SetPhotoViewerAssociation


# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
	Write-Output "Adding Small Icons To Control Panel View"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}
SetControlPanelSmallIcons


# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Host "Adding This PC To Explorer View"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}
SetExplorerThisPC


# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
	Write-Output "Adding File Delete Confirmation Dialog"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}
EnableFileDeleteConfirm


Write-Output " "


# Hide Taskbar Search button / box
Function HideTaskbarSearchBox {
	Write-Host "Removing Taskbar Search Button"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}
HideTaskbarSearchBox


# Hide Task View button
Function HideTaskView {
	Write-Host "Removing Task View Button"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}
HideTaskView


# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Host "Removing People Button"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}
HideTaskbarPeopleIcon


# Disable Action Center
Function DisableActionCenter {
	Write-Host "Removing Action Center"
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}
DisableActionCenter


# Remove secondary sv-SE keyboard
Function RemoveENKeyboard {
	Write-Host "Removing Secondary sv-SE Keyboard"
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "sv-SE"}) -Force
}
RemoveENKeyboard


# Remove secondary en-GB keyboard
Function RemoveENKeyboard {
	Write-Host "Removing Secondary en-GB Keyboard"
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-GB"}) -Force
}
RemoveENKeyboard


# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	Write-Host "Removing Secondary en-US Keyboard"
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
}
RemoveENKeyboard


# Remove Windows default Printers
Get-WmiObject -Class Win32_Printer | where{$_.name}| foreach{$_.delete()}
Write-Host "Removing Windows Default Printers"


# Hide Quick Acess from Explorer
Function HideQuickAcessfromExplorer {
	Write-Host "Removing Quick Acess From Explorer"
	New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Force | New-ItemProperty -Name "Attributes" -Type DWord -Value 0xa0600000 -Force | Out-Null
}
HideQuickAcessfromExplorer


Function HideRecycleBin {

    Write-Host "Removing Recycle Bin from Desktop"
    # test if registerpaths exists, if not create them
    $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path $RegistryPath) {
	    $Res = Get-ItemProperty -Path $RegistryPath -Name "HideIcons"
	    If (-Not($Res)) {
		    New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "1" -PropertyType DWORD -Force | Out-Null
	    }
	    $Check = (Get-ItemProperty -Path $RegistryPath -Name "HideIcons").HideIcons
	    If ($Check -NE 0) {
		    New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "1" -PropertyType DWORD -Force | Out-Null
	    }
    }
    $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
    If (-Not(Test-Path $RegistryPath)) {
	    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "HideDesktopIcons" -Force | Out-Null
	    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
    }
    $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    If (-Not(Test-Path $RegistryPath)) {
	    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
    }

    $Res = Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "1" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}")."{645FF040-5081-101B-9F08-00AA002F954E}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "1" -PropertyType DWORD -Force | Out-Null
	}
}
HideRecycleBin


# Remove files immediately when deleted
Write-Host "Removing Files Immediately When Deleted"
Function NoRecycleBin {
    
    $Regpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    If (-Not(Test-Path $Regpath)) { 
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\" -Name "Explorer" -Force | Out-Null;
    }

    If (-Not(Get-ItemProperty -Path $Regpath -Name "NoRecucleFiles")) {
        New-ItemProperty -Path $Regpath -Name "NoRecycleFiles" -PropertyType DWORD -Value 1 -Force | Out-Null;
        
    } ElseIf (-Not(Equals(Get-ItemPropertyValue -Path $Regpath -Name "NoRecycleFiles"), 1)) {
        Set-ItemProperty -Path $Regpath -Name "NoRecycleFiles" -Value 1 -Force | Out-Null;
    }
}
NoRecycleBin


# Hide 3D Objects icon from This PC
Function Hide3DObjectsFromThisPC {
	Write-Host "Removing 3D Objects Folder From This PC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}
Hide3DObjectsFromThisPC


function JPEGComp {
Write-Host "Removing JPEG-Compression For Wallpaper"
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop\" -Type DWord -Name "JPEGImportQuality" -Value 0x0000064 -Force | Out-Null
}
JPEGComp


Write-Output " "


# Disable Windows Defender
Function DisableDefender {
	Write-Host "Disabling Windows Defender"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
}
DisableDefender


# Disable Windows Defender Cloud
Function DisableDefenderCloud {
    Write-Host "Disabling Windows Defender Cloud"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}
DisableDefenderCloud


# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox Features"
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}
DisableXboxFeatures


Write-Output "Disabling Windows Services"

Set-Service DPS -StartupType Disabled
Set-Service TrkWks -StartupType Disabled
Set-Service MapsBroker -StartupType Disabled
Set-Service iphlpsvc -StartupType Disabled
Set-Service PcaSvc -StartupType Disabled
Set-Service Spooler -StartupType Disabled
Set-Service seclogon -StartupType Disabled
Set-Service TabletInputService -StartupType Disabled
Set-Service stisvc -StartupType Disabled
Set-Service WerSvc -StartupType Disabled
Set-Service XboxGipSvc -StartupType Disabled
Set-Service XblAuthManager -StartupType Disabled
Set-Service XblGameSave -StartupType Disabled
Set-Service XboxNetApiSvc -StartupType Disabled


Walkir@SweClockers Windows 10 Service Configurations:

Set-Service SysMain -StartupType Disabled
Set-Service NcaSvc -StartupType Disabled
Set-Service irmon -StartupType Disabled
Set-Service CDPSvc -StartupType Disabled


Black Viper’s Windows 10 Service Configurations:

Set-Service AJRouter -StartupType Disabled
Set-Service ALG -StartupType Disabled
Set-Service AppMgmt -StartupType Disabled
Set-Service tzautoupdate -StartupType Disabled
Set-Service BDESVC -StartupType Disabled
Set-Service wbengine -StartupType Disabled
Set-Service PeerDistSvc -StartupType Disabled
Set-Service CertPropSvc -StartupType Disabled
Set-Service DiagTrack -StartupType Disabled
Set-Service DsSvc -StartupType Disabled
Set-Service DusmSvc -StartupType Disabled
Set-Service DoSvc -StartupType Disabled
Set-Service Fax -StartupType Disabled
Set-Service fhsvc -StartupType Disabled
Set-Service lfsvc -StartupType Disabled
Set-Service hidserv -StartupType Disabled
Set-Service HvHost -StartupType Disabled
Set-Service vmickvpexchange -StartupType Disabled
Set-Service vmicguestinterface -StartupType Disabled
Set-Service vmicshutdown -StartupType Disabled
Set-Service vmicheartbeat -StartupType Disabled
Set-Service vmicvmsession -StartupType Disabled
Set-Service vmicrdv -StartupType Disabled
Set-Service vmictimesync -StartupType Disabled
Set-Service vmicvss -StartupType Disabled
Set-Service irmon -StartupType Disabled
Set-Service SharedAccess -StartupType Disabled
Set-Service IpxlatCfgSvc -StartupType Disabled
Set-Service wlidsvc -StartupType Disabled
Set-Service AppVClient -StartupType Disabled
Set-Service MSiSCSI -StartupType Disabled
Set-Service swprv -StartupType Disabled
Set-Service smphost -StartupType Disabled
Set-Service InstallService -StartupType Disabled
Set-Service SmsRouter -StartupType Disabled
Set-Service NaturalAuthentication -StartupType Disabled
Set-Service NetTcpPortSharing -StartupType Disabled
Set-Service Netlogon -StartupType Disabled
Set-Service NcdAutoSetup -StartupType Disabled
Set-Service CscService -StartupType Disabled
Set-Service WpcMonSvc -StartupType Disabled
Set-Service SEMgrSvc -StartupType Disabled
Set-Service PhoneSvc -StartupType Disabled
Set-Service PrintNotify -StartupType Disabled
Set-Service SessionEnv -StartupType Disabled
Set-Service TermService -StartupType Disabled
Set-Service UmRdpService -StartupType Disabled
Set-Service RpcLocator -StartupType Disabled
Set-Service RemoteRegistry -StartupType Disabled
Set-Service RetailDemo -StartupType Disabled
Set-Service RemoteAccess -StartupType Disabled
Set-Service SensorDataService -StartupType Disabled
Set-Service SensrSvc -StartupType Disabled
Set-Service SensorService -StartupType Disabled
Set-Service shpamsvc -StartupType Disabled
Set-Service SCardSvr -StartupType Disabled
Set-Service ScDeviceEnum -StartupType Disabled
Set-Service SCPolicySvc -StartupType Disabled
Set-Service SNMPTRAP -StartupType Disabled
Set-Service StorSvc -StartupType Disabled
Set-Service UevAgentService -StartupType Disabled
Set-Service VSS -StartupType Disabled
Set-Service WebClient -StartupType Disabled
Set-Service WFDSConSvc -StartupType Disabled
Set-Service FrameServer -StartupType Disabled
Set-Service wcncsvc -StartupType Disabled
Set-Service wisvc -StartupType Disabled
Set-Service LicenseManager -StartupType Disabled
Set-Service WMPNetworkSvc -StartupType Disabled
Set-Service icssvc -StartupType Disabled
Set-Service spectrum -StartupType Disabled
Set-Service FontCache3.0.0.0 -StartupType Disabled
Set-Service WinRM -StartupType Disabled
Set-Service WwanSvc -StartupType Disabled


Function DisableTelemetry {
	Write-Output "Disabling Windows Telemetry"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}
DisableTelemetry


# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}
DisableWiFiSense


Function DisableSmartScreen {
	Write-Output "Disabling SmartScreen Filter"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}
DisableSmartScreen


# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search In Start Menu"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}
DisableWebSearch


Function DisableAppSuggestions {
	Write-Output "Disabling Application Suggestions"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}
DisableAppSuggestions


# Disable Activity History feed in Task View - Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
Function DisableActivityHistory {
	Write-Output "Disabling Activity History"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}
DisableActivityHistory


# Disable Background application access - ie. if apps can download or update when they aren't used - Cortana is excluded as its inclusion breaks start menu search
Function DisableBackgroundApps {
	Write-Output "Disabling Background Application Access"
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}
}
DisableBackgroundApps


# Disable Location Tracking
Function DisableLocationTracking {
	Write-Output "Disabling Location Tracking"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}
DisableLocationTracking


# Disable automatic Maps Updates
Function DisableMapUpdates {
	Write-Output "Disabling Automatic Maps updates"
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}
DisableMapUpdates


Function DisableFeedback {
	Write-Output "Disabling Feedback"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}
DisableFeedback


# Disable Tailored Experiences
Function DisableTailoredExperiences {
	Write-Output "Disabling Tailored Experiences"
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}
DisableTailoredExperiences


# Disable Advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}
DisableAdvertisingID


# Disable Cortana
Function DisableCortana {
	Write-Host "Disabling Cortana"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}
DisableCortana


# Disable Error reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error Reporting"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}
DisableErrorReporting


# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
	Write-Host "Disabling AutoLogger File And Restricting Directory"
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}
DisableAutoLogger


# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
	Write-Output "Disabling Diagnostics Tracking Service"
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}
DisableDiagTrack


# Stop and disable WAP Push Service
Function DisableWAPPush {
	Write-Output "Disabling WAP Push Service"
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}
DisableWAPPush


# "
Function DisableSharingMappedDrives {
	Write-Output "Disabling Sharing Mapped Drives Between Users"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}
DisableSharingMappedDrives


# "
Function DisableAdminShares {
	Write-Output "Disabling Implicit Administrative Shares"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}
DisableAdminShares


# Disable Windows Update automatic restart
Function DisableUpdateRestart {
	Write-Output "Disabling Windows Update Automatic Restart"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}
DisableUpdateRestart


# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
	Write-Output "Disabling Remote Assistance"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}
DisableRemoteAssistance


# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}
DisableRemoteDesktop


# Disable Windows Search indexing service
Function DisableIndexing {
	Write-Output "Disabling Windows Search Indexing Service"
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}
DisableIndexing


# Wait for key press
Function WaitForKey {
	Write-Host
	Write-Host "Go Through The Settings App. Press any key to continue..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}
WaitForKey


Write-Output " "


# Wait for key press
Function WaitForKey {
	Write-Host
	Write-Host "Go Through Control Panel. Press Any Key To Continue..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}
WaitForKey


Write-Output " "


# Wait for key press
Function WaitForKey {
	Write-Host
	Write-Host "Press Any Key To Restart PC..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}
WaitForKey


# Restart computer
Function Restart {
	Write-Host "Restarting..."
	Restart-Computer
}
Restart
