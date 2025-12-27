	<# : batch portion
	@setlocal DisableDelayedExpansion
	@echo off
	Color 0F
	echo "%*"|find /i "-el" >nul && set _elev=1
	set arg="""%~f0""" -el
	setlocal EnableDelayedExpansion
	>nul 2>&1 fltmc || >nul 2>&1 net session || (
	if not defined _elev (
	powershell -nop -c "saps cmd.exe '/c', '!arg!' -Verb RunAs" >nul 2>&1 && exit /b 0
	)
	echo.
	echo This script require administrator privileges.
	echo To do so, right click on this script and select 'Run as administrator'.
	pause
	exit 1
	)
	where pwsh.exe >nul 2>&1 && set "ps1=pwsh" || set "ps1=powershell"
	%ps1% -nop -ep Bypass -c "Get-Content '%~f0' -Raw | iex"
	goto :eof
	: end batch / begin powershell #>
	
	$Host.UI.RawUI.WindowTitle='Bloatware (Administrator)'
	
	function show-menu {
	Clear-Host	
	Write-Host " 1. Remove : All Bloatware (Recommended)"	
	Write-Host " 2. Install: Store"	
	Write-Host " 3. Install: All UWP Apps"	
	Write-Host " 4. Install: UWP Features"	
	Write-Host " 5. Install: Legacy Features"	
	Write-Host " 6. Install: One Drive"	
	Write-Host " 7. Install: Remote Desktop Connection"	
	Write-Host " 8. Install: Legacy Snipping Tool W10"	
	Write-Host " 9. Install: Legacy Paint W10"	
	Write-Host "10. Install: GameInput"	
	}
	
	show-menu
	while ($true) {
	$choice = Read-Host " "
	if ($choice -match '^(10|[1-9])$') {
	switch ($choice) {
	1 {	
	Clear-Host
	$ProgressPreference='SilentlyContinue'
	Write-Host "Uninstalling: UWP Apps. Please wait . . ."
	# uninstall all uwp apps keep
	# uninstall all uwp apps keep nvidia, cbs, winget, copilot, xbox & widgets
	Get-AppxPackage -AllUsers | ? Name -notmatch 'NVIDIA|CBS|DesktopAppInstaller|Winget|Copilot|Gaming|Xbox|Widgets|Experience' | Remove-AppxPackage -ea 0
	Clear-Host				
	Write-Host "Uninstalling: UWP Features. Please wait . . ."
	# uninstall all uwp features				
	# notepad & media player left out
	Remove-Item "$env:TEMP\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk" -force -ea 0	
	Remove-WindowsCapability -Online -Name "App.StepsRecorder~~~~0.0.1.0" -ea 0	| Out-Null
	Remove-WindowsCapability -Online -Name "App.Support.QuickAssist~~~~0.0.1.0" -ea 0 | Out-Null
	Remove-WindowsCapability -Online -Name "Browser.InternetExplorer~~~~0.0.11.0" -ea 0	| Out-Null
	Remove-WindowsCapability -Online -Name "DirectX.Configuration.Database~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "Hello.Face.18967~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "Hello.Face.20134~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "MathRecognizer~~~~0.0.1.0" -ea 0 | Out-Null				
	# breaks media player legacy
	# Remove-WindowsCapability -Online -Name "Media.WindowsMediaPlayer~~~~0.0.12.0" | Out-Null				
	Remove-WindowsCapability -Online -Name "Microsoft.Wallpapers.Extended~~~~0.0.1.0" -ea 0	| Out-Null
	Remove-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint~~~~0.0.1.0" -ea 0	| Out-Null
	Remove-WindowsCapability -Online -Name "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "Microsoft.Windows.WordPad~~~~0.0.1.0" -ea 0	| Out-Null				
	Remove-WindowsCapability -Online -Name "OneCoreUAP.OneSync~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "Print.Fax.Scan~~~~0.0.1.0" -ea 0 | Out-Null				
	Remove-WindowsCapability -Online -Name "Print.Management.Console~~~~0.0.1.0" -ea 0 | Out-Null				
	# breaks installer & uninstaller programs
	# Remove-WindowsCapability -Online -Name "VBSCRIPT~~~~" | Out-Null
	Remove-WindowsCapability -Online -Name "WMIC~~~~" -ea 0 | Out-Null
	# breaks uwp snippingtool w10
	# Remove-WindowsCapability -Online -Name "Windows.Client.ShellComponents~~~~0.0.1.0" | Out-Null
	Remove-WindowsCapability -Online -Name "Windows.Kernel.LA57~~~~0.0.1.0" -ea 0 | Out-Null
	Clear-Host
    Write-Host "Uninstalling: Legacy Features. Please wait . . ."
    # uninstall all legacy features
    # .net framework 4.8 advanced services left out
    # Dism /Online /NoRestart /Disable-Feature /FeatureName:NetFx4-AdvSrvs | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-Services45 | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:MediaPlayback | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-XPSServices-Features | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-Foundation-Features | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:MSRDC-Infrastructure | Out-Null
    # breaks search
    # Dism /Online /NoRestart /Disable-Feature /FeatureName:SearchEngine-Client-Package | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol-Client | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol-Deprecation | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:SmbDirect | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:Windows-Identity-Foundation | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 | Out-Null
    Dism /Online /NoRestart /Disable-Feature /FeatureName:WorkFolders-Client | Out-Null
	Clear-Host
    Write-Host "Uninstalling: Legacy Apps. Please wait . . ."
    # uninstall microsoft update health tools w11
    cmd /c "MsiExec.exe /X{C6FD611E-7EFE-488C-A0E0-974C09EF6473} /qn >nul 2>&1"
    # uninstall microsoft update health tools w10
    cmd /c "MsiExec.exe /X{1FC1A6C2-576E-489A-9B4A-92D21F542136} /qn >nul 2>&1"
    # clean microsoft update health tools w10
    cmd /c "reg delete `"HKLM\SYSTEM\ControlSet001\Services\uhssvc`" /f >nul 2>&1"
    Unregister-ScheduledTask -TaskName PLUGScheduler -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    # uninstall update for windows 10 for x64-based systems
    cmd /c "MsiExec.exe /X{B9A7A138-BFD5-4C73-A269-F78CCA28150E} /qn >nul 2>&1"
    cmd /c "MsiExec.exe /X{85C69797-7336-4E83-8D97-32A7C8465A3B} /qn >nul 2>&1"
	cmd /c "MsiExec.exe /X{B8D93870-98D1-4980-AFCA-E26563CDFB79} /qn >nul 2>&1"
    # stop onedrive running
    Stop-Process -Force -Name OneDrive -ErrorAction SilentlyContinue | Out-Null
    # uninstall onedrive w10
    cmd /c "C:\Windows\SysWOW64\OneDriveSetup.exe -uninstall >nul 2>&1"
    # clean onedrive w10
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'OneDrive'} | Unregister-ScheduledTask -Confirm:$false
    # uninstall onedrive w11
    cmd /c "C:\Windows\System32\OneDriveSetup.exe -uninstall >nul 2>&1"
    # clean adobe type manager w10
    cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`" /f >nul 2>&1"
    # uninstall old snippingtool w10
    Start-Process "C:\Windows\System32\SnippingTool.exe" -ArgumentList "/Uninstall"
    Clear-Host
    # silent window for old snippingtool w10
    $processExists = Get-Process -Name SnippingTool -ErrorAction SilentlyContinue
    if ($processExists) {
    $running = $true
    do {
    $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
    foreach ($window in $openWindows) {
    if ($window.MainWindowTitle -eq 'Snipping Tool') {
    Stop-Process -Force -Name SnippingTool -ErrorAction SilentlyContinue | Out-Null
    $running = $false
    }
    }
    } while ($running)
    } else {
    }
    Timeout /T 1 | Out-Null
	# uninstall remote desktop connection
    Start-Process "mstsc" -ArgumentList "/Uninstall"
    Clear-Host
    # silent window for remote desktop connection
    $processExists = Get-Process -Name mstsc -ErrorAction SilentlyContinue
    if ($processExists) {
    $running = $true
    do {
    $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
    foreach ($window in $openWindows) {
    if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
    Stop-Process -Force -Name mstsc -ErrorAction SilentlyContinue | Out-Null
    $running = $false
    }
    }
    } while ($running)
    } else {
    }
	
	# create notepad legacy shortcut
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk")
    $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
    $shortcut.Save()
    # install photo viewer
    'tif','tiff','bmp','dib','gif','jfif','jpe','jpeg','jpg','jxr','png','ico' | ForEach-Object {reg add "HKCU\SOFTWARE\Classes\.${_}" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1}							
	# wallpaper
	# disable spotlight
	New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}' -PropertyType DWORD -Value 1 -Force | Out-Null
	# solid color black
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'Wallpaper' -Value ''
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers' -Name 'BackgroundType' -Type DWord -Value 1
			
	# create reg file
	$MultilineComment = @'
Windows Registry Editor Version 5.00

; This reg file automatically applies Media Player setup phase as you would like to complete, no document history, no data sharing. Can be implemented to the ISOs.

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Health]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Skins]
"LastViewModeVTen"=dword:00000002
"SkinX"=dword:00000000
"SkinY"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Skins\res://wmploc/RT_TEXT/player.wsz]
"Prefs"="currentMetadataIconV11;0;FirstRun;0;ap;False;max;False"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Tasks]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Tasks\NowPlaying]
"InitFlags"=dword:00000001
"ShowHorizontalSeparator"=dword:00000001
"ShowVerticalSeparator"=dword:00000001
"PlaylistWidth"=dword:000000ba
"PlaylistHeight"=dword:00000064
"SettingsWidth"=dword:00000064
"SettingsHeight"=dword:00000087
"MetadataWidth"=dword:000000ba
"MetadataHeight"=dword:000000a0
"CaptionsHeight"=dword:00000064

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences]
"AutoMetadataCurrent503ServerErrorCount"=dword:00000000
"AutoMetadataCurrentOtherServerErrorCount"=dword:00000000
"AutoMetadataCurrentNetworkErrorCount"=dword:00000000
"AutoMetadataLastResetTime"=dword:293e214e
"SyncPlaylistsAdded"=dword:00000001
"MLSChangeIndexMusic"=dword:00000000
"MLSChangeIndexVideo"=dword:00000000
"MLSChangeIndexPhoto"=dword:00000000
"MLSChangeIndexList"=dword:00000000
"MLSChangeIndexOther"=dword:00000000
"LibraryHasBeenRun"=dword:00000000
"FirstRun"=dword:00000000
"NextLaunchIndex"=dword:00000002
"XV11"="256"
"YV11"="144"
"WidthV11"="2048"
"HeightV11"="1152"
"Maximized"="0"
"Volume"=dword:00000032
"ModeShuffle"=dword:00000000
"DisableMRUMusic"=dword:00000001
"Mute"=dword:00000000
"Balance"=dword:00000000
"CurrentEffectType"="Bars"
"CurrentEffectPreset"=dword:00000003
"VideoZoom"=dword:00000064
"AutoMetadataCurrent500ServerErrorCount"=dword:00000000
"StretchToFit"=dword:00000001
"ShowEffects"=dword:00000001
"ShowFullScreenPlaylist"=dword:00000000
"NowPlayingQuickHide"=dword:00000000
"ShowTitles"=dword:00000001
"ShowCaptions"=dword:00000000
"NowPlayingPlaylist"=dword:00000001
"NowPlayingMetadata"=dword:00000001
"NowPlayingSettings"=dword:00000000
"CurrentDisplayView"="VideoView"
"CurrentSettingsView"="EQView"
"CurrentMetadataView"="MediaInfoView"
"CurrentDisplayPreset"=dword:00000000
"CurrentSettingsPreset"=dword:00000000
"CurrentMetadataPreset"=dword:00000000
"UserDisplayView"="VizView"
"UserWMPDisplayView"="VizView"
"UserWMPSettingsView"="EQView"
"UserWMPMetadataView"="MediaInfoView"
"UserDisplayPreset"=dword:00000000
"UserWMPDisplayPreset"=dword:00000000
"UserWMPSettingsPreset"=dword:00000000
"UserWMPMetadataPreset"=dword:00000000
"UserWMPShowSettings"=dword:00000000
"UserWMPShowMetadata"=dword:00000000
"ShowAlbumArt"=dword:00000000
"AutoMetadataCurrentDownloadCount"=dword:00000000
"MediaLibraryCreateNewDatabase"=dword:00000000
"TranscodedFilesCacheDefaultSizeSet"=dword:00000001
"TranscodedFilesCacheSize"=dword:00002a5e
"LastScreensaverTimeout"=dword:00003a98
"LastScreensaverState"=dword:00000005
"LastScreensaverSetThreadExecutionState"=dword:80000003
"AppColorLimited"=dword:00000000
"SQMLaunchIndex"=dword:00000001
"LaunchIndex"=dword:00000001
"DisableMRUVideo"=dword:00000001
"DisableMRUPlaylists"=dword:00000001
"ShrinkToFit"=dword:00000000
"DisableMRUPictures"=dword:00000001
"UsageTracking"=dword:00000000
"SilentAcquisition"=dword:00000000
"SendUserGUID"=hex(3):00
"MetadataRetrieval"=dword:00000000
"AcceptedPrivacyStatement"=dword:00000001
"ModeLoop"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\EqualizerSettings]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\HME]
"LocalLibraryID"="{95ADD7BE-43A3-4FD9-A4C8-453B88711A10}"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\ProxySettings]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\ProxySettings\HTTP]
"ProxyName"=""
"ProxyPort"=dword:00000050
"ProxyExclude"=""
"ProxyBypass"=dword:00000000
"ProxyStyle"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\ProxySettings\RTSP]
"ProxyStyle"=dword:00000000
"ProxyName"=""
"ProxyPort"=dword:0000022a
"ProxyBypass"=dword:00000000
"ProxyExclude"=""

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\VideoSettings]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{1F32514F-1561-4922-A604-8A1F478B5A42}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{52903d79-f993-4de6-8317-20c9c176d823}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{5DF031B7-6A37-42D9-8802-E27F4F224332}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{5F4BB5C9-4652-489B-8601-EEC0C3C32E2E}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{7F2B1D6B-1357-402C-A1C8-67E59583B41D}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{93075F62-16B3-43EC-A53B-FFAD0E01D5E7}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{9695AEF9-9D03-4671-8F2F-FF49D1BB01C4}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{976ABECA-93F7-4d81-9187-2A6137829675}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{99DB05E3-F81E-4C8A-A252-F396306AB6FE}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{9F9562EB-15B6-46C6-A7CB-0A66FC65130E}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{9FA014E3-076F-4865-A73C-117131B8E292}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{C1B5977D-9801-4D80-8592-143A044568AF}]
"AttemptedAutoRun"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{D5E49195-ED19-40fb-9EE0-E6625A808B77}]
"AttemptedAutoRun"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{E641D09E-E500-4c09-8260-F1CD7B902E9C}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{F24A1BC2-2331-4B91-8A13-5A549DA56E9D}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins\{FD981763-B6BB-4d51-9143-6D372A0ED56F}]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK\General]
"UniqueID"="{326EA348-9669-4511-8B5D-82373066F6FB}"
"VolumeSerialNumber"=dword:5acb5c10
"ComputerName"="XOS"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK\Namespace]
"DTDFile"="C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows Media\\12.0\\WMSDKNS.DTD"
"LocalDelta"="C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows Media\\12.0\\WMSDKNSD.XML"
"RemoteDelta"="C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows Media\\12.0\\WMSDKNSR.XML"
"LocalBase"="C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows Media\\12.0\\WMSDKNS.XML"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\JumplistData]
"Microsoft.Windows.MediaPlayer32"=hex(b):E8,DF,57,F3,0D,E9,D7,01

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/vnd.ms-wpl]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/vnd.ms-wpl\UserChoice]
"Progid"="WMP11.AssocMIME.WPL"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-mplayer2]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-mplayer2\UserChoice]
"Progid"="WMP11.AssocMIME.ASF"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmd]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmd\UserChoice]
"Progid"="WMP11.AssocMIME.WMD"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmz]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmz\UserChoice]
"Progid"="WMP11.AssocMIME.WMZ"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp2]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp2\UserChoice]
"Progid"="WMP11.AssocMIME.3G2"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp\UserChoice]
"Progid"="WMP11.AssocMIME.3GP"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/aiff]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/aiff\UserChoice]
"Progid"="WMP11.AssocMIME.AIFF"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/basic]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/basic\UserChoice]
"Progid"="WMP11.AssocMIME.AU"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mid]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mid\UserChoice]
"Progid"="WMP11.AssocMIME.MIDI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/midi]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/midi\UserChoice]
"Progid"="WMP11.AssocMIME.MIDI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp3]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp3\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp4]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp4\UserChoice]
"Progid"="WMP11.AssocMIME.M4A"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpeg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpeg\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpegurl]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpegurl\UserChoice]
"Progid"="WMP11.AssocMIME.M3U"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpg\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/vnd.dlna.adts]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/vnd.dlna.adts\UserChoice]
"Progid"="WMP11.AssocMIME.ADTS"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/wav]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/wav\UserChoice]
"Progid"="WMP11.AssocMIME.WAV"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-aiff]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-aiff\UserChoice]
"Progid"="WMP11.AssocMIME.AIFF"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-flac]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-flac\UserChoice]
"Progid"="WMP11.AssocMIME.FLAC"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-matroska]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-matroska\UserChoice]
"Progid"="WMP11.AssocMIME.MKA"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mid]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mid\UserChoice]
"Progid"="WMP11.AssocMIME.MIDI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-midi]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-midi\UserChoice]
"Progid"="WMP11.AssocMIME.MIDI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mp3]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mp3\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpeg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpeg\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpegurl]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpegurl\UserChoice]
"Progid"="WMP11.AssocMIME.M3U"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpg\UserChoice]
"Progid"="WMP11.AssocMIME.MP3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-ms-wax]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-ms-wax\UserChoice]
"Progid"="WMP11.AssocMIME.WAX"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-ms-wma]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-ms-wma\UserChoice]
"Progid"="WMP11.AssocMIME.WMA"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-wav]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-wav\UserChoice]
"Progid"="WMP11.AssocMIME.WAV"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\midi/mid]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\midi/mid\UserChoice]
"Progid"="WMP11.AssocMIME.MIDI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp2]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp2\UserChoice]
"Progid"="WMP11.AssocMIME.3G2"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp\UserChoice]
"Progid"="WMP11.AssocMIME.3GP"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/avi]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/avi\UserChoice]
"Progid"="WMP11.AssocMIME.AVI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mp4]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mp4\UserChoice]
"Progid"="WMP11.AssocMIME.MP4"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpeg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpeg\UserChoice]
"Progid"="WMP11.AssocMIME.MPEG"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpg\UserChoice]
"Progid"="WMP11.AssocMIME.MPEG"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/msvideo]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/msvideo\UserChoice]
"Progid"="WMP11.AssocMIME.AVI"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/quicktime]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/quicktime\UserChoice]
"Progid"="WMP11.AssocMIME.MOV"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/vnd.dlna.mpeg-tts]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/vnd.dlna.mpeg-tts\UserChoice]
"Progid"="WMP11.AssocMIME.TTS"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-matroska]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-matroska-3d]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-matroska-3d\UserChoice]
"Progid"="WMP11.AssocMIME.MK3D"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-matroska\UserChoice]
"Progid"="WMP11.AssocMIME.MKV"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-mpeg]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-mpeg2a]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-mpeg2a\UserChoice]
"Progid"="WMP11.AssocMIME.MPEG"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-mpeg\UserChoice]
"Progid"="WMP11.AssocMIME.MPEG"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-asf]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-asf-plugin]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-asf-plugin\UserChoice]
"Progid"="WMP11.AssocMIME.ASX"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-asf\UserChoice]
"Progid"="WMP11.AssocMIME.ASX"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wm]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wm\UserChoice]
"Progid"="WMP11.AssocMIME.ASF"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wmv]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wmv\UserChoice]
"Progid"="WMP11.AssocMIME.WMV"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wmx]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wmx\UserChoice]
"Progid"="WMP11.AssocMIME.ASX"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wvx]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-ms-wvx\UserChoice]
"Progid"="WMP11.AssocMIME.WVX"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-msvideo]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/x-msvideo\UserChoice]
"Progid"="WMP11.AssocMIME.AVI"

; Created by: Shawn Brink
; Created on: September 28th 2015
; Updated on: August 28th 2019
; Tutorial: https://www.tenforums.com/tutorials/24412-add-remove-default-new-context-menu-items-windows-10-a.html


; Text Document
[-HKEY_CLASSES_ROOT\.txt\ShellNew]
[HKEY_CLASSES_ROOT\.txt\ShellNew]
"ItemName"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,\
  6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\
  00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,2c,00,\
  2d,00,34,00,37,00,30,00,00,00
"NullFile"=""


[-HKEY_CLASSES_ROOT\.txt]

[HKEY_CLASSES_ROOT\.txt]
@="txtfile"
"Content Type"="text/plain"
"PerceivedType"="text"

[HKEY_CLASSES_ROOT\.txt\PersistentHandler]
@="{5e941d80-bf96-11cd-b579-08002b30bfeb}"

[HKEY_CLASSES_ROOT\.txt\ShellNew]
"ItemName"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,\
  6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\
  00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,2c,00,\
  2d,00,34,00,37,00,30,00,00,00
"NullFile"=""

[-HKEY_CLASSES_ROOT\SystemFileAssociations\.txt]

[HKEY_CLASSES_ROOT\SystemFileAssociations\.txt]
"PerceivedType"="document"

[-HKEY_CLASSES_ROOT\txtfile]

[HKEY_CLASSES_ROOT\txtfile]
@="Text Document"
"EditFlags"=dword:00210000
"FriendlyTypeName"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,\
  00,6f,00,6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,\
  32,00,5c,00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,\
  00,2c,00,2d,00,34,00,36,00,39,00,00,00

[HKEY_CLASSES_ROOT\txtfile\DefaultIcon]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,00,6d,00,\
  61,00,67,00,65,00,72,00,65,00,73,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,31,\
  00,30,00,32,00,00,00

[HKEY_CLASSES_ROOT\txtfile\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,4e,00,4f,00,\
  54,00,45,00,50,00,41,00,44,00,2e,00,45,00,58,00,45,00,20,00,25,00,31,00,00,\
  00

[HKEY_CLASSES_ROOT\txtfile\shell\print\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,4e,00,4f,00,\
  54,00,45,00,50,00,41,00,44,00,2e,00,45,00,58,00,45,00,20,00,2f,00,70,00,20,\
  00,25,00,31,00,00,00

[HKEY_CLASSES_ROOT\txtfile\shell\printto\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,6e,00,6f,00,\
  74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,20,00,2f,00,70,00,74,\
  00,20,00,22,00,25,00,31,00,22,00,20,00,22,00,25,00,32,00,22,00,20,00,22,00,\
  25,00,33,00,22,00,20,00,22,00,25,00,34,00,22,00,00,00

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithList]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids]
"txtfile"=hex(0):

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice]
"Hash"="hyXk/CpboWw="
"ProgId"="txtfile"

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.txt]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.txt\UserChoice]
"Hash"="FvJcqeZpmOE="
"ProgId"="txtfile"
'@
	Set-Content -Path "$env:TEMP\bloatware.reg" -Value $MultilineComment -Force -ea 0 | Out-Null
	# import reg file
	reg import "$env:TEMP\bloatware.reg" 2> $null
	Clear-Host
	Write-Host "Restart to apply . . ."
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	show-menu	
	}
	2 {

				Clear-Host
				Write-Host "Installing: Store. Please wait . . ."
				# install store
				Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
	    
				# Fix [ PUR-AuthenticationFailure ]
				# enable Microsoft Account Sign-in Assistant
				$batchCode = @'
@echo off
:: https://privacy.sexy — v0.13.8 — Sun, 19 Oct 2025 08:43:23 GMT
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
echo --- Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
:: Restore service(s) to default state: `wlidsvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wlidsvc'; $defaultStartupMode = 'Manual'; $ignoreMissingOnRevert =  $false; Write-Host "^""Reverting service `"^""$serviceName`"^"" start to `"^""$defaultStartupMode`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { if ($ignoreMissingOnRevert) { Write-Output "^""Skipping: The service `"^""$serviceName`"^"" is not found. No action required."^""; Exit 0; }; Write-Warning "^""Failed to revert changes to the service `"^""$serviceName`"^"". The service is not found."^""; Exit 1; }; <# -- 2. Enable or skip if already enabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if (!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq "^""$defaultStartupMode"^"") { Write-Host "^""`"^""$serviceName`"^"" has already expected startup mode: `"^""$defaultStartupMode`"^"". No action required."^""; } else { try { Set-Service -Name "^""$serviceName"^"" -StartupType "^""$defaultStartupMode"^"" -Confirm:$false -ErrorAction Stop; Write-Host "^""Reverted `"^""$serviceName`"^"" with `"^""$defaultStartupMode`"^"" start, this may require restarting your computer."^""; } catch { Write-Error "^""Failed to enable `"^""$serviceName`"^"": $_"^""; Exit 1; }; }; <# -- 4. Start if not running (must be enabled first) #>; if ($defaultStartupMode -eq 'Automatic' -or $defaultStartupMode -eq 'Boot' -or $defaultStartupMode -eq 'System') { if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is not running, starting it."^""; try { Start-Service $serviceName -ErrorAction Stop; Write-Host "^""Started `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Failed to start `"^""$serviceName`"^"", requires restart, it will be started after reboot.`r`n$_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is already running, no need to start."^""; }; }"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
exit
'@
			    $batPath = "$env:TEMP\EnableMSAccountSignInAssistant.bat"
			    Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
			    Start-Process -FilePath $batPath -WindowStyle Hidden -Wait
		    
			    try {
			        # try Open Phone Link App page
			        Start-Process "ms-windows-store://pdp/?ProductId=9NMPJ99VJBWV"
			    }catch{
			        Write-Host "MS Store failed to install correctly, trying another method . . ."
			        Get-FileFromWeb -URL "https://github.com/ManuelBiscotti/test/raw/refs/heads/main/tools/MS_Store.msix" -File "$env:TEMP\MS_Store.msix"
			        Clear-Host
			        Start-Process "$env:TEMP\MS_Store.msix"
			    }
			    Clear-Host
			    show-menu
		    
			  }	  
			3 {

				Clear-Host
                Write-Host "Installing: All UWP Apps. Please wait . . ."
                # install all uwp apps
                Get-AppxPackage -AllUsers| ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
                Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                show-menu

			}	  
			4 {

				Clear-Host
				Write-Host "Install: UWP Features . . ."
				Write-Host ""
				Write-Host "Installing multiple features at once may fail."
				Write-Host "If so, restart PC between each feature install."
				Write-Host ""
				# open uwp optional features
				Start-Process "ms-settings:optionalfeatures"
				# uwp list
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W11"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-Extended Theme Content"
				Write-Host "-Facial Recognition (Windows Hello)"
				Write-Host "-Internet Explorer mode"
				Write-Host "-Math Recognizer"
				Write-Host "-Notepad (system)"
				Write-Host "-OpenSSH Client"
				Write-Host "-Print Management"
				Write-Host "-Steps Recorder"
				Write-Host "-WMIC"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Windows PowerShell ISE"
				Write-Host "-WordPad"
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W10"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-Internet Explorer 11"
				Write-Host "-Math Recognizer"
				Write-Host "-Microsoft Quick Assist (App)"
				Write-Host "-Notepad (system)"
				Write-Host "-OpenSSH Client"
				Write-Host "-Print Management Console"
				Write-Host "-Steps Recorder"
				Write-Host "-Windows Fax and Scan"
				Write-Host "-Windows Hello Face"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Windows PowerShell Integrated Scripting Environment"
				Write-Host "-WordPad"
				Write-Host ""
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			5 {

				Clear-Host
				Write-Host "Install: Legacy Features . . ."
				# open legacy optional features
				Start-Process "C:\Windows\System32\OptionalFeatures.exe"
				# legacy list
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W11"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-.Net Framework 4.8 Advanced Services +"
				Write-Host "-WCF Services +"
				Write-Host "-TCP Port Sharing"
				Write-Host "-Media Features +"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Microsoft Print to PDF"
				Write-Host "-Print and Document Services +"
				Write-Host "-Internet Printing Client"
				Write-Host "-Remote Differential Compression API Support"
				Write-Host "-SMB Direct"
				Write-Host "-Windows PowerShell 2.0 +"
				Write-Host "-Windows PowerShell 2.0 Engine"
				Write-Host "-Work Folders Client"
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W10"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-.Net Framework 4.8 Advanced Services +"
				Write-Host "-WCF Services +"
				Write-Host "-TCP Port Sharing"
				Write-Host "-Internet Explorer 11"
				Write-Host "-Media Features +"
				Write-Host "-Windows Media Player"
				Write-Host "-Microsoft Print to PDF"
				Write-Host "-Microsoft XPS Document Writer"
				Write-Host "-Print and Document Services +"
				Write-Host "-Internet Printing Client"
				Write-Host "-Remote Differential Compression API Support"
				Write-Host "-SMB 1.0/CIFS File Sharing Support +"
				Write-Host "-SMB 1.0/CIFS Automatic Removal"
				Write-Host "-SMB 1.0/CIFS Client"
				Write-Host "-SMB Direct"
				Write-Host "-Windows PowerShell 2.0 +"
				Write-Host "-Windows PowerShell 2.0 Engine"
				Write-Host "-Work Folders Client"
				Write-Host ""
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			6 {

				Clear-Host
				Write-Host "Installing: One Drive. Please wait . . ."
				# install onedrive w10
				cmd /c "C:\Windows\SysWOW64\OneDriveSetup.exe >nul 2>&1"
				# install onedrive w11
				cmd /c "C:\Windows\System32\OneDriveSetup.exe >nul 2>&1"
				Start-Process "$env:OneDrive"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}	  
			7 {
				
				Clear-Host
				Write-Host "Installing: Remote Desktop Connection. Please wait . . ."
				# download remote desktop connection
				Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2247659" -File "$env:TEMP\setup.exe"
				# install remote desktop connection 
				cmd /c "%TEMP%\setup.exe >nul 2>&1"
				Timeout T/1 | Out-Null
				Start-Process "mstsc"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			8 {
				
				Clear-Host
				Write-Host "Installing: Legacy Snipping Tool W10. Please wait . . ."
				# Ensure target directory exists
				New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force | Out-Null	
				# Ensure Accessories folder exists
				New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force | Out-Null		
				# Snipping Tool (Windows 10 Version 1803)		
				Get-FileFromWeb -URL "https://github.com/ManueITest/Windows/raw/main/SnippingTool.zip" -File "$env:TEMP\SnippingTool.zip"		
				Expand-Archive -Path "$env:TEMP\SnippingTool.zip" -DestinationPath "C:\Program Files\Windows NT\Accessories" -Force			
				# Create Snipping Tool Start menu shortcut		
				$shell = New-Object -ComObject WScript.Shell		
				$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk")		
				$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\SnippingTool.exe"	
				$shortcut.Save()
				Timeout T/1 | Out-Null
				Start-Process "C:\Program Files\Windows NT\Accessories\SnippingTool.exe"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			9 {
				
				Clear-Host
				Write-Host "Installing: Legacy Paint W10. Please wait . . ."
				# Ensure target directory exists
				New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force | Out-Null	
				# Ensure Accessories folder exists
				New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force | Out-Null		
				# classic Paint (mspaint) app taken from Windows 10 Build 14393
				Get-FileFromWeb -URL "https://github.com/ManueITest/Windows/raw/main/Classic%20Paint.zip" -File "$env:TEMP\ClassicPaint.zip"
				Expand-Archive -Path "$env:TEMP\ClassicPaint.zip" -DestinationPath "C:\Program Files\Windows NT\Accessories" -Force	
				# Create Paint Start menu shortcut  
				$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk")
				$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\mspaint1.exe"
				$shortcut.Save()
				Timeout T/1 | Out-Null
				Start-Process "C:\Program Files\Windows NT\Accessories\mspaint1.exe"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}    
			10 {
			
				Write-Host "Installing: HEVC Video Extensions & HEIF Image Extensions . . ."					
				# install hevc video extension needed for amd recording				
				Get-AppXPackage -AllUsers *Microsoft.HEVCVideoExtension* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
				Timeout /T 2 | Out-Null				
				# install heif image extension needed for some files				
				Get-AppXPackage -AllUsers *Microsoft.HEIFImageExtension* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
				Timeout /T 2 | Out-Null		

				}

			}    
		} 
	} else { Write-Host "Invalid input. Please select a valid option (1-10)." } 
