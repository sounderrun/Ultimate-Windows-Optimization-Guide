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

$Host.UI.RawUI.WindowTitle = 'Sound (Administrator)'
(irm https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/5%20Graphics/8%20Sound.ps1) -replace '.*WindowTitle.*', '' | iex

# download real
curl.exe -s 'https://github.com/miniant-git/REAL/releases/latest/REAL.exe' -o "$env:TEMP\REAL.exe"; --tray

# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy]
"AllowHeadlessExecution"=dword:00000001
"AllowMultipleBackgroundTasks"=dword:00000001
"InactivityTimeoutMs"=dword:ffffffff

; FL STUDIO

; CPU Priority: High
; I/O Priority: High
; Page Priority: High
; Scheduling: Foreground priority
; Working Set: no RAM limit
; "foreground I/O?", effect unclear
; CPU Affinity: All cores
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FL64.exe\PerfOptions]
"CpuPriorityClass"=dword:00000003
"IoPriority"=dword:00000003
"PagePriority"=dword:00000007
; "SchedulingCategory"=dword:00000005 ; experimental/undocumented
"WorkingSetLimit"=dword:00000000
; "IoPreference"=dword:00000001 ; experimental/undocumented
"CpuAffinityMask"=dword:ffffffff

; GPU Preferences: High performance
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX\UserGpuPreferences]
"C:\\Program Files\\Image-Line\\FL Studio 2025\\FL64.exe"="GpuPreference=2;"

; Assigns FL Studio to Pro Audio profile for highest audio scheduling priority
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Applications\FL64.exe]
"AppProfileName"="Pro Audio"

; Disable unnecessary visual effects for the FL Studio process
; Reduces GUI latency by simplifying window management
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"ProcessAffects"=dword:00000001
"FL64.exe"=dword:00000000




; Task scheduling and priority settings for CPU, GPU, and I/O
; Affinity = which CPU cores the task can use  
; Background Only = whether task runs as background  
; Clock Rate = scheduler tick rate for this task  
; GPU Priority = GPU scheduling priority  
; Priority = CPU priority for this task  
; Scheduling Category = overall scheduling class  
; SFIO Priority = special I/O priority

; PRO AUDIO - The most important task for any DAW. This provides the highest priority and lowest latency.
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]
"Affinity"=dword:00000000
"BackgroundPriority"=dword:00000008
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:0000001f
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"

; AUDIO - General audio processing engine
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
"Affinity"=dword:00000000
"BackgroundPriority"=dword:00000008
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:0000001f
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"

; CAPTURE - Directly manages audio input (microphone/interface recording).
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture]
"Affinity"=dword:00000000
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000005
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

; PLAYBACK - Important for general audio streaming. Bump its priority to ensure smooth playback.
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback]
"Affinity"=dword:00000000
"Background Only"="False"
"BackgroundPriority"=dword:00000004
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000002
"Scheduling Category"="High"
"SFIO Priority"="Normal"






; System Responsiveness
; Controls how much CPU time background processes receive when multimedia applications are running
; Minimizes background process interference during audio recording/playback
; Ensures maximum CPU availability for real-time audio processing
; Reduces potential for dropouts and glitches caused by background activity
; Works synergistically with the "Pro Audio" MMCSS profile
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"SystemResponsiveness"=dword:00000000
; "SystemResponsiveness"=dword:00000001 ; slightly safer, leaves some CPU for background tasks




; POWER

; Unpark cpu cores 
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000000

; Disable power throttling
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling]
"PowerThrottlingOff"=dword:00000001




; PERFORMANCE

; Win32PrioritySeparation controls how Windows balances foreground vs background process quantum length and boost
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000018   ; 24 decimal - BEST for audio
; "Win32PrioritySeparation"=dword:00000012   ; 18 decimal - Good and safer alternative
; "Win32PrioritySeparation"=dword:00000026   ; 38 decimal - Short quanta + foreground boost (lowest latency)


; Enable Virtual memory
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"ClearPageFileAtShutdown"=dword:00000000
"DisablePagingExecutive"=dword:00000001
"LargeSystemCache"=dword:00000000
"NonPagedPoolQuota"=dword:00000000
"NonPagedPoolSize"=dword:00000000
"PagedPoolQuota"=dword:00000000
"PagedPoolSize"=dword:00000000
"PagingFiles"=hex(7):63,00,3a,00,5c,00,70,00,61,00,67,00,65,00,66,00,69,00,6c,\
  00,65,00,2e,00,73,00,79,00,73,00,20,00,31,00,36,00,20,00,38,00,31,00,39,00,\
  32,00,00,00,00,00
"SecondLevelDataCache"=dword:00000000
"SessionPoolSize"=dword:00000004
"SessionViewSize"=dword:00000030
"SystemPages"=dword:00000000
"SwapfileControl"=dword:00000000
"AutoReboot"=dword:00000000
"CrashDumpEnabled"=dword:00000000
"Overwrite"=dword:00000000
"LogEvent"=dword:00000000
"MinidumpsCount"=dword:00000020
"FeatureSettings"=dword:00000000
"FeatureSettingsOverrideMask"=dword:00000003 ; disables mitigations for both Meltdown and Spectre v2
"FeatureSettingsOverride"=dword:00000003 ; disables mitigations for both Meltdown and Spectre v2
"PhysicalAddressExtension"=dword:00000001
"ExistingPageFiles"=hex(7):5c,00,3f,00,3f,00,5c,00,43,00,3a,00,5c,00,70,00,61,\
  00,67,00,65,00,66,00,69,00,6c,00,65,00,2e,00,73,00,79,00,73,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000003 ; Faster loading of your DAW and plugins. (value:0 = Disabled)
"EnableBootTrace"=dword:00000000
"BootId"=dword:0000001e
"BaseTime"=dword:2c9b398f
"EnableSuperfetch"=dword:00000000
"SfTracingState"=dword:00000001




; SOUND

; Set audiodg.exe priority to high
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions]
"CpuPriorityClass"=dword:00000003
"IoPriority"=dword:00000003

; Sound Scheme No Sounds
[HKEY_CURRENT_USER\AppEvents\Schemes]
@=".None"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\.Default\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\MailBeep\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemHand\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current]
@=""

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current]
@=""

; Disable Play Windows Startup sound
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation]
"DisableStartupSound"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\EditionOverrides]
"UserSetting_DisableStartupSound"=dword:00000001

; Communications Do nothing
[HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio]
"UserDuckingPreference"=dword:00000003
'@
set-content "$env:TEMP\Sound.reg" -value $MultilineComment -force
# import reg file
reg import "$env:TEMP\Sound.reg" 2> $null

# open sounds
Start-Process "mmsys.cpl"