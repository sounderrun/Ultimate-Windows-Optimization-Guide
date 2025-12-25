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
	
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
	$Host.UI.RawUI.BackgroundColor = "Black"
	$Host.PrivateData.ProgressBackgroundColor = "Black"
	$Host.PrivateData.ProgressForegroundColor = "White"
	Clear-Host
	
    function RunAsTI($cmd, $arg) {
    $id = 'RunAsTI'; $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code = @'
    $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
    $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
    0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
    $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
    0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
    $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
    1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
    0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
    $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
    if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
    function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
    M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
    $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
    $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
    F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
    'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
    $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
    function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
    $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
    function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
    $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
    if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
    if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
    L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
    if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
    if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V = ''; 'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $($V, $code) -type 7 -force -ea 0
    Start-Process powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
    }

    function Get-FileFromWeb {
    param ([Parameter(Mandatory)][string]$URL, [Parameter(Mandatory)][string]$File)
    function Show-Progress {
    param ([Parameter(Mandatory)][Single]$TotalValue, [Parameter(Mandatory)][Single]$CurrentValue, [Parameter(Mandatory)][string]$ProgressText, [Parameter()][int]$BarSize = 10, [Parameter()][switch]$Complete)
    $percent = $CurrentValue / $TotalValue
    $percentComplete = $percent * 100
    if ($psISE) { Write-Progress "$ProgressText" -id 0 -percentComplete $percentComplete }
    else { Write-Host -NoNewLine "`r$ProgressText $(''.PadRight($BarSize * $percent, [char]9608).PadRight($BarSize, [char]9617)) $($percentComplete.ToString('##0.00').PadLeft(6)) % " }
    }
    try {
    $request = [System.Net.HttpWebRequest]::Create($URL)
    $response = $request.GetResponse()
    if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) { throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'." }
    if ($File -match '^\.\\') { $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1] }
    if ($File -and !(Split-Path $File)) { $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File }
    if ($File) { $fileDirectory = $([System.IO.Path]::GetDirectoryName($File)); if (!(Test-Path($fileDirectory))) { [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null } }
    [long]$fullSize = $response.ContentLength
    [byte[]]$buffer = new-object byte[] 1048576
    [long]$total = [long]$count = 0
    $reader = $response.GetResponseStream()
    $writer = new-object System.IO.FileStream $File, 'Create'
    do {
    $count = $reader.Read($buffer, 0, $buffer.Length)
    $writer.Write($buffer, 0, $count)
    $total += $count
    if ($fullSize -gt 0) { Show-Progress -TotalValue $fullSize -CurrentValue $total -ProgressText " $($File.Name)" }
    } while ($count -gt 0)
    }
    finally {
    $reader.Close()
    $writer.Close()
    }
    }

Write-Host "1. Registry: Optimize (Recommended)"
Write-Host "2. Registry: Default"
while ($true) {
	$choice = Read-Host " "
	if ($choice -match '^[1-2]$') {
		switch ($choice) {
			1 {

				Clear-Host
				$progresspreference = 'silentlycontinue'
				Write-Host "Registry: Optimize . . ."
# FR33THY
$scriptContent = (Invoke-WebRequest "https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/6%20Windows/12%20Registry.ps1" -UseBasicParsing).Content
$scriptContent = $scriptContent -replace 'Write-Host "Restart to apply \. \. \."\s*\$\w+ = \$Host\.UI\.RawUI\.ReadKey\("NoEcho,IncludeKeyDown"\)', '' 
$scriptContent = $scriptContent -replace 'exit', ''
$scriptContent = $scriptContent -replace 'show-menu', ''
if ($scriptContent -match '1 \{\s*([\s\S]*?)\s*\}\s*2 \{') {
    $option1Code = $matches[1]
    Invoke-Expression $option1Code *> $null
} else {Write-Host "Failed to extract option 1 code" -ForegroundColor Red}

# My Overrides
# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

; remove activate windows watermark
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SoftwareProtectionPlatform]
"Activation"=dword:00000000

; disable onedrive startup
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"OneDrive"=-

; Disabling Media Player telemetry
[HKEY_CURRENT_USER\Software\Policies\Microsoft\WindowsMediaPlayer]
"PreventCDDVDMetadataRetrieval"=dword:00000001
"PreventMusicFileMetadataRetrieval"=dword:00000001
"PreventRadioPresetsRetrieval"=dword:00000001

; prevent-media-sharing
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer]
"PreventLibrarySharing"=dword:00000001

;prevent-windows-media-drm-internet-access-reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WMDRM]
"DisableOnline"=dword:00000001

; disable spotlight
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableCloudOptimizedContent"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableWindowsSpotlightFeatures"=dword:00000001
"DisableWindowsSpotlightWindowsWelcomeExperience"=dword:00000001
"DisableWindowsSpotlightOnActionCenter"=dword:00000001
"DisableWindowsSpotlightOnSettings"=dword:00000001
"DisableThirdPartySuggestions"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel]
"{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"=dword:00000001

; show frequent folders in quick access
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"ShowFrequent"=-

; enable lock
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]
"ShowLockOption"=-

; enable sleep
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]
"ShowSleepOption"=-

; disable Windows Platform Binary Table (WPBT)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"DisableWpbtExecution"=dword:00000001

; allow powershell scripts
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell]
"ExecutionPolicy"="Unrestricted"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell]
"ExecutionPolicy"="Unrestricted"

; prefer IPv4 over IPv6
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters]
"DisabledComponents"=dword:00000020

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"EnablePMTUDiscovery"=dword:00000001
"EnablePMTUBHDetect"=dword:00000000
"Tcp1323Opts"=dword:00000001
"SackOpts"=dword:00000001
"DefaultTTL"=dword:00000040
"GlobalMaxTcpWindowSize"=dword:00007fff

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters]
"MaxCacheEntryTtlLimit"=dword:0000fa00
"MaxNegativeCacheTtl"=dword:00000000

; visual effects
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=dword:3

[HKEY_CURRENT_USER\Control Panel\Desktop]
"FontSmoothing"="2"
"UserPreferencesMask"=hex:90,12,03,80,10,00,00,00
"DragFullWindows"="1"

[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]
"MinAnimate"="0"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ListviewAlphaSelect"=dword:00000001
"IconsOnly"=dword:00000000
"TaskbarAnimations"=dword:00000000 ; animations in the taskbar
"ListviewShadow"=dword:00000001

; enable Multimedia Class Scheduler Service (MMCS)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS]
"Start"=dword:00000002

; win32prior
; Another value said to have good results were A2 value 42 (Short, Fixed , High foreground boost) - https://docs.google.com/spreadsheets/d/1ZWQFycOWdODkUOuYZCxm5lTp08V2m7gjZQSCjywAsl8/edit#gid=762933934
; But since high foreground, means is prioritizing more the foreground app, it might take from other parts that could be relevant, like input, etc.. I could be wrong.
; https://docs.google.com/document/d/1ILugrwtHfmisYzI1MdCOhSzBPuLJPi5D7xYJgQ4sxDM/edit#heading=h.emf7opqgiwv8 - 36 has the lowest latency
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000024


; system responsiveness
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"AlwaysOn"=dword:00000001
"LazyMode"=dword:00000000
"SystemResponsiveness"=dword:0000000a

; cpu priorities
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
"Affinity"=dword:00000000
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture]
"Affinity"=dword:00000000
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000005
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing]
"Affinity"=dword:00000000
"Background Only"="True"
"BackgroundPriority"=dword:00000008
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution]
"Affinity"=dword:00000000
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000004
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="High"
"SFIO Priority"="High"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback]
"Affinity"=dword:00000000
"Background Only"="False"
"BackgroundPriority"=dword:00000004
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000003
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000001
"Scheduling Category"="High"
"SFIO Priority"="Normal"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager]
"Affinity"=dword:00000000
"Background Only"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000005
"Scheduling Category"="Medium"
"SFIO Priority"="Normal"

; enable virtual memory
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"ClearPageFileAtShutdown"=dword:00000000
"DisablePagingExecutive"=dword:00000001 ; disallow drivers to get paged into virtual memory
"HotPatchTableSize"=dword:00001000
"LargeSystemCache"=dword:00000000 ; use big system memory caching to improve microstuttering
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
"PhysicalAddressExtension"=dword:00000001
"ExistingPageFiles"=hex(7):5c,00,3f,00,3f,00,5c,00,43,00,3a,00,5c,00,70,00,61,\
  00,67,00,65,00,66,00,69,00,6c,00,65,00,2e,00,73,00,79,00,73,00,00,00,00,00
"SimulateCommitSavings"=dword:00000000
"TrackLockedPages"=dword:00000000
"TrackPtes"=dword:00000000
"DisablePageCombining"=dword:00000001 ; disable pagecombining
"IoPageLockLimit"=dword:ffffffff ; disable iopagelock

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"AlpcWakePolicy"=dword:00000001
"DisablePagingExecutive"=dword:00000001 ; disallow drivers to get paged into virtual memory (duplicate key)

; disable fetch feature that may cause higher disk usage
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000000
"EnableBootTrace"=dword:00000000
"EnableSuperfetch"=dword:00000000
"SfTracingState"=dword:00000000

; disable fth (fault tolerant heap)
[HKEY_LOCAL_MACHINE\Software\Microsoft\FTH]
"Enabled"=dword:00000000

; remove fth state key
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTH\State]

; disable error reporting
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting]
"DontSendAdditionalData"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting]
"DoReport"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting]
"Disabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports]
"PreventHandwritingErrorReports"=dword:00000001

; dont send a windows error report when a generic driver is installed on a device
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings]
"DisableSendGenericDriverNotFoundToWER"=dword:00000001

; disable game mode
[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"AllowAutoGameMode"=-
"AutoGameModeEnabled"=-

; turn off resume
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration]
"IsResumeAllowed"=dword:00000000

; disable CrossDeviceResume
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume]  
"DisableCrossDeviceResume"=dword:00000001  

; disable sync apps
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowSyncMySettings]
"value"=dword:00000000

; enale transparency
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"EnableTransparency"=dword:00000001

; hide all taskbar icons
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=-

; disable online tips
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"AllowOnlineTips"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings]
"DisableBalloonTips"=dword:00000001

; disable Clipboard
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"AllowCrossDeviceClipboard"=dword:00000000

; disable clipboard history
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"AllowClipboardHistory"=dword:00000000

; disable Cortana
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search]
"AllowCortana"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Experience]
"AllowCortana"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]
"AllowCortanaAboveLock"=dword:00000000

; disable ink workspace
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace]
"AllowWindowsInkWorkspace"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics]
"EnabledExecution"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000

; disable activity history
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableActivityFeed"=dword:00000000
"UploadUserActivities"=dword:00000000

; disable NCSI active probing
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator]
"NoActiveProbe"=dword:00000001

; restore quick access
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"HubMode"=-

; add "Take ownership" context menu to files and folders
[HKEY_CLASSES_ROOT\*\shell\TakeOwnership]
@="Take ownership"
"HasLUAShield"=""
"NoWorkingDirectory"=""
"NeverDefault"=""

[HKEY_CLASSES_ROOT\*\shell\TakeOwnership\command]
@="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l & pause' -Verb runAs\""
"IsolatedCommand"= "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l & pause' -Verb runAs\""


[HKEY_CLASSES_ROOT\Directory\shell\TakeOwnership]
@="Take ownership"
"HasLUAShield"=""
"NoWorkingDirectory"=""
"NeverDefault"=""

[HKEY_CLASSES_ROOT\Directory\shell\TakeOwnership\command]
@="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l /q & pause' -Verb runAs\""
"IsolatedCommand"="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l /q & pause' -Verb runAs\""

; enable win32 long paths
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem]
"LongPathsEnabled"=dword:00000001

; remove share context menu
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked]
"{e2bf9676-5f8f-435c-97eb-11607a5bedf7}"="Share"

; remove add to favourites context menu
[-HKEY_CLASSES_ROOT\*\shell\pintohomefile]

; hide insider program page
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility]
"HideInsiderPage"=dword:00000001

; clear icon cache
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_ShowRecentDocs"=dword:00000001
"Start_TrackDocs"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"Shell Icons"=-

; disable the " - shortcut" text for shortcuts
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates]
"ShortcutNameTemplate"="\"%s.lnk\""

; set "Do this for all current items" checked by default
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager]
"ConfirmationCheckBoxDoForAll"=dword:00000001

; disable automatic folder type discovery
[-HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags]

[HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell]
"FolderType"="NotSpecified"

; Show Drive letters before labels
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"ShowDriveLettersFirst"=dword:00000004

; Enable Compact Mode (File Explorer)
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"UseCompactMode"=dword:00000001

; enable network drives over uac
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLinkedConnections"=dword:00000001
"LocalAccountTokenFilterPolicy"=dword:00000001
"EnableVirtualization"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"DisableLoopbackCheck"=dword:00000001

; hide lock screen
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData]
"AllowLockScreen"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization]
"NoLockScreen"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]
"AllowCortanaAboveLock"=dword:00000000

; disable automatic registry backup
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager]
"EnablePeriodicBackup"=dword:00000000

; disable "Look for an app in the Store" notification
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"NoUseStoreOpenWith"=dword:00000001

; disable downloaded files from being blocked in file explorer
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments]
"SaveZoneInformation"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments]
"SaveZoneInformation"=dword:00000001

; disable mark-of-the-web (MOTW) for downloaded files
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AttachmentManager]
"ScanWithAntiVirus"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Associations]
"LowRiskFileTypes"=".exe;.msi;.bat;.cmd;.ps1;.js;.vbs"

; disable protected view for office files
[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security\ProtectedView]
"DisableInternetFilesInPV"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView]
"DisableInternetFilesInPV"=dword:00000001

; disable malicious software removal tool from installing
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT]
"DontOfferThroughWUAU"=dword:00000001

; disable live tiles
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications]
"NoTileApplicationNotification"=dword:00000001

; increase wallpaper quallity
[HKEY_CURRENT_USER\Control Panel\Desktop]
"JPEGImportQuality"=dword:00000063

; enable windows installer in safe Mode
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer]
@="Service"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer]
@="Service"

; change the timeout for disk auto check to 5 seconds
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"AutoChkTimeout"=dword:00000005

; disable blur on sign-in screen
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"DisableAcrylicBackgroundOnLogon"=dword:00000001

; disable settings home
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"="hide:home"

; disable consumer features
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableSoftLanding"=dword:00000001
"DisableConsumerFeatures"=dword:00000001
"DisableWindowsConsumerFeatures"=dword:00000001
"DisableConsumerAccountStateContent"=dword:00000001

; disable homegroup
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupListener]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupProvider ]
"Start"=dword:00000004

; disable wifi-sense
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"AllowWiFiHotSpotReporting"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting]
"Value"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots]
"Value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config]
"AutoConnectAllowedOEM"=dword:00000000

; disable ai features
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI]
"DisableAIDataAnalysis"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsAI]
"DisableAIDataAnalysis"=dword:00000001
"AllowRecallEnablement"=dword:00000000

; disable NumLock on startup
[HKEY_USERS\.DEFAULT\Control Panel\Keyboard]
"InitialKeyboardIndicators"=dword:"0"

; enable verbose messages during logon
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"VerboseStatus"=dword:00000001

; disable thumbnail cache
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"DisableThumbnailCache"=dword:00000001

; close apps automatically on shutdown
[HKEY_CURRENT_USER\Control Panel\Desktop]
"AutoEndTasks"="1"
"HungAppTimeout"="1000"
"WaitToKillAppTimeout"="1000"
"LowLevelHooksTimeout"="1000"

; fix mouse cursor dissapeiring
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableCursorSuppression"=dword:00000000

; disable tablet mode
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell]
"TabletMode"=dword:00000000
"SignInMode"=dword:00000001

; disables push to install feature
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall]
"DisablePushToInstall"=dword:00000001

; Allow double-click execution of .ps1 files (Windows PowerShell)
[HKEY_CLASSES_ROOT\Applications\powershell.exe\shell\open\command]
@="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -ExecutionPolicy Unrestricted -File \"%1\""

; Allow double-click execution of .ps1 files (PowerShell 7)
[HKEY_CLASSES_ROOT\Applications\pwsh.exe\shell\open\command]
@="C:\\Program Files\\PowerShell\\7\\pwsh.exe -NoLogo -ExecutionPolicy Unrestricted -File \"%1\""

; FrameSync Labs Registry Tweaks

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"TimerCoalescing"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00

[HKEY_CURRENT_USER\Control Panel\Desktop]
"ScreenSaveActive"="0"
"ScreenSaveTimeOut"="0"
"SCRNSAVE.EXE"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet]
"EnableActiveProbing"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"EventProcessorEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm]
"OverlayTestMode"=dword:00000005
"OverlayMinFPS"=dword:0000270f

[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_FSEBehaviorMode"=dword:00000002
"GameDVR_FSEBehavior"=dword:00000002

[HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys]
"Flags"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap]
"Enabled"=dword:00000001
"OverrideServerSKU"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"ScopeType"="Client"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"SleepStudyDisabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"ThreadDpcEnable"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"QueuedPresentLimit"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"HwSchMode"=dword:00000002
"HwSchTreatExperimentalAsStable"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"SerializeTimerExpiration"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System]
"EnableCpuQuota"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters]
"MouseDataQueueSize"=dword:00000023

; SECURITY

Windows Registry Editor Version 5.00

; Disable Sharing mapped drives
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]

; Disable Process and Kernel Mitigations
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\kernel]
"DisableExceptionChainValidation"=dword:00000001
"KernelSEHOPEnabled"=dword:00000000
"MitigationOptions"=hex:22,22,22,20,22,02,20,22,22,22,22,22,22,20,02,00,00,00,20,00,02,00,00,00,00,00,00,00
"MitigationAuditOptions"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"EnableCfg"=dword:00000000
"MoveImages"=dword:00000000

; Disable DMA remapping
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy]
"value"=dword:00000002

; WDigest
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest]
"UseLogonCredential"=dword:00000000

; Block untrusted fonts
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions]
"MitigationOptions_FontBocking"=qword:000100000000000000

; Prevent DLL Hijacking
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"CWDIllegalInDllSearch"=dword:00000002
"SafeDLLSearchMode"=dword:00000001

; Prevent unauthenticated RPC connections
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc]
"RestrictRemoteClients"=dword:00000001

; Block anonymous enumeration
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RestrictAnonymousSAM"=dword:00000001
"RestrictAnonymous"=dword:00000001

; Disable PC discoverable on network
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control]
"NewNetworkWindowOff"=dword:00000001

; Disable DEP
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"NoDataExecutionPrevention"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"DisableHHDEP"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main]
"DEPOff"=dword:00000001

; Disable Windows Connect Now wizard
[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\UI]
"DisableWcnUi"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars]
"DisableFlashConfigRegistrar"=dword:00000000
"DisableInBand802DOT11Registrar"=dword:00000000
"DisableUPnPRegistrar"=dword:00000000
"DisableWPDRegistrar"=dword:00000000
"EnableRegistrars"=dword:00000000

; Disable Mitigations on csrss
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe]
"MitigationAuditOptions"=hex:22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22
"MitigationOptions"=hex:22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22,22

; Disable Kernel-Managed Memory and disable Meltdown/Spectre patches
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management]
"FeatureSettings"=dword:00000000
"FeatureSettingsOverride"=dword:00000003
"FeatureSettingsOverrideMask"=dword:00000003

; Disable additional NTFS/ReFS mitigations
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager]
"ProtectionMode"=dword:00000000

; Disable Intel TSX mitigation
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel]
"DisableTsx"=dword:00000000


; disable password reveal button
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI]
"DisablePasswordReveal"=dword:00000001

; disable firewall notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection]
"NoActionNotificationDisabled"=dword:00000001
"SummaryNotificationDisabled"=dword:00000001
"FilesBlockedNotificationDisabled"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender Security Center\Account protection]
"DisableNotifications"=dword:00000001
"DisableDynamiclockNotifications"=dword:00000001
"DisableWindowsHelloNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Epoch]
"Epoch"=dword:000004cf

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"DisableNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"DisableNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"DisableNotifications"=dword:00000001

; Disable Core Isolation Memory Integrity
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"Enabled"=dword:00000000

; Disable DMA memory protection and cores isolation (virtualization-based protection)
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"ChangedInBootCycle"=-
"WasEnabledBy"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FVE]
"DisableExternalDMAUnderLock"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000000
"HVCIMATRequired"=dword:00000000
"RequirePlatformSecurityFeatures"=dword:00000001
"HypervisorEnforcedCodeIntegrity"=dword:00000000
"LsaCfgFlags"=dword:00000000
"ConfigureSystemGuardLaunch"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard]
"RequireMicrosoftSignedBootChain"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"WasEnabledBy"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios]
"HypervisorEnforcedCodeIntegrity"=dword:00000000

; hide family options settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options]
"UILockdown"=dword:00000001

; hide account protection settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection]
"UILockdown"=dword:00000001

; increase system restore point creation frequency
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore]
"SystemRestorePointCreationFrequency"=dword:00000000

; limit defender cpu usage
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
"AvgCPULoadFactor"=dword:00000019
"ScanAvgCPULoadFactor"=dword:00000019

; dwm tweaks
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"DesktopHeapLogging"=dword:00000000
"DwmInputUsesIoCompletionPort"=dword:00000000
"EnableDwmInputProcessing"=dword:00000000

; increase explorer responses
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid\Parameters]
"TreatAbsolutePointerAsAbsolute"=dword:00000001
"TreatAbsoluteAsRelative"=dword:00000000

; Disable Drivers from Windows Update
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Update]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata]
"PreventDeviceMetadataFromNetwork"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching]
"SearchOrderConfig"=dword:00000000
"DontSearchWindowsUpdate"=dword:00000001




; --SERVICES--

; WINDOWS
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AarSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AJRouter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ALG]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppIDSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Appinfo]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppMgmt]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppReadiness]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppVClient]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppXSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AssignedAccessManagerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AudioEndpointBuilder]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Audiosrv]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\autotimesvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AxInstSV]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BcastDVRUserService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BDESVC]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BITS]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BluetoothUserService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Browser]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BrokerInfrastructure]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BTAGService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BthAvctpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\camsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CaptureService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\cbdhsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CDPSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CDPUserSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CertPropSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ClipSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CloudBackupRestoreSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\cloudidsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\COMSysApp]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ConsentUxUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CoreMessagingRegistrar]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CredentialEnrollmentManagerUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CryptSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CscService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DcomLaunch]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dcsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\defragsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceAssociationBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceAssociationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceInstall]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevicePickerUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevicesFlowUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevQueryBroker]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Dhcp]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DialogBlockingService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DispBrokerDesktopSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DisplayEnhancementService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DmEnrollmentSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Dnscache]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DoSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dot3svc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DPS]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DsmSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DsSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DusmSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EapHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdatem]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdate]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EFS]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\embeddedmode]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EntAppSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventSystem]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Fax]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\fdPHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FDResPub]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\fhsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FontCache]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FontCache3.0.0.0]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FrameServerMonitor]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FrameServer]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GameInputSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\gpsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GraphicsPerfSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\hidserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\HvHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\icssvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\IKEEXT]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\InstallService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\InventorySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\iphlpsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\IpxlatCfgSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\KeyIso]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\KtmRm]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanWorkstation]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lfsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LicenseManager]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lltdsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lmhosts]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\logi_lamparray_service]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LSM]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LxpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MapsBroker]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\McpManagementService]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MDCoreSvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MessagingService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MixedRealityOpenXRSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mpssvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSDTC]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSiSCSI]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\msiserver]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MsKeyboardFilter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NaturalAuthentication]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcbService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcdAutoSetup]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Netlogon]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Netman]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\netprofm]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetSetupSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetTcpPortSharing]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcCtnrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NlaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NPSMSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nsi]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\OneSyncSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\p2pimsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\p2psvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\P9RdrService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PcaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PeerDistSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PenService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\perceptionsimulation]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PerfHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PhoneSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PimIndexMaintenanceSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\pla]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PlugPlay]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PNRPAutoReg]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PNRPsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PolicyAgent]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Power]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintNotify]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ProfSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PushToInstall]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\QWAVE]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RasAuto]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RasMan]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteAccess]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteRegistry]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RetailDemo]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RmSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcEptMapper]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcLocator]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCardSvr]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ScDeviceEnum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Schedule]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCPolicySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SDRSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\seclogon]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SEMgrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensorDataService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensorService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SENS]
"Start"=dword:00000002

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense]
; "Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SessionEnv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedRealitySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ShellHWDetection]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\shpamsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\smphost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SmsRouter]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SNMPTrap]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\spectrum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Spooler]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\sppsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SSDPSRV]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ssh-agent]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SstpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StateRepository]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\stisvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StiSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StorSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\svsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\swprv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SysMain]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SystemEventsBroker]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TabletInputService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TapiSrv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TermService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TextInputManagementService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Themes]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TieringEngineService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TimeBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TokenBroker]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TrkWks]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TroubleshootingSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TrustedInstaller]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\tzautoupdate]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UdkUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UevAgentService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uhssvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UmRdpService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UnistoreSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\upnphost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UserDataSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UserManager]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UsoSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VacSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VaultSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vds]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicguestinterface]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicheartbeat]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmickvpexchange]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicrdv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicshutdown]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmictimesync]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvmsession]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvss]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VSS]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\W32Time]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WaaSMedicSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WalletService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WarpJITSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wbengine]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WbioSrvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Wcmsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wcncsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiServiceHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiSystemHost]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]
; "Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WebClient]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]
; "Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Wecsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WEPHOSTSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wercplsupport]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WerSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WFDSConMgrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WiaRpc]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinHttpAutoProxySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Winmgmt]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinRM]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wisvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WlanSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wlidsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wlpasvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WManSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wmiApSrv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WMPNetworkSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\workfolderssvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpcMonSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WPDBusEnum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService]
"Start"=dword:00000002

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WSearch]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wuauserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WwanSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblAuthManager]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblGameSave]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxGipSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxNetApiSvc]
"Start"=dword:00000003

; OTHER
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsusUpdateCheck]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BraveElevationService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\brave]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bravem]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\jhi_service]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMIRegistrationService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intel(R) TPM Provisioning Service]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intel(R) Platform License Manager Service]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ipfsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igccservice]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cplspcon]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LMS]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelAudioService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intel(R) Capability Licensing Service TCP IP Interface]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cphs]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DSAService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DSAUpdateService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxCUIService2.0.0.0]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RstMwService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intel(R) SUR QC SAM]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemUsageReportSvc_QUEENCREEK]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAfsService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SynTPEnhService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NahimicService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RtkAudioUniversalService]
"Start"=dword:00000004

; --------------------------------------------------------------------------------------------------
;   @script       windows-updates-pause.reg
;   @author       Aetherinox
;   @url          https://github.com/Aetherinox/pause-windows-updates
;
;   A script to pause Windows Updates for a long period of time.
;
;   User can un-pause updates by opening the 'Windows Update' window.
;   You can also access that window by opening your start menu, select 'Run'
;   and type
;       ms-settings:windowsupdate
;
;   You can also re-enable updates by executing the other file included
;   in the repo URL above:
;       windows-updates-unpause.reg
; --------------------------------------------------------------------------------------------------

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
"PauseFeatureUpdatesStartTime"="2025-01-01T00:00:00Z"
"PauseFeatureUpdatesEndTime"="2051-12-31T00:00:00Z"
"PauseQualityUpdatesStartTime"="2025-01-01T00:00:00Z"
"PauseQualityUpdatesEndTime"="2051-12-31T00:00:00Z"
"PauseUpdatesStartTime"="2025-01-01T00:00:00Z"
"PauseUpdatesExpiryTime"="2051-12-31T00:00:00Z"
"ActiveHoursStart"=dword:0000000d
"ActiveHoursEnd"=dword:00000007
"FlightSettingsMaxPauseDays"=dword:00002727

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc]
"Start"=dword:00000003
"FailureActions"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
"AUOptions"=dword:00000001
"NoAutoUpdate"=dword:00000001
"NoAUShutdownOption"=dword:00000001
"AlwaysAutoRebootAtScheduledTime"=dword:00000000
"NoAutoRebootWithLoggedOnUsers"=dword:00000001
"AutoInstallMinorUpdates"=dword:00000000
"UseWUServer"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings]
"PausedFeatureStatus"=dword:00000001
"PausedQualityStatus"=dword:00000001
"PausedQualityDate"="2025-01-01T00:00:00Z"
"PausedFeatureDate"="2025-01-01T00:00:00Z"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

; DWM tweaks
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"FrameLatency"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"ForceDirectDrawSync"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"MaxQueuedPresentBuffers"=dword:00000001

; Disable InterruptSteering
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"InterruptSteeringDisabled"=dword:00000001

; Resource Sets
; Founded by Kizzimo
; Registry made and modified by Alchemy Tweaks

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets]

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationService]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceElastic]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriElastic]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceRemote]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\AppToAppTarget]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundAudioPlayer]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundCachedFileUpdater]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskCompletion]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskDebug]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransfer]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransferNetworkState]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Balloon]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CalendarProviderAsChild]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CallingEvent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CallingEventHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ChatMessageNotification]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ComponentTarget]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ContinuousBackgroundExecution]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CortanaSpeechBackground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CreateProcess]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultModernBackgroundTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultPPLE]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultPPLE2]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcess]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcessNormalPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHost]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHostHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHostPPLE]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\FileProviderTarget]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundAgent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundCachedFileUpdater]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundTaskCompletion]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Frozen]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GenericExtendedExecution]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GeofenceTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundAgent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundDemoted]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundTransfer]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\IoTStartupTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\JumboForegroundAgent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaBackgroundTaskCompletion]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaDefaultModernBackgroundTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaPrelaunchForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiDebugModeForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozen]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNCS]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNK]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForegroundLarge]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPaused]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedDNK]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausing]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningBluetooth]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningControlChannel]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\MediaProcessing]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\OemBackgroundAgent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\OemTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PendingDefaultPPLE]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PiP]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PreinstallTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PrelaunchForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PushTriggerTask]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ResourceIntensive]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShareDataPackageHost]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShortRunningBluetooth]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\TaskCompletionHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiComposer]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiDebugModeForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiForegroundDNK]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozen]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNCS]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNK]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiLockScreen]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundExtended]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundLarge]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiOverlay]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPaused]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausedDNK]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausedHighPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausing]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausingLowPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom1]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom2]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom3]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom4]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VideoTranscoding]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallBackground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallBackgroundPriority]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallForeground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipForegroundWorker]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipSuspendedBackground]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipWorker]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Vpn]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\WebAuthSignIn]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ResourceIntensive"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

; SerializeTimerExpiration (Value 1).reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"SerializeTimerExpiration"=dword:00000001

; Power Profile Events Priorities Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0AABB002-A307-447e-9B81-1D819DF6C6D0}]
"Name"="SustainedPerf"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0c3d5326-944b-4aab-8ad8-fe422a0e50e0}]
"Name"="MultimediaQos"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}]
"Name"="LowLatency"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{4569E601-272E-4869-BCAB-1C6C03D7966F}]
"Name"="LowPower"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{8BC6262C-C026-411d-AE3B-7E2F70811A13}]
"Name"="Standby"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{a4a61b5f-f42c-4d23-b3ab-5c27df9f0f18}]
"Name"="EntryLevelPerf"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{c04a802d-2205-4910-ae98-3b51e3bb72f2}]
"Name"="Background"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{D4140C81-EBBA-4e60-8561-6918290359CD}]
"Name"="GameMode"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{EE1E4F72-E368-46b1-B3C6-5048B11C2DBD}]
"Name"="Constrained"
"Pri"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}]
"TimeLimitInSeconds"=dword:00000001

; Power Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy]
"DisableTaggedEnergyLogging"=dword:00000001 ;Turns off energy tracking logs that record how much power apps use. Less background logging = slightly less CPU use.
"TelemetryMaxApplication"=dword:00000000 ;Stops Windows from collecting energy data per app for telemetry (data reporting).
"TelemetryMaxTagPerApplication"=dword:00000000 ;Stops Windows from tagging and tracking extra details about app energy use.

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle]
"PerfEnablePackageIdle"=dword:00000000 ;Prevents the system from forcing CPU packages into idle states (C-states). Keeps the CPU more responsive but uses a bit more power.

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"PlatformAoAcOverride"=dword:00000000 ;Disables Modern Standby (AoAc) so your PC uses classic sleep mode instead of the mobile-style background mode that can cause instability.

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor]
"CPPCEnable"=dword:00000000 ;Turns off Collaborative Processor Performance Control, meaning Windows won’t “negotiate”
"AllowPepPerfStates"=dword:00000000 ;Blocks Platform Energy Provider (PEP) from managing CPU performance states automatically. Basically, disables “smart” energy saving.

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System]
"CountOperations"=dword:00000000 ;Disables operation counting in the I/O system Windows won’t measure how many read/write actions apps do. Reduces logging overhead.

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\fssProv]
"EncryptProtocol"=dword:00000000 ;Turns off forced encryption in the File System Shadow Copy Provider (used by backups). Rarely affects daily use.

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci\Parameters]
"ASPMOptOut"=dword:00000001 ;Tells Windows to ignore PCIe power-saving features (ASPM). Keeps PCIe devices (like GPUs, SSDs) always ready and avoids latency spikes.

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule]
"DisableRpcOver"=dword:00000001 ;Disables RPC over Scheduler, stopping certain scheduled background communications or telemetry tasks. Reduces remote calls made by Windows.

; Kernel Tweaks
; Base tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"DisableOverlappedExecution"=dword:00000000
"PriorityControl"=dword:00000032
"QuantumLength"=dword:00000014
"TimeIncrement"=dword:0000000f

; Advanced tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"DisableLowQosTimerResolution"=dword:00000001

; DPC Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"DpcWatchdogProfileOffset"=dword:00000000
"DpcTimeout"=dword:00000000
"IdealDpcRate"=dword:00000001
"MaximumDpcQueueDepth"=dword:00000001
"MinimumDpcRate"=dword:00000001
"DpcWatchdogPeriod"=dword:00000000
"UnlimitDpcQueue"=dword:00000001

; SplitLargeCaches
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"SplitLargeCaches"=dword:00000001

; NVMe Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters]
"StorNVMeAllowZeroLatency"=dword:00000001
"QueueDepth"=dword:00000040
"NvmeMaxReadSplit"=dword:00000004
"NvmeMaxWriteSplit"=dword:00000004
"ForceFlush"=dword:00000001
"ImmediateData"=dword:00000001
"MaxSegmentsPerCommand"=dword:00000100
"MaxOutstandingCmds"=dword:00000100
"ForceEagerWrites"=dword:00000001
"MaxQueuedCommands"=dword:00000100
"MaxOutstandingIORequests"=dword:00000100
"NumberOfRequests"=dword:000005DC
"IoSubmissionQueueCount"=dword:00000003
"IoQueueDepth"=dword:00000040
"HostMemoryBufferBytes"=dword:000005DC
"ArbitrationBurst"=dword:00000100

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device]
"StorNVMeAllowZeroLatency"=dword:00000001
"QueueDepth"=dword:00000040
"NvmeMaxReadSplit"=dword:00000004
"NvmeMaxWriteSplit"=dword:00000004
"ForceFlush"=dword:00000001
"ImmediateData"=dword:00000001
"MaxSegmentsPerCommand"=dword:00000100
"MaxOutstandingCmds"=dword:00000100
"ForceEagerWrites"=dword:00000001
"MaxQueuedCommands"=dword:00000100
"MaxOutstandingIORequests"=dword:00000100
"NumberOfRequests"=dword:000005DC
"IoSubmissionQueueCount"=dword:00000003
"IoQueueDepth"=dword:00000040
"HostMemoryBufferBytes"=dword:000005DC
"ArbitrationBurst"=dword:00000100

; Priority Control Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"AdjustDpcThreshold"=dword:00000320
"DeepIoCoalescingEnabled"=dword:00000001
"IdealDpcRate"=dword:00000320
"ForegroundBoost"=dword:00000001
"SchedulerAssistThreadFlagOverride"=dword:00000001
"ThreadBoostType"=dword:00000002
"ThreadSchedulingModel"=dword:00000001
'@
Set-Content -Path "$env:TEMP\RegistryOptimize.reg" -Value $MultilineComment -Force -ErrorAction SilentlyContinue | Out-Null
# import reg file RunAsTI
$RegistryOptimize = @'
Regedit.exe /S "$env:TEMP\RegistryOptimize.reg"
'@
RunAsTI powershell "-nologo -windowstyle hidden -command $RegistryOptimize"
Timeout /T 5 | Out-Null

# TASKS
# disable OneDrive and Edge scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*OneDrive*" -or $_.TaskName -like "*Edge*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }
# disable automatic disk defragmentation
schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null	
# disable security scheduled tasks
Disable-ScheduledTask -TaskName "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" *> $null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" *> $null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" *> $null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" *> $null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Verification" *> $null

# SECURITY
# set account password to never expire
Get-LocalUser | ForEach-Object { Set-LocalUser -Name $_.Name -PasswordNeverExpires $true | Out-Null }
# disable defender telemetry
Set-MpPreference -CloudBlockLevel 0 -Force | Out-Null
Set-MpPreference -SubmitSamplesConsent 2 -Force | Out-Null
Set-MpPreference -MAPSReporting 0 -Force | Out-Null
Set-MpPreference -DisableCoreServiceECSIntegration $true -Force | Out-Null
# disable Mitigations
$batchCode = @'
@echo off
setlocal EnableDelayedExpansion

:: Disable Spectre and Meltdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f > nul

:: Disable Structured Exception Handling Overwrite Protection (SEHOP)
:: Exists in ntoskrnl strings, keep for now
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f > nul

:: Disable Control Flow Guard (CFG)
:: Find correct mitigation values for different Windows versions
:: Initialize bit mask in registry by disabling a random mitigation
PowerShell -NoP -C "Set-ProcessMitigation -System -Disable CFG" > nul

:: Get current bit mask
for /f "tokens=3 skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do (
    set "mitigation_mask=%%a"
)

:: Set all bits to 2 (Disable all process mitigations)
for /l %%a in (0,1,9) do (
    set "mitigation_mask=!mitigation_mask:%%a=2!"
)

:: Fix Valorant with mitigations disabled - enable CFG
set "enableCFGApps=valorant valorant-win64-shipping vgtray vgc"
PowerShell -NoP -C "foreach ($a in $($env:enableCFGApps -split ' ')) {Set-ProcessMitigation -Name $a`.exe -Enable CFG}" > nul

:: Set Data Execution Prevention (DEP) only for operating system components
:: https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention
:: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#verification-settings
bcdedit /set nx OptIn > nul

:: Apply mask to kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul

:: Disable file system mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f > nul

exit /b
'@
$bat = "$env:TEMP\Disable All Mitigations.cmd"
Set-Content -Path $bat -Value $batchCode -Encoding ASCII	
& $bat | Out-Null

# UPDATES
# Sets Windows Update to recommended settings
Write-Host "Disabled driver offering through Windows Update"
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null}
# Sets Windows Update to Semi-Annual Channel (Targeted)            
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20 | Out-Null
# Defers feature updates for 365 days
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365 | Out-Null
# Defers quality updates for 4 days
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4 | Out-Null

# sherifmagdy32 
# audio
Get-FileFromWeb "https://github.com/sherifmagdy32/gaming_os_tweaker/raw/refs/heads/main/scripts/tweaks/audio.cmd" "$env:TEMP\audio.cmd"
& "$env:TEMP\audio.cmd" *> $null
# disk
Get-FileFromWeb "https://github.com/sherifmagdy32/gaming_os_tweaker/raw/refs/heads/main/scripts/tweaks/disk.cmd" "$env:TEMP\disk.cmd"
& "$env:TEMP\disk.cmd" *> $null
# processes
Get-FileFromWeb "https://github.com/sherifmagdy32/gaming_os_tweaker/raw/refs/heads/main/scripts/tweaks/processes.cmd" "$env:TEMP\processes.cmd"
cmd /c "echo y | $env:TEMP\processes.cmd" *> $null
<#
# AlchemyTweaks
# Verified-Tweaks
# DWM tweaks
Get-FileFromWeb "https://github.com/AlchemyTweaks/Verified-Tweaks/raw/refs/heads/main/DWM/DWMAdjustablesd-jdallmann.bat" "$env:TEMP\DWMAdjustablesd-jdallmann.bat"
& "$env:TEMP\DWMAdjustablesd-jdallmann.bat" | Out-Null
Get-FileFromWeb "https://github.com/AlchemyTweaks/Verified-Tweaks/raw/refs/heads/main/DWM/DWMImmediateRender-Kizzimo.bat" "$env:TEMP\DWMImmediateRender-Kizzimo.bat"
& "$env:TEMP\DWMImmediateRender-Kizzimo.bat" | Out-Null

# DPC Kernel Tweaks
Get-FileFromWeb "https://github.com/AlchemyTweaks/Verified-Tweaks/raw/refs/heads/main/Kernel/DPC%20Kernel%20Tweaks/Apply%20DPC%20Kernel%20Tweaks.bat" "$env:TEMP\Apply DPC Kernel Tweaks.bat"
(Get-Content "$env:TEMP\Apply DPC Kernel Tweaks.bat") -replace 'pause', '' | Out-File "$env:TEMP\Apply DPC Kernel Tweaks.bat" -Encoding ASCII
& "$env:TEMP\Apply DPC Kernel Tweaks.bat" | Out-Null
# Kernel Tweaks
Get-FileFromWeb "https://github.com/AlchemyTweaks/Verified-Tweaks/raw/refs/heads/main/Kernel/Kernel%20Tweaks/Apply%20Kernel%20Tweaks.bat" "$env:TEMP\Apply Kernel Tweaks.bat"
& "$env:TEMP\Apply Kernel Tweaks.bat" | Out-Null
# Officially-Verified
#>
# MEMORY
# Disable Memory Compression
Disable-MMAgent -MemoryCompression *> $null
# Disable Page Combining
Disable-MMAgent -PageCombining *> $null
# Enable Application PreLaunch
Enable-MMAgent -ApplicationPreLaunch *> $null
# Group svchost.exe processes
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb | Out-Null	
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force | Out-Null			

# NTFS
fsutil behavior set disabledeletenotify 0 | Out-null
fsutil behavior set disabledeletenotify refs 0 | Out-null
fsutil behavior set mftzone 2 | Out-null
fsutil behavior set disablelastaccess 1 | Out-null
fsutil behavior set encryptpagingfile 0 | Out-null
fsutil behavior set memoryusage 2 | Out-null
fsutil behavior set disable8dot3 1 | Out-null
# Keep both set to 0, otherwise it will break restore system point.
fsutil behavior set disablecompression 0 | Out-null
fsutil behavior set disableencryption 0 | Out-null

# BOOT
# Enable Legacy F8 Boot Recovery
If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\LastKnownGood')) {New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\LastKnownGood' -Force | Out-Null}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\LastKnownGood' -Name 'Enabled' -Type DWord -Value 1 -Force      
Start-Process -FilePath cmd.exe -ArgumentList '/c bcdedit /Set {Current} BootMenuPolicy Legacy' -Wait | Out-Null      
# BCDEdit Tweaks
# https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#additional-settings
# Constantly pool interrupts, dynamic tick was implemented as a power saving feature
# Disable the kernel from being tickless
bcdedit /set disabledynamictick Yes | Out-Null
bcdedit /set useplatformtick Yes | Out-Null
bcdedit /set useplatformclock no | Out-Null
bcdedit /set tscsyncpolicy Enhanced | Out-Null	
bcdedit /set bootmenupolicy Legacy | Out-Null
bcdedit /set integrityservices disable | Out-Null
bcdedit /set bootux disabled | Out-Null
bcdedit /set bootlog no | Out-Null
bcdedit /event off | Out-Null
bcdedit /bootdebug off | Out-Null
bcdedit /set debug no | Out-Null
bcdedit /set ems no | Out-Null
bcdedit /set bootems no | Out-Null
bcdedit /set sos no | Out-Null
# Disable Hyper-V
bcdedit /set hypervisorlaunchtype off | Out-Null
# Disable DMA memory protection and cores isolation ("virtualization-based protection").
bcdedit /set vsmlaunchtype Off | Out-Null
bcdedit /set vm No | Out-Null
# Apply MSI to devices by default
bcdedit /set MSI Default | Out-Null
netsh interface tcp set global autotuninglevel=disabled | Out-Null
# Disable 57-bits 5-level paging, also known as "Linear Address 57". Only 100% effective on 10th gen Intel. 256 TB of virtual memory per-disk is way much more than enough anyway.
bcdedit /set linearaddress57 OptOut | Out-Null
bcdedit /set increaseuserva 268435328 | Out-Null
# Disable DEP
bcdedit /set nx AlwaysOff | Out-Null
# Disable some of the kernel memory mitigations. Causes boot crash/loops if Intel SGX is enforced and not set to "Application Controlled" or "Off" in your Firmware. Gamers don't use SGX under any possible circumstance.
bcdedit /set allowedinmemorysettings 0x0 | Out-Null
bcdedit /set isolatedcontext No | Out-Null
# Speed boot time a bit
bcdedit /set quietboot yes | Out-Null
bcdedit /timeout 0 | Out-Null # 3
bcdedit /set {globalsettings} custom:16000067 true | Out-Null
# Avoid the use of uncontiguous portions of low-memory from the OS. Boosts memory performance and improves microstuttering at least 80% of the cases. Also fixes the command buffer stutter after disabling 5-level paging on 10th gen Intel. Causes system freeze on unstable memory sticks.
bcdedit /set firstmegabytepolicy UseAll | Out-Null
bcdedit /set avoidlowmemory 0x8000000 | Out-Null
bcdedit /set nolowmem Yes | Out-Null
# Enable X2Apic and enable Memory Mapping for PCI-E devices.
bcdedit /set x2apicpolicy Enable | Out-Null
bcdedit /set configaccesspolicy Default | Out-Null
bcdedit /set usefirmwarepcisettings No | Out-Null
# Disable Early Launch Anti-Malware Protection
bcdedit /set disableelamdrivers Yes | Out-Null
# forces Windows to use logical destination mode for interrupts	
bcdedit /set usephysicaldestination No | Out-Null
# disable legacy APIC
bcdedit /set uselegacyapicmode no | Out-Null 

# NETWORK
# Gaming OS Tweaker - network [ VERY SLOW ]
Get-FileFromWeb "https://github.com/sherifmagdy32/gaming_os_tweaker/raw/refs/heads/main/scripts/tweaks/network.cmd" "$env:TEMP\network.cmd"
& "$env:TEMP\network.cmd"
# HakanFly - WINDOWS-NETWORK-OPTIMIZATIONS
Invoke-RestMethod "https://github.com/HakanFly/WINDOWS-NETWORK-OPTIMIZATIONS/raw/refs/heads/main/W10ANDW11-NETWORK-TCP-DESUBOPTIMIZATION.ps1" | Invoke-Expression *> $null
# set dns to google public dns
$adapters = Get-NetAdapter -Physical | Where-Object Status -eq "Up"
foreach ($a in $adapters) {Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses "8.8.8.8","8.8.4.4" -ErrorAction SilentlyContinue *> $null}

# PERSONALIZATION
# Download blanc.ico into C:\Windows
Get-FileFromWeb "https://github.com/benzaria/remove_shortcut_arrow/raw/refs/heads/main/blanc.ico" "C:\\Windows\\blanc.ico"
# Remove shortcut arrow overlay icon
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Force | Out-Null}
# Set the shortcut arrow overlay to a blank icon
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -PropertyType String -Value "C:\Windows\blanc.ico" -Force | Out-Null

				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				exit

			}
			2 {

				Clear-Host
				Write-Host "Registry: Default . . ."
				# create reg file
				$MultilineComment = @"
Windows Registry Editor Version 5.00

; --LEGACY CONTROL PANEL--




; EASE OF ACCESS
; narrator
[HKEY_CURRENT_USER\Software\Microsoft\Narrator\NoRoam]
"DuckAudio"=-
"WinEnterLaunchEnabled"=-
"ScriptingEnabled"=-
"OnlineServicesEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Narrator]
"NarratorCursorHighlight"=-
"CoupleNarratorCursorKeyboard"=-

; ease of access settings
[-HKEY_CURRENT_USER\Software\Microsoft\Ease of Access]

[HKEY_CURRENT_USER\Control Panel\Accessibility]
"Sound on Activation"=-
"Warning Sounds"=-

[HKEY_CURRENT_USER\Control Panel\Accessibility\HighContrast]
"Flags"="126"

[HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response]
"Flags"="126"
"AutoRepeatRate"="500"
"AutoRepeatDelay"="1000"

[HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys]
"Flags"="62"
"MaximumSpeed"="80"
"TimeToMaximumSpeed"="3000"

[HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys]
"Flags"="510"

[HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys]
"Flags"="62"

[HKEY_CURRENT_USER\Control Panel\Accessibility\SoundSentry]
"Flags"="2"
"FSTextEffect"="0"
"TextEffect"="0"
"WindowsEffect"="1"

[HKEY_CURRENT_USER\Control Panel\Accessibility\SlateLaunch]
"ATapp"="narrator"
"LaunchAT"=dword:00000001




; CLOCK AND REGION
; notify me when the clock changes
[-HKEY_CURRENT_USER\Control Panel\TimeDate]




; APPEARANCE AND PERSONALIZATION
; spotlight
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableCloudOptimizedContent"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableWindowsSpotlightFeatures"=dword:00000000
"DisableWindowsSpotlightWindowsWelcomeExperience"=dword:00000000
"DisableWindowsSpotlightOnActionCenter"=dword:00000000
"DisableWindowsSpotlightOnSettings"=dword:00000000
"DisableThirdPartySuggestions"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel]
"{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"=dword:00000000

; open file explorer to this quick access
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"LaunchTo"=-

; frequent folders in quick access
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"ShowFrequent"=-

; file name extensions
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"HideFileExt"=dword:00000001

; search history
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsDeviceSearchHistoryEnabled"=-

; show files from office.com
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"ShowCloudFilesInQuickAccess"=-

; display file size information in folder tips
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"FolderContentsInfoTip"=-

; display full path in the title bar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState]
"FullPath"=dword:00000000

; show pop-up description for folder and desktop items
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowInfoTip"=dword:00000001

; show preview handlers in preview pane
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowPreviewHandlers"=-

; show status bar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowStatusBar"=dword:00000001

; show sync provider notifications
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowSyncProviderNotifications"=-

; use sharing wizard
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"SharingWizardOn"=-

; show network
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}]




; HARDWARE AND SOUND
; lock
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]

; sleep
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]

; sound communications
[HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio]
"UserDuckingPreference"=-

; startup sound
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation]
"DisableStartupSound"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\EditionOverrides]
"UserSetting_DisableStartupSound"=dword:00000000

; sound scheme
[HKEY_CURRENT_USER\AppEvents\Schemes]
@=".Default"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\.Default\.Current]
@="C:\\Windows\\media\\Windows Background.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current]
@="C:\\Windows\\media\\Windows Foreground.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current]
@="C:\\Windows\\media\\Windows Hardware Insert.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current]
@="C:\\Windows\\media\\Windows Hardware Remove.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current]
@="C:\\Windows\\media\\Windows Hardware Fail.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current]
@="C:\\Windows\\media\\Windows Notify Email.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current]
@="C:\\Windows\\media\\Windows Background.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\MailBeep\.Current]
@="C:\\Windows\\media\\Windows Notify Email.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current]
@="C:\\Windows\\media\\Windows Message Nudge.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current]
@="C:\\Windows\\media\\Windows Notify System Generic.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current]
@="C:\\Windows\\media\\Windows Notify Messaging.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current]
@="C:\\Windows\\media\\Windows Notify Email.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current]
@="C:\\Windows\\media\\Windows Proximity Notification.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current]
@="C:\\Windows\\media\\Windows Notify Calendar.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current]
@="C:\\Windows\\media\\Windows Notify Messaging.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current]
@="C:\\Windows\\media\\Windows Proximity Connection.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current]
@="C:\\Windows\\media\\Windows Background.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current]
@="C:\\Windows\\media\\Windows Background.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemHand\.Current]
@="C:\\Windows\\media\\Windows Foreground.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current]
@="C:\\Windows\\media\\Windows Background.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current]
@="C:\\Windows\\media\\Windows User Account Control.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current]
@="C:\\Windows\\media\\Speech Disambiguation.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current]
@="C:\\Windows\\media\\Speech Off.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current]
@="C:\\Windows\\media\\Speech On.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current]
@="C:\\Windows\\media\\Speech Sleep.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current]
@="C:\\Windows\\media\\Speech Misrecognition.wav"

[HKEY_CURRENT_USER\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current]
@="C:\\Windows\\media\\Speech Disambiguation.wav"

; autoplay
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]
"DisableAutoplay"=dword:00000000

; enhance pointer precision
[HKEY_CURRENT_USER\Control Panel\Mouse]
"MouseSpeed"="1"
"MouseThreshold1"="6"
"MouseThreshold2"="10"

; mouse pointers scheme
[HKEY_CURRENT_USER\Control Panel\Cursors]
"AppStarting"="C:\\Windows\\cursors\\aero_working.ani"
"Arrow"="C:\\Windows\\cursors\\aero_arrow.cur"
"ContactVisualization"=dword:00000001
"Crosshair"=""
"CursorBaseSize"=dword:00000020
"GestureVisualization"=dword:0000001f
"Hand"="C:\\Windows\\cursors\\aero_link.cur"
"Help"="C:\\Windows\\cursors\\aero_helpsel.cur"
"IBeam"=""
"No"="C:\\Windows\\cursors\\aero_unavail.cur"
"NWPen"="C:\\Windows\\cursors\\aero_pen.cur"
"Scheme Source"=dword:00000002
"SizeAll"="C:\\Windows\\cursors\\aero_move.cur"
"SizeNESW"="C:\\Windows\\cursors\\aero_nesw.cur"
"SizeNS"="C:\\Windows\\cursors\\aero_ns.cur"
"SizeNWSE"="C:\\Windows\\cursors\\aero_nwse.cur"
"SizeWE"="C:\\Windows\\cursors\\aero_ew.cur"
"UpArrow"="C:\\Windows\\cursors\\aero_up.cur"
"Wait"="C:\\Windows\\cursors\\aero_busy.ani"
@="Windows Default"

; device installation settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata]
"PreventDeviceMetadataFromNetwork"=dword:00000000




; NETWORK AND INTERNET
; allow other network users to control or disable the shared internet connection
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Network\SharedAccessConnection]
"EnableControl"=dword:00000001




; SYSTEM AND SECURITY
; undo prefer IPv4 over IPv6
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters]
"DisabledComponents"=00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"EnablePMTUDiscovery"=-
"EnablePMTUBHDetect"=-
"Tcp1323Opts"=-
"SackOpts"=-
"DefaultTTL"=-
"GlobalMaxTcpWindowSize"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters]
"MaxCacheEntryTtlLimit"=-
"MaxNegativeCacheTtl"=-

; set appearance options
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=-

; animate controls and elements inside windows
; fade or slide menus into view
; fade or slide tooltips into view
; fade out menu items after clicking
; show shadows under mouse pointer
; show shadows under windows
; slide open combo boxes
; smooth-scroll list boxes
[HKEY_CURRENT_USER\Control Panel\Desktop]
"UserPreferencesMask"=hex(2):9e,1e,07,80,12,00,00,00

; animate windows when minimizing and maximizing
[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]
"MinAnimate"="1"

; animations in the taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarAnimations"=dword:1

; enable peek
[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"EnableAeroPeek"=dword:1

; save taskbar thumbnail previews
[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"AlwaysHibernateThumbnails"=dword:0

; disable show thumbnails instead of icons
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"IconsOnly"=dword:0

; show translucent selection rectangle
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ListviewAlphaSelect"=dword:1

; show window contents while dragging
[HKEY_CURRENT_USER\Control Panel\Desktop]
"DragFullWindows"="1"

; smooth edges of screen fonts
[HKEY_CURRENT_USER\Control Panel\Desktop]
"FontSmoothing"="2"

; use drop shadows for icon labels on the desktop
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ListviewShadow"=dword:1

; adjust for best performance of
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000002

; remote assistance
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance]
"fAllowToGetHelp"=dword:00000001

; system responsiveness
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:0000000a
"SystemResponsiveness"=dword:00000014

; cpu priority
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager]

; virtual memory
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"ClearPageFileAtShutdown"=dword:00000000
"DisablePagingExecutive"=dword:00000000
"HotPatchTableSize"=dword:00001000
"LargeSystemCache"=dword:00000000
"NonPagedPoolQuota"=dword:00000000
"NonPagedPoolSize"=dword:00000000
"PagedPoolQuota"=dword:00000000
"PagedPoolSize"=dword:00000000
"SecondLevelDataCache"=dword:00000000
"SessionPoolSize"=dword:00000004
"SessionViewSize"=dword:00000030
"SystemPages"=dword:00000000
"PagingFiles"=hex(7):63,00,3a,00,5c,00,70,00,61,00,67,00,65,00,66,00,69,00,6c,\
  00,65,00,2e,00,73,00,79,00,73,00,20,00,30,00,20,00,30,00,00,00,00,00
"PagefileUsage"=hex:04,00,00,00,4e,a5,02,00,cf,8f,00,00,b3,72,00,00,1b,74,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"PhysicalAddressExtension"=dword:00000001
"FeatureSettings"=dword:00000000
"FeatureSettingsOverrideMask"=-
"FeatureSettingsOverride"=-
"ExistingPageFiles"=hex(7):5c,00,3f,00,3f,00,5c,00,43,00,3a,00,5c,00,70,00,61,\
  00,67,00,65,00,66,00,69,00,6c,00,65,00,2e,00,73,00,79,00,73,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000003
"EnableSuperfetch"=dword:00000003
"EnableBootTrace"=dword:00000001
"BootId"=-
"BaseTime"=-
"SfTracingState"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\StoreParameters]




; ENABLE WINDOWS SECURITY SETTINGS
; cloud delivered protection
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet]
"SpyNetReporting"=dword:00000002

; automatic sample submission
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet]
"SubmitSamplesConsent"=dword:00000001

; firewall notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection]
"NoActionNotificationDisabled"=dword:00000000
"SummaryNotificationDisabled"=dword:00000000
"FilesBlockedNotificationDisabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender Security Center\Account protection]
"DisableNotifications"=dword:00000000
"DisableDynamiclockNotifications"=dword:00000000
"DisableWindowsHelloNotifications"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Epoch]
"Epoch"=dword:000004cc

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"DisableNotifications"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"DisableNotifications"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"DisableNotifications"=dword:00000000

; exploit protection
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Session Manager\kernel]
"MitigationOptions"=hex(3):11,11,11,00,00,01,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00

; core isolation 
; memory integrity 
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"ChangedInBootCycle"=-
"Enabled"=dword:00000001
"WasEnabledBy"=dword:00000002

; device guard
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000001
"HypervisorEnforcedCodeIntegrity"=dword:00000001
"HVCIMATRequired"=dword:00000001
"LsaCfgFlags"=dword:00000001
"ConfigureSystemGuardLaunch"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000001
"HypervisorEnforcedCodeIntegrity"=dword:00000001
"HVCIMATRequired"=dword:00000001
"LsaCfgFlags"=dword:00000001
"ConfigureSystemGuardLaunch"=dword:00000001

; enable local security authority protection
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RunAsPPL"=dword:00000001
"RunAsPPLBoot"=dword:00000001

; enable microsoft vulnerable driver blocklist
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\CI\Config]
"VulnerableDriverBlocklistEnable"=dword:00000001

; enable Bitlocker
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BitLocker]
"PreventDeviceEncryption"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE]
"DisableExternalDMAUnderLock"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices]
"TCGSecurityActivationDisabled"=dword:00000000

; kernel-mode hardware-enforced stack protection
[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks]
"ChangedInBootCycle"=-
"Enabled"=dword:00000001
"WasEnabledBy"=dword:00000002

; spectre and meltdown
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management]
"FeatureSettingsOverrideMask"=-
"FeatureSettingsOverride"=-

; other mitigations
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsMitigation]
"UserPreference"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SCMConfig]
"EnableSvchostMitigationPolicy"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"MitigationAuditOptions"=-
"MitigationOptions"=-
"KernelSEHOPEnabled"=-

[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks]
"ChangedInBootCycle"=-
"Enabled"=-
"WasEnabledBy"=-

; enable uac
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000001

; enable smartscreen
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"SmartScreenEnabled"="Warn"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=-

; turn on smartscreen in edge
[HKEY_CURRENT_USER\Software\Microsoft\Edge\SmartScreenEnabled]
"(Default)"="1"

; enable smartscreen for store apps
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppHost]
"EnableWebContentEvaluation"=dword:00000001
"PreventOverride"=dword:00000001

; show family options settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options]
"UILockdown"=-

; show account protection settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection]
"UILockdown"=-

; show device security settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security]
"UILockdown"=-

; enable fth
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTH]
"Enabled"=dword:00000001




; TROUBLESHOOTING
; automatic maintenance
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance]
"MaintenanceDisabled"=-




; SECURITY AND MAINTENANCE
; report problems
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting]
"DoReport"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting]
"Disabled"=dword:00000000

; restore point creation frequency
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore]
"SystemRestorePointCreationFrequency"=-

; Restore Windows Defender CPU usage
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]




; --IMMERSIVE CONTROL PANEL--




; WINDOWS UPDATE
; automatic updates
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
"AUOptions"=-
"NoAutoUpdate"=-
"AutoInstallMinorUpdates"=-

; prevent automatic upgrade to windows 11 and defer updates
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"targetreleaseversion"=-
"targetreleaseversioninfo"=-
"productversion"=-
"deferfeatureupdates"=-
"deferfeatureupdatesperiodindays"=-
"deferqualityupdates"=-
"deferqualityupdatesperiodindays"=-

; block workplace join prompt
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin]
"blockaadworkplacejoin"=-

; turn on driver updates via win update
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update]
"ExcludeWUDriversInQualityUpdate"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Update]
"ExcludeWUDriversInQualityUpdate"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
"ExcludeWUDriversInQualityUpdate"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"ExcludeWUDriversInQualityUpdate"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate]
"value"=-

; delivery optimization
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization]
"DODownloadMode"=-

[HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings]
"DownloadMode"=-

;   @script       windows-updates-unpause.reg
;   @author       Aetherinox
;   @url          https://github.com/Aetherinox/pause-windows-updates
;
;   A script to re-activate Windows Updates.

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
"PauseFeatureUpdatesStartTime"=-
"PauseFeatureUpdatesEndTime"=-
"PauseQualityUpdatesStartTime"=-
"PauseQualityUpdatesEndTime"=-
"PauseUpdatesStartTime"=-
"PauseUpdatesExpiryTime"=-
"ActiveHoursStart"=dword:0000000d
"ActiveHoursEnd"=dword:00000007
"FlightSettingsMaxPauseDays"=dword:00002727

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc]
"Start"=dword:00000003
"FailureActions"=hex:84,03,00,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00

; driver searching & updates
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching]
"DontSearchWindowsUpdate"=dword:00000000
"SearchOrderConfig"=dword:00000001




; PRIVACY
; password reveal button
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI]
"DisablePasswordReveal"=dword:00000000

; show me notification in the settings app
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications]
"EnableAccountNotifications"=-

; location
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location]
"Value"="Allow"

; allow location override
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting]
"Value"=dword:00000001

; camera
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam]
"Value"="Allow"

; microphone 
[Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone]
"Value"="Allow"

; voice activation
[-HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings]

; notifications
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener]
"Value"="Allow"

; account info
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation]
"Value"="Allow"

; contacts
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts]
"Value"="Allow"

; calendar
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments]
"Value"="Allow"

; phone calls
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall]
"Value"="Allow"

; call history
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory]
"Value"="Allow"

; email
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email]
"Value"="Allow"

; tasks
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks]
"Value"="Allow"

; messaging
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat]
"Value"="Allow"

; radios
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios]
"Value"="Allow"

; other devices 
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync]

; app diagnostics 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics]
"Value"="Allow"

; documents
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary]
"Value"="Allow"

; downloads folder 
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder]

; music library
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary]
"Value"="Allow"

; pictures
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary]
"Value"="Deny"

; videos
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary]
"Value"="Allow"

; file system
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess]
"Value"="Allow"

; let websites show me locally relevant content by accessing my language list 
[HKEY_CURRENT_USER\Control Panel\International\User Profile]
"HttpAcceptLanguageOptOut"=-

; let windows improve start and search results by tracking app launches  
[-HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI]

; personal inking and typing dictionary
[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization]
"RestrictImplicitInkCollection"=dword:00000000
"RestrictImplicitTextCollection"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore]
"HarvestContacts"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings]
"AcceptedPrivacyPolicy"=dword:00000001

; sending required data
[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection]
"AllowTelemetry"=-

; feedback frequency
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf]

; store my activity history on this device 
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"PublishUserActivities"=-

; Re-enable NCSI Active Probing
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator]
"NoActiveProbe"=dword:00000000



; SEARCH
; search highlights
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsDynamicSearchBoxEnabled"=-

; safe search
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"SafeSearchMode"=-

; cloud content search for work or school account
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsAADCloudSearchEnabled"=-

; cloud content search for microsoft account
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsMSACloudSearchEnabled"=-




; EASE OF ACCESS
; magnifier settings 
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\ScreenMagnifier]
"FollowCaret"=-
"FollowNarrator"=-
"FollowMouse"=-
"FollowFocus"=-

; narrator settings
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator]
"IntonationPause"=-
"ReadHints"=-
"ErrorNotificationType"=-
"EchoChars"=-
"EchoWords"=-

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator\NarratorHome]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator\NoRoam]
"EchoToggleKeys"=-

; use the print screen key to open screeen capture
[HKEY_CURRENT_USER\Control Panel\Keyboard]
"PrintScreenKeyForSnippingEnabled"=-




; GAMING
; game bar
[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR]
"AppCaptureEnabled"=-

; enable open xbox game bar using game controller
[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"UseNexusForGameBarEnabled"=-

; game mode
[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"AutoGameModeEnabled"=00000000
"AllowAutoGameMode"=00000000

; other settings
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR]
"AudioEncodingBitrate"=-
"AudioCaptureEnabled"=-
"CustomVideoEncodingBitrate"=-
"CustomVideoEncodingHeight"=-
"CustomVideoEncodingWidth"=-
"HistoricalBufferLength"=-
"HistoricalBufferLengthUnit"=-
"HistoricalCaptureEnabled"=-
"HistoricalCaptureOnBatteryAllowed"=-
"HistoricalCaptureOnWirelessDisplayAllowed"=-
"MaximumRecordLength"=-
"VideoEncodingBitrateMode"=-
"VideoEncodingResolutionMode"=-
"VideoEncodingFrameRateMode"=-
"EchoCancellationEnabled"=-
"CursorCaptureEnabled"=-
"VKToggleGameBar"=-
"VKMToggleGameBar"=-
"VKSaveHistoricalVideo"=-
"VKMSaveHistoricalVideo"=-
"VKToggleRecording"=-
"VKMToggleRecording"=-
"VKTakeScreenshot"=-
"VKMTakeScreenshot"=-
"VKToggleRecordingIndicator"=-
"VKMToggleRecordingIndicator"=-
"VKToggleMicrophoneCapture"=-
"VKMToggleMicrophoneCapture"=-
"VKToggleCameraCapture"=-
"VKMToggleCameraCapture"=-
"VKToggleBroadcast"=-
"VKMToggleBroadcast"=-
"MicrophoneCaptureEnabled"=-
"SystemAudioGain"=-
"MicrophoneGain"=-




; TIME & LANGUAGE 
; show the voice typing mic button
[HKEY_CURRENT_USER\Software\Microsoft\input\Settings]
"IsVoiceTypingKeyEnabled"=-

; capitalize the first letter of each sentence
; play key sounds as i type
; add a period after i double-tap the spacebar
[HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7]
"EnableAutoShiftEngage"=-
"EnableKeyAudioFeedback"=-
"EnableDoubleTapSpace"=-

; typing insights 
[HKEY_CURRENT_USER\Software\Microsoft\input\Settings]
"InsightsEnabled"=-




; ACCOUNTS
; use my sign in info after restart
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableAutomaticRestartSignOn"=-




; APPS
; automatically update maps
[HKEY_LOCAL_MACHINE\SYSTEM\Maps]
"AutoUpdateEnabled"=-

; archive apps
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Appx]
"AllowAutomaticAppArchiving"=-

; turn on resume
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration]
"IsResumeAllowed"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume]  
"DisableCrossDeviceResume"=dword:00000000

; sync apps
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowSyncMySettings]
"value"=dword:00000001




; PERSONALIZATION
show all taskbar icons
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=dword:00000000

; picture personalize your background
[HKEY_CURRENT_USER\Control Panel\Desktop]
"WallPaper"="C:\\Windows\\web\\wallpaper\\Windows\\img0.jpg"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers]
"BackgroundHistoryPath0"="C:\\Windows\\web\\wallpaper\\Windows\\img0.jpg"
"CurrentWallpaperPath"="C:\\Windows\\web\\wallpaper\\Windows\\img0.jpg"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers]
"BackgroundType"=dword:00000000

; light theme 
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"AppsUseLightTheme"=dword:00000001
"SystemUsesLightTheme"=dword:00000001

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent]
"AccentPalette"=hex:99,eb,ff,00,4c,c2,ff,00,00,91,f8,00,00,78,d4,00,00,67,c0,\
  00,00,3e,92,00,00,1a,68,00,f7,63,0c,00
"StartColorMenu"=dword:ffc06700
"AccentColorMenu"=dword:ffd47800

[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"EnableWindowColorization"=dword:00000000
"AccentColor"=dword:ffd47800
"ColorizationColor"=dword:c40078d4
"ColorizationAfterglow"=dword:c40078d4

; transparency
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"EnableTransparency"=dword:00000001

; don't hide most used list in start menu
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]

[-HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer]

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]

; revert start menu hide recommended w11
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Start]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Education]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"HideRecommendedSection"=-

; default pins personalization start
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_Layout"=-

; show recently added apps
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]

; show account-related notifications
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_AccountNotifications"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"HideRecentlyAddedApps"=-

; show recently opened items in start, jump lists and file explorer
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_TrackDocs"=-

; normal taskbar alignment
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarAl"=-

; chat from taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarMn"=-

; task view from taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowTaskViewButton"=-

; search from taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search]
"SearchboxTaskbarMode"=-

; windows widgets from taskbar
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds]
"ShellFeedsTaskbarOpenOnHover"=dword:00000001

; copilot from taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowCopilotButton"=-

; meet now
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]

; action center
[-HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer]

; news and interests
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds]

; don't show all taskbar icons
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=-

; security taskbar icon
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run]
"SecurityHealth"=hex:04,00,00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"SecurityHealth"=hex(2):25,00,77,00,69,00,6e,00,64,00,69,00,72,00,25,00,5c,00,\
  73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,00,65,00,63,00,75,\
  00,72,00,69,00,74,00,79,00,48,00,65,00,61,00,6c,00,74,00,68,00,53,00,79,00,\
  73,00,74,00,72,00,61,00,79,00,2e,00,65,00,78,00,65,00,00,00

; use dynamic lighting on my devices
[HKEY_CURRENT_USER\Software\Microsoft\Lighting]
"AmbientLightingEnabled"=dword:00000001

; compatible apps in the forground always control lighting 
[HKEY_CURRENT_USER\Software\Microsoft\Lighting]
"ControlledByForegroundApp"=-

; match my windows accent color 
[HKEY_CURRENT_USER\Software\Microsoft\Lighting]
"UseSystemAccentColor"=dword:00000001

; show key background
[HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7]
"IsKeyBackgroundEnabled"=-

; show recommendations for tips shortcuts new apps and more
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_IrisRecommendations"=-

; share any window from my taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarSn"=-

; online tips
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"AllowOnlineTips"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"AllowOnlineTips"=dword:00000001

; enable EdgeUI help stickers
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\EdgeUI]
"DisableHelpSticker"=dword:00000000

; device install balloon tips
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings]
"DisableBalloonTips"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceInstall\Settings]
"DisableBalloonTips"=dword:00000000




; DEVICES
; usb issues notify
[-HKEY_CURRENT_USER\Software\Microsoft\Shell]

; let windows manage my default printer
[HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows]
"LegacyDefaultPrinterMode"=dword:ffffffff

; write with your fingertip
[-HKEY_CURRENT_USER\Software\Microsoft\TabletTip\EmbeddedInkControl]




; SYSTEM
; dpi scaling
[HKEY_CURRENT_USER\Control Panel\Desktop]
"LogPixels"=-
"Win8DpiScaling"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\DWM]
"UseDpiScaling"=-

; fix scaling for apps
[HKEY_CURRENT_USER\Control Panel\Desktop]
"EnablePerProcessSystemDPI"=-

; hardware accelerated gpu scheduling
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"HwSchMode"=-

; variable refresh rate & optimizations for windowed games
[HKEY_CURRENT_USER\Software\Microsoft\DirectX\UserGpuPreferences]
"DirectXUserGlobalSettings"=-

; notifications
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications]
"ToastEnabled"=-

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel]
"Enabled"=-

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.CapabilityAccess]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo]
"DisabledByGroupPolicy"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"RotatingLockScreenEnabled"=dword:00000001
"RotatingLockScreenOverlayEnabled"=dword:00000001
"SubscribedContent-338389Enabled"=dword:00000001

[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement]

; suggested actions
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard]
"Disabled"=-

; focus assist
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\??windows.data.notifications.quiethourssettings\Current]
"Data"=hex:02,00,00,00,74,a9,70,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,d2,14,28,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,2e,00,51,\
  00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,00,6f,00,\
  66,00,69,00,6c,00,65,00,2e,00,55,00,6e,00,72,00,65,00,73,00,74,00,72,00,69,\
  00,63,00,74,00,65,00,64,00,ca,28,00,00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentfullscreen?windows.data.notifications.quietmoment\Current]
"Data"=hex:02,00,00,00,82,a3,71,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,c2,14,01,d2,1e,26,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  2e,00,51,00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,\
  00,6f,00,66,00,69,00,6c,00,65,00,2e,00,41,00,6c,00,61,00,72,00,6d,00,73,00,\
  4f,00,6e,00,6c,00,79,00,ca,50,00,00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentgame?windows.data.notifications.quietmoment\Current]
"Data"=hex:02,00,00,00,a5,c1,71,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,c2,14,01,d2,1e,28,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  2e,00,51,00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,\
  00,6f,00,66,00,69,00,6c,00,65,00,2e,00,50,00,72,00,69,00,6f,00,72,00,69,00,\
  74,00,79,00,4f,00,6e,00,6c,00,79,00,ca,50,00,00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpostoobe?windows.data.notifications.quietmoment\Current]
"Data"=hex:02,00,00,00,85,de,71,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,c2,14,01,d2,1e,28,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  2e,00,51,00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,\
  00,6f,00,66,00,69,00,6c,00,65,00,2e,00,50,00,72,00,69,00,6f,00,72,00,69,00,\
  74,00,79,00,4f,00,6e,00,6c,00,79,00,ca,50,00,00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpresentation?windows.data.notifications.quietmoment\Current]
"Data"=hex:02,00,00,00,a4,fa,71,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,c2,14,01,d2,1e,26,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  2e,00,51,00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,\
  00,6f,00,66,00,69,00,6c,00,65,00,2e,00,41,00,6c,00,61,00,72,00,6d,00,73,00,\
  4f,00,6e,00,6c,00,79,00,ca,50,00,00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentscheduled?windows.data.notifications.quietmoment\Current]
"Data"=hex:02,00,00,00,fe,17,72,73,03,82,da,01,00,00,00,00,43,42,01,00,c2,0a,\
  01,d2,1e,28,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,2e,00,51,\
  00,75,00,69,00,65,00,74,00,48,00,6f,00,75,00,72,00,73,00,50,00,72,00,6f,00,\
  66,00,69,00,6c,00,65,00,2e,00,50,00,72,00,69,00,6f,00,72,00,69,00,74,00,79,\
  00,4f,00,6e,00,6c,00,79,00,d1,32,80,e0,aa,8a,99,30,d1,3c,80,e0,f6,c5,d5,0e,\
  ca,50,00,00

; battery options optimize
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\VideoSettings]

; storage sense
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense]

; snap window settings
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"SnapAssist"=-
"DITest"=-
"EnableSnapBar"=-
"EnableTaskGroups"=-
"EnableSnapAssistFlyout"=-
"SnapFill"=-
"JointResize"=-

; alt tab open
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"MultiTaskingAltTabFilter"=-

; share across devices
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP]
"RomeSdkChannelUserAuthzPolicy"=dword:00000001
"CdpSessionUserAuthzPolicy"=-

; enable clipboard
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"AllowCrossDeviceClipboard"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\System]
"AllowCrossDeviceClipboard"=dword:00000001

; enable clipboard history
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\System]
"AllowClipboardHistory"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"AllowClipboardHistory"=dword:00000001




; --OTHER--




; STORE
; update apps automatically
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore]




; EDGE
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]

[-HKEY_CURRENT_USER\Software\Policies\Microsoft\EdgeUpdate]

; Restore Edge as default PDF viewer - Remove custom association
[-HKEY_CLASSES_ROOT\.pdf]

; Remove the OpenWithProgids removal for Edge PDF handler (restores Edge as an option)
[HKEY_CLASSES_ROOT\.pdf\OpenWithProgids]
"AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723"=dword:00000000




; CHROME
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem]
"Start"=dword:00000002




; BRAVE
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineCore]

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineUA]




;FIREFOX
[-HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox]




; NVIDIA
; nvidia tray icon
[-HKEY_CURRENT_USER\Software\NVIDIA Corporation\NvTray]




; --CAN'T DO NATIVELY--




; UWP APPS
; background apps
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsRunInBackground"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications]
"GlobalUserDisabled"=dword:00000000

; disable windows input experience preload
[HKEY_CURRENT_USER\Software\Microsoft\input]
"IsInputAppPreloadEnabled"=-

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Dsh]

; web search in start menu 
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer]
"DisableSearchBoxSuggestions"=-

; copilot
[-HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot]

; cortana
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search]
"AllowCortana"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Experience]
"AllowCortana"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]
"AllowCortanaAboveLock"=dword:00000001

; widgets
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests]
"value"=dword:00000001

; enable ink workspace
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace]
"AllowWindowsInkWorkspace"=dword:00000001

; enable telemetry
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection]
"AllowTelemetry"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics]
"EnabledExecution"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection]
"LimitDiagnosticLogCollection"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000001

; enable activity history
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableActivityFeed"=dword:00000001
"PublishUserActivities"=dword:00000001
"UploadUserActivities"=dword:00000001

; enable location
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors]
"DisableLocation"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors]
"DisableLocationScripting"=dword:00000000
"DisableWindowsLocationProvider"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\System]
"AllowExperimentation"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}]
"SensorPermissionState"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration]
"Status"=dword:00000001

; allow double-click of .ps1 files
[HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\Open\Command]
@="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -ExecutionPolicy Unrestricted -File \"%1\""




; NVIDIA
; disable old nvidia legacy sharpening
; old location
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS]
"EnableGR535"=dword:00000001

; new location
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters\FTS]
"EnableGR535"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\FTS]
"EnableGR535"=dword:00000001




; POWER
; park cpu cores 
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000064
"ValueMin"=-

; remove maximum processor frequency
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100]
"Attributes"=dword:00000001

; power throttling
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling]

; hibernate
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"HibernateEnabled"=-
"HibernateEnabledDefault"=dword:00000001

; fast boot
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"HiberbootEnabled"=dword:00000001

; energy estimation & power saving
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"EnergyEstimationEnabled"=dword:00000001
"EnergySaverPolicy"=dword:00000000

; connected standby
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"CsEnabled"=dword:00000001

; timer coalescing
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"CoalescingTimerInterval"=dword:00000001

; away mode
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"AwayModeEnabled"=dword:00000001




; ADVERTISING & PROMOTIONAL
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"ContentDeliveryAllowed"=dword:00000001
"FeatureManagementEnabled"=dword:00000001
"OemPreInstalledAppsEnabled"=dword:00000001
"PreInstalledAppsEnabled"=dword:00000001
"PreInstalledAppsEverEnabled"=dword:00000001
"RotatingLockScreenEnabled"=dword:00000001
"RotatingLockScreenOverlayEnabled"=dword:00000001
"SilentInstalledAppsEnabled"=dword:00000001
"SlideshowEnabled"=dword:00000001
"SoftLandingEnabled"=dword:00000001
"SubscribedContent-310093Enabled"=-
"SubscribedContent-314563Enabled"=-
"SubscribedContent-338388Enabled"=-
"SubscribedContent-338389Enabled"=-
"SubscribedContent-338389Enabled"=-
"SubscribedContent-338393Enabled"=-
"SubscribedContent-338393Enabled"=-
"SubscribedContent-353694Enabled"=-
"SubscribedContent-353694Enabled"=-
"SubscribedContent-353696Enabled"=-
"SubscribedContent-353696Enabled"=-
"SubscribedContent-353698Enabled"=-
"SubscribedContentEnabled"=dword:00000001
"SystemPaneSuggestionsEnabled"=dword:00000001




; OTHER
; 3d objects
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}]

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}]

; quick access
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"HubMode"=-

; home
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}]
@="CLSID_MSGraphHomeFolder"

; gallery
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}]

; context menu
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}]

; remove "Kill Not Responding Tasks" to desktop context menu
[-HKEY_CLASSES_ROOT\DesktopBackground\Shell\KillNRTasks]

; remove Run with priority context menu
[-HKEY_CLASSES_ROOT\exefile\Shell\RunWithPriority]

; remove Switch Power Plan context menu to desktop
[-HKEY_CLASSES_ROOT\DesktopBackground\Shell\PowerPlan_WAT]

; remove "Take Ownership" context menu to files and folders
[-HKEY_CLASSES_ROOT\*\shell\TakeOwnership]

; remove delete temp files
[-HKEY_CLASSES_ROOT\DesktopBackground\Shell\TempClean]

; menu show delay
[HKEY_CURRENT_USER\Control Panel\Desktop]
"MenuShowDelay"="400"

; mouse (default accel with epp on)
[HKEY_CURRENT_USER\Control Panel\Mouse]
"MouseSensitivity"="10"
"SmoothMouseXCurve"=hex:00,00,00,00,00,00,00,00,15,6e,00,00,00,00,00,00,00,40,\
  01,00,00,00,00,00,29,dc,03,00,00,00,00,00,00,00,28,00,00,00,00,00
"SmoothMouseYCurve"=hex:00,00,00,00,00,00,00,00,fd,11,01,00,00,00,00,00,00,24,\
  04,00,00,00,00,00,00,fc,12,00,00,00,00,00,00,c0,bb,01,00,00,00,00

[HKEY_USERS\.DEFAULT\Control Panel\Mouse]
"MouseSpeed"="1"
"MouseThreshold1"="6"
"MouseThreshold2"="10"

; disable endtask menu taskbar w11
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings]
"TaskbarEndTask"=dword:00000000

; disable win32 long paths
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem]
"LongPathsEnabled"=dword:00000001

; add 'Open in Windows Terminal' in win 11
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked]
"{9F156763-7844-4DC4-B2B1-901F640F5155}"=-

; share context menu
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked]
"{e2bf9676-5f8f-435c-97eb-11607a5bedf7}"=-

; add to favourites context menu
[-HKEY_CLASSES_ROOT\*\shell\pintohomefile]

[HKEY_CLASSES_ROOT\*\shell\pintohomefile]
"CommandStateHandler"="{b455f46e-e4af-4035-b0a4-cf18d2f6f28e}"
"CommandStateSync"=""
"MUIVerb"="@shell32.dll,-51389"
"NeverDefault"=""
"SkipCloudDownload"=dword:00000000

[HKEY_CLASSES_ROOT\*\shell\pintohomefile\command]
"DelegateExecute"="{b455f46e-e4af-4035-b0a4-cf18d2f6f28e}"

; show insider program page
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility]
"HideInsiderPage"=-

; shortcut overlay icon 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons]
"29"=-

; enable the " - shortcut" text for shortcuts
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates]
"ShortcutNameTemplate"=-

; undo "Do this for all current items" checked by default
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager]
"ConfirmationCheckBoxDoForAll"=dword:00000000

; Enable automatic folder type discovery
[HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags]

[-HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell]

; Disable Network Drives over UAC
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLinkedConnections"=dword:00000000
"LocalAccountTokenFilterPolicy"=dword:00000000
"EnableVirtualization"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"DisableLoopbackCheck"=dword:00000000

; onedrive user folder backup
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive]
"KFMBlockOptIn"=-

; restore onedrive folder visibility
[HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:1

[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:1

; onedrive startup
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"OneDrive"="\"C:\\Users\\Admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"

; lock screen
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData]
"AllowLockScreen"=-

; enable automatic registry backup
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager]
"EnablePeriodicBackup"=dword:00000001

; enable "Look for an app in the Store" notification
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"NoUseStoreOpenWith"=-

; enable download restrictions in file explorer
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments]
"SaveZoneInformation"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments]
"SaveZoneInformation"=-

; enable mark-of-the-web (MOTW) for downloaded files
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AttachmentManager]
"ScanWithAntiVirus"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Associations]
"LowRiskFileTypes"=-

; protected view for office files
[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security\ProtectedView]
"DisableInternetFilesInPV"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView]
"DisableInternetFilesInPV"=dword:00000000

; undo disable malicious software removal tool from installing
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT]
"DontOfferThroughWUAU"=-

; live tiles
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications]
"NoTileApplicationNotification"=dword:00000000

; default wallpaper quallity
[HKEY_CURRENT_USER\Control Panel\Desktop]
"JPEGImportQuality"=dword:00000055

; disable windows installer in safe mode
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer]

; default timeout for disk auto check
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"AutoChkTimeout"=dword:00000008

; enable blur on sign-in screen
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"DisableAcrylicBackgroundOnLogon"=dword:00000000

; deactivate photo viewer
[HKEY_CLASSES_ROOT\jpegfile\shell\open\DropTarget]
"Clsid"=-

[HKEY_CLASSES_ROOT\pngfile\shell\open\DropTarget]
"Clsid"=-

[-HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Bitmap]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Gif]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Png]

[-HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp]



[HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.ico]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.gif]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.png]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tif]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff]
@=-

[HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp]
@=-


[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids]
"PhotoViewer.FileAssoc.Tiff"=-

[-HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\Image Preview]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities]
"ApplicationDescription"="@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3069"
"ApplicationName"="@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3009"

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations]
".tif"="PhotoViewer.FileAssoc.Tiff"
".tiff"="PhotoViewer.FileAssoc.Tiff"

; enable settings home
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"=-

; enable consumer features
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableSoftLanding"=dword:00000000
"DisableConsumerFeatures"=dword:00000000
"DisableWindowsConsumerFeatures"=dword:00000000
"DisableConsumerAccountStateContent"=dword:00000000

; enable homegroup
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupListener]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupProvider ]
"Start"=dword:00000003

; enable wifi-sense
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"AllowWiFiHotSpotReporting"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting]
"Value"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots]
"Value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config]
"AutoConnectAllowedOEM"=dword:00000001

; enable ai features
[-HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI]

; enable NumLock on startup
[HKEY_USERS\.DEFAULT\Control Panel\Keyboard]
"InitialKeyboardIndicators"=dword:"2"

; Disable Verbose Messages During Logon
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"VerboseStatus"=dword:00000000

; enable thumbnail cache
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"DisableThumbnailCache"=dword:00000001

; wait apps to close on shutdown
[HKEY_CURRENT_USER\Control Panel\Desktop]
"autoendtasks"="0"
"hungapptimeout"="5000"
"waittokillapptimeout"="20000"
"lowlevelhookstimeout"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control]
"waittokillservicetimeout"="5000"

; audiodg priority
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions]
"CpuPriorityClass"=-
"IoPriority"=-

; mouse cursor dissapeiring
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableCursorSuppression"=-

; tablet mode
; [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell]
; "TabletMode"=dword:-
; "SignInMode"=dword:-

; push to install feature
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall]
"DisablePushToInstall"=dword:00000000




; FOX OS
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival]
@=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival]
@=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival]
@=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival]
@=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"winstationsdisabled"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"disabledomaincreds"=-
"restrictanonymous"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing]
"enablelog"=-
"enabledpxlog"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Component Based Servicing]
"enablelog"=-
"enabledpxlog"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole]
"enabledcom"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Ole]
"enabledcom"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy]
"value"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\pci\Parameters]
"dmaremappingcompatible"=-
"dmaremappingonhiberpath"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\storahci\Parameters]
"dmaremappingcompatible"=-
"dmaremappingonhiberpath"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\stornvme\Parameters]
"dmaremappingcompatible"=-
"dmaremappingonhiberpath"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\USBXHCI\Parameters]
"dmaremappingcompatibleselfhost"=-
"dmaremappingcompatible"=-

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers]
"adobe type manager"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\Wds\rdpwd]
"startupprograms"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Beep]
"start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\GpuEnergyDrv]
"start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\npsvctrig]
"start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wanarp]
"start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wanarpv6]
"start"=-

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\Win32knsWPP\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Win32knsWPP\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\USBHUB3\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\USBHUB3\Parameters\Wdf]
"logpages"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid\Parameters]
"logpages"=-

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule]
"disablerpcovertcp"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"restrictanonymoussam"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control]
"disableremotescmendpoints"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services]
"fdisablecdm"=-
"fallowtogethelp"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server]
"tsenabled"=-




; KHORVIE TECH
; tcpip tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"tcptimedwaitdelay"=dword:000000f0
"tcp1323opts"=-
"tcpmaxconnectretransmissions"=dword:00000002
"delayedackfrequency"=-
"delayedackticks"=-
"multihopsets"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"irpstacksize"=-
"sizreqbuf"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\QoS]
"do not use nla"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters]
"negativecachetime"=dword:0000012c
"negativesoacachetime"=-
"netfailurecachetime"=-
"enableautodoh"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters]
"nonblockingsendspecialbuffering"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]
"tcpnodelay"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched]
"nonbesteffortlimit"=-

; dwm schedule master values
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM\Schedule]
"windowedgsyncgeforceflag"=-
"frameratemin"=-
"ignoredisplaychangeduration"=-
"lingerinterval"=-
"licenseinterval"=-
"restrictednvcpluimode"=-
"disablespecificpopups"=-
"disableexpirationpopups"=-
"enableforceigpudgpufromui"=-
"hidexgputrayicon"=-
"showtrayicon"=-
"hideballoonnotification"=-
"performancestate"=-
"gc6state"=-
"framedisplaybasenegoffsetns"=-
"framedisplayresdivvalue"=-
"ignorenodelocked"=-
"ignoresp"=-
"dontaskagain"=-

; kernel new kizzimo
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"kiclocktimerpercpu"=-
"kiclocktimerhighlatency"=-
"kiclocktimeralwaysonpresent"=-
"clocktimerpercpu"=-
"clocktimerhighlatency"=-
"clocktimeralwaysonpresent"=-

; smooth scrolling
[HKEY_CURRENT_USER\Control Panel\Desktop]
"smoothscroll"=-

; fast user switching
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"hidefastuserswitching"=-

; dont tolerate high dpc/isr
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"exitlatency"=-
"exitlatencycheckenabled"=-
"latency"=-
"latencytolerancedefault"=-
"latencytolerancefsvp"=-
"latencytoleranceperfoverride"=-
"latencytolerancescreenoffir"=-
"latencytolerancevsyncenabled"=-
"rtlcapabilitychecklatency"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power]
*all values removed*

; display
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\ModernSleep]
"adaptiverefreshrate"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"videoidletimeout"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"powersavingmodeenabled"=-
"panelselfrefresh"=-
"forceoffscreentimeout"=-

; gpu
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"enableframebuffercompression"=-
"enablegpuboost"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv]
"start"=-

; network
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001]
"pnpcapabilities"=-




; ARKHAM

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX]
"d3d12_enable_unsafe_command_buffer_reuse"=-
"d3d12_enable_runtime_driver_optimizations"=-
"d3d12_resource_alignment"=-
"d3d11_multithreaded"=-
"d3d12_multithreaded"=-
"d3d11_deferred_contexts"=-
"d3d12_deferred_contexts"=-
"d3d11_allow_tiling"=-
"d3d11_enable_dynamic_codegen"=-
"d3d12_allow_tiling"=-
"d3d12_cpu_page_table_enabled"=-
"d3d12_heap_serialization_enabled"=-
"d3d12_map_heap_allocations"=-
"d3d12_residency_management_enabled"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl]
"creategdiprimaryonslavegpu"=-
"driversupportscdddwminterop"=-
"dxgkcddsyncdxaccess"=-
"dxgkcddsyncgpuaccess"=-
"dxgkcddwaitforverticalblankevent"=-
"dxgkcreateswapchain"=-
"dxgkfreegpuvirtualaddress"=-
"dxgkopenswapchain"=-
"dxgkshareswapchainobject"=-
"dxgkwaitforverticalblankevent"=-
"dxgkwaitforverticalblankevent2"=-
"swapchainbackbuffer"=-
"tdrresetfromtimeoutasync"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters]
"StorNVMeAllowZeroLatency"=-
"queuedepth"=-
"nvmemaxreadsplit"=-
"nvmemaxwritesplit"=-
"forceflush"=-
"immediatedata"=-
"maxsegmentspercommand"=-
"maxoutstandingcmds"=-
"forceeagerwrites"=-
"maxqueuedcommands"=-
"maxoutstandingiorequests"=-
"numberofrequests"=dword:000003e8
"io submissionqueuecount"=-
"ioqueuedepth"=-
"hostmemorybufferbytes"=-
"arbitrationburst"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device]
"StorNVMeAllowZeroLatency"=-
"queuedepth"=-
"nvmemaxreadsplit"=-
"nvmemaxwritesplit"=-
"forceflush"=-
"immediatedata"=-
"maxsegmentspercommand"=-
"maxoutstandingcmds"=-
"forceeagerwrites"=-
"maxqueuedcommands"=-
"maxoutstandingiorequests"=-
"numberofrequests"=dword:000003e8
"io submissionqueuecount"=-
"ioqueuedepth"=-
"hostmemorybufferbytes"=-
"arbitrationburst"=-

; dpc kernel tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"dpcwatchdogprofileoffset"=-
_dpctimeout"=-
"idealdpcrate"=-
"maximumdpcqueuedepth"=-
"minimumdpcrate"=-
"dpcwatchdogperiod"=-
"maxdynamictickduration"=-
"maximumsharedreadyqueuesize"=-
"buffersize"=-
"ioqueueworkitem"=-
"ioqueueworkitemtonode"=-
"ioqueueworkitemex"=-
"ioqueuethreadirp"=-
"extryqueueworkitem"=-
"exqueueworkitem"=-
"ioenqueueirp"=-
"xmmizerroingenable"=-
"usenormalstack"=-
"usenewaabuffering"=-
"stacksubsystemstacksize"=-

; cpu performance tuning
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment]
"cpu_max_pending_interrupts"=-
"cpu_max_pending_io"=-
"cpu_idle_policy"=-
"cpu_boost_policy"=-
"cpu_max_frequency"=-
"cpu_interrupt_balance_policy"=-
"mkl_debug_cpu_type"=-

"io performance tuning
"io_completion_policy"=-
"io_request_limit"=-
"disk_max_pending_io"=-
"io_priority"=-
"disk_max_pending_interrupts"=-
"io_max_pending_interrupts"=-




; HAKANFLY

; Revert Base and OverTarget Priorities
; Founded and Created by Kizzimo (Revert file created by Alchemy Tweaks)
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}]
"BasePriority"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}]
"BasePriority"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}]
"BasePriority"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}]
"BasePriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}]
"BasePriority"=-



[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003]


[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002]


[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001]


[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001]


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}]
"OverTargetPriority"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}]
"OverTargetPriority"=-

; Revert Advanced DWM Tweaks
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe]

; FlipPresent
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"ForceDirectDrawSync"=-
"FrameLatency"=-
"MaxQueuedPresentBuffers"=-

; Adjustablesd - jdallmann
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"DDisplayTestMode"=-
"DebugFailFast"=-
"DisableDeviceBitmaps"=-
"DisableHologramCompositor"=-
"DisableLockingMemory"=-
"DisableProjectedShadowsRendering"=-
"DisableProjectedShadows"=-
"DisallowNonDrawListRendering"=-
"EnableCpuClipping"=-
"EnableRenderPathTestMode"=-
"FlattenVirtualSurfaceEffectInput"=-
"InkGPUAccelOverrideVendorWhitelist"=-
"InteractionOutputPredictionDisabled"=-
"MPCInputRouterWaitForDebugger"=-
"OneCoreNoDWMRawGameController"=-
"ResampleInLinearSpace"=-
"SDRBoostPercentOverride"=-
"SuperWetEnabled"=-

; ImmediateRender - Kizzimo
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"AnimationAttributionEnabled"=-
"AnimationsShiftKey"=-
"DisableAdvancedDirectFlip"=-
"DisableDrawListCaching"=-
"EnableCommonSuperSets"=-
"EnableDesktopOverlays"=-
"EnableEffectCaching"=-
"EnableFrontBufferRenderChecks"=-
"EnableMegaRects"=-
"EnablePrimitiveReordering"=-
"EnableResizeOptimization"=-
"HighColor"=-
"MaxD3DFeatureLevel"=-
"OverlayQualifyCount"=-
"OverlayDisqualifyCount"=-
"ParallelModePolicy"=-
"ResampleModeOverride"=-
"RenderThreadWatchdogTimeoutMilliseconds"=-
"ResizeTimeoutGdi"=-
"ResizeTimeoutModern"=-
"UseHWDrawListEntriesOnWARP"=-

; Revert CSRSS Tweaks
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe]

; Revert D3D11 - D3D12 Tweaks
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX]
"D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE"=-
"D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS"=-
"D3D12_RESOURCE_ALIGNMENT"=-
"D3D11_MULTITHREADED"=-
"D3D12_MULTITHREADED"=-
"D3D11_DEFERRED_CONTEXTS"=-
"D3D12_DEFERRED_CONTEXTS"=-
"D3D11_ALLOW_TILING"=-
"D3D11_ENABLE_DYNAMIC_CODEGEN"=-
"D3D12_ALLOW_TILING"=-
"D3D12_CPU_PAGE_TABLE_ENABLED"=-
"D3D12_HEAP_SERIALIZATION_ENABLED"=-
"D3D12_MAP_HEAP_ALLOCATIONS"=-
"D3D12_RESIDENCY_MANAGEMENT_ENABLED"=-

; Revert DirectX Driver DXGKrnl Advanced Tweaks (2)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl]
"CreateGdiPrimaryOnSlaveGPU"=-
"DriverSupportsCddDwmInterop"=-
"DxgkCddSyncDxAccess"=-
"DxgkCddSyncGPUAccess"=-
"DxgkCddWaitForVerticalBlankEvent"=-
"DxgkCreateSwapChain"=-
"DxgkFreeGpuVirtualAddress"=-
"DxgkOpenSwapChain"=-
"DxgkShareSwapChainObject"=-
"DxgkWaitForVerticalBlankEvent"=-
"DxgkWaitForVerticalBlankEvent2"=-
"SwapChainBackBuffer"=-
"TdrResetFromTimeoutAsync"=-

; Revert NVMe Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters]
"StorNVMeAllowZeroLatency"=-
"QueueDepth"=-
"NvmeMaxReadSplit"=-
"NvmeMaxWriteSplit"=-
"ForceFlush"=-
"ImmediateData"=-
"MaxSegmentsPerCommand"=-
"MaxOutstandingCmds"=-
"ForceEagerWrites"=-
"MaxQueuedCommands"=-
"MaxOutstandingIORequests"=-
"NumberOfRequests"=-
"IoSubmissionQueueCount"=-
"IoQueueDepth"=-
"HostMemoryBufferBytes"=-
"ArbitrationBurst"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device]
"StorNVMeAllowZeroLatency"=-
"QueueDepth"=d-
"NvmeMaxReadSplit"=-
"NvmeMaxWriteSplit"=-
"ForceFlush"=-
"ImmediateData"=-
"MaxSegmentsPerCommand"=-
"MaxOutstandingCmds"=-
"ForceEagerWrites"=-
"MaxQueuedCommands"=-
"MaxOutstandingIORequests"=-
"NumberOfRequests"=-
"IoSubmissionQueueCount"=-
"IoQueueDepth"=-
"HostMemoryBufferBytes"=-
"ArbitrationBurst"=-

; Revert Priority Control Tweaks
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"AdjustDpcThreshold"=-
"DeepIoCoalescingEnabled"=-
"IdealDpcRate"=-
"ForegroundBoost"=-
"SchedulerAssistThreadFlagOverride"=-
"ThreadBoostType"=-
"ThreadSchedulingModel"=-

; Revert Resource Sets
[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets]

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationService]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceElastic]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="ElasticRecipient"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriElastic]
"CPU"="SoftCapLow"
"ExternalResources"="BackgroundAudioPlayer"
"Flags"="ElasticRecipient"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriority]
"CPU"="SoftCapLow"
"ExternalResources"="BackgroundAudioPlayer"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceRemote]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\AppToAppTarget]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="None"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundAudioPlayer]
"CPU"="SoftCapLow"
"ExternalResources"="BackgroundAudioPlayer"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundCachedFileUpdater]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskCompletion]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskDebug]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransfer]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransferNetworkState]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Balloon]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CalendarProviderAsChild]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CallingEvent]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CallingEventHighPriority]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="VeryHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ChatMessageNotification]
"CPU"="SoftCapFull"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="VeryHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ComponentTarget]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ContinuousBackgroundExecution]
"CPU"="SoftCapLow"
"ExternalResources"="ExtendedExecution"
"Flags"="None"
"Importance"="MediumHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CortanaSpeechBackground]
"CPU"="SoftCapLow"
"ExternalResources"="Cortana"
"Flags"="BackgroundDefault"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CreateProcess]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultModernBackgroundTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultPPLE]
"CPU"="SoftCapFull"
"ExternalResources"="PPLE"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultPPLE2]
"CPU"="SoftCapFull"
"ExternalResources"="PPLE"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcess]
"CPU"="SoftCapLowBackgroundBegin"
"ExternalResources"="EmCreateProcess"
"Flags"="EstimateMemoryUsage"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcessNormalPriority]
"CPU"="SoftCapLow"
"ExternalResources"="EmCreateProcess"
"Flags"="EstimateMemoryUsage"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHost]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHostHighPriority]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHostPPLE]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="FrozenPPLE"
"Importance"="EmptyHostPPLE"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\FileProviderTarget]
"CPU"="SoftCapFull"
"ExternalResources"="FileProviderTarget"
"Flags"="Foreground"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundAgent]
"CPU"="SoftCapLow"
"ExternalResources"="ForegroundAgent"
"Flags"="ShareWithFG"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundCachedFileUpdater]
"CPU"="SoftCapFull"
"ExternalResources"="ForegroundAgent"
"Flags"="None"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundTaskCompletion]
"CPU"="SoftCapFull"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Frozen]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GenericExtendedExecution]
"CPU"="SoftCapLow"
"ExternalResources"="ExtendedExecution"
"Flags"="None"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GeofenceTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundAgent]
"CPU"="UnmanagedAboveNormal"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="VeryHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundDemoted]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundTransfer]
"CPU"="SoftCapFull"
"ExternalResources"="ForegroundAgent"
"Flags"="ShareWithFG"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\IoTStartupTask]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\JumboForegroundAgent]
"CPU"="SoftCapLow"
"ExternalResources"="ForegroundAgent"
"Flags"="ShareWithFG"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaBackgroundTaskCompletion]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaDefaultModernBackgroundTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaPrelaunchForeground]
"CPU"="SoftCapFull"
"ExternalResources"="ApplicationService"
"Flags"="PrelaunchForeground"
"Importance"="Lowest"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiDebugModeForeground]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozen]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNCS]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="FrozenDNCS"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNK]
"CPU"="SoftCapFull"
"ExternalResources"="None"
"Flags"="FrozenDNK"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenHighPriority]
"CPU"="SoftCapFull"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="StartHost"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForeground]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForegroundLarge]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPaused]
"CPU"="HardCap0"
"ExternalResources"="Paused"
"Flags"="Paused"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedDNK]
"CPU"="SoftCapFull"
"ExternalResources"="Paused"
"Flags"="PausedDNK"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedHighPriority]
"CPU"="SoftCapFull"
"ExternalResources"="Paused"
"Flags"="Paused"
"Importance"="VeryHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausing]
"CPU"="SoftCapFull"
"ExternalResources"="Pausing"
"Flags"="Pausing"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningBluetooth]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationServiceNetworkSponsor"
"Flags"="BackgroundDefault"
"Importance"="MediumHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningControlChannel]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="MediumHigh"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\MediaProcessing]
"CPU"="SoftCapLow"
"ExternalResources"="ExtendedExecution"
"Flags"="ThrottleGPUInterference"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\OemBackgroundAgent]
"CPU"="SoftCapLow"
"ExternalResources"="EmCreateProcess"
"Flags"="NotKillable"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\OemTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PendingDefaultPPLE]
"CPU"="SoftCapFull"
"ExternalResources"="PPLE"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PiP]
"CPU"="SoftCapLow"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="CriticalNoUi"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PreinstallTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PrelaunchForeground]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="PrelaunchForeground"
"Importance"="Lowest"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PushTriggerTask]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ResourceIntensive]
"CPU"="SoftCapLow"
"ExternalResources"="ResourceIntensive"
"Flags"="BackgroundDefault"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShareDataPackageHost]
"CPU"="SoftCapFull"
"ExternalResources"="ApplicationService"
"Flags"="None"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShortRunningBluetooth]
"CPU"="SoftCapLow"
"ExternalResources"="ApplicationService"
"Flags"="BackgroundDefault"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\TaskCompletionHighPriority]
"CPU"="SoftCapLow"
"ExternalResources"="ExtendedExecution"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiComposer]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiDebugModeForeground]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiForegroundDNK]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozen]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNCS]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="FrozenDNCS"
"Importance"="Low"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNK]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="FrozenDNK"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenHighPriority]
"CPU"="HardCap0"
"ExternalResources"="None"
"Flags"="Frozen"
"Importance"="StartHost"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiLockScreen]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForeground]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundExtended]
"CPU"="SoftCapLow"
"ExternalResources"="UiExtended"
"Flags"="None"
"Importance"="CriticalNoUi"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundLarge]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiOverlay]
"CPU"="SoftCapLow"
"ExternalResources"="UiOverlay"
"Flags"="Foreground"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPaused]
"CPU"="Paused"
"ExternalResources"="Paused"
"Flags"="Paused"
"Importance"="VeryLow"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausedDNK]
"CPU"="Paused"
"ExternalResources"="Paused"
"Flags"="PausedDNK"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausedHighPriority]
"CPU"="Paused"
"ExternalResources"="Paused"
"Flags"="Paused"
"Importance"="StartHost"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausing]
"CPU"="SoftCapLow"
"ExternalResources"="Pausing"
"Flags"="Pausing"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausingLowPriority]
"CPU"="SoftCapLow"
"ExternalResources"="Pausing"
"Flags"="Pausing"
"Importance"="StartHost"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom1]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom2]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom3]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiShellCustom4]
"CPU"="SoftCapFull"
"ExternalResources"="StandardExternalResources"
"Flags"="Foreground"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VideoTranscoding]
"CPU"="SoftCapLow"
"ExternalResources"="ExtendedExecution"
"Flags"="ThrottleGPUInterference"
"Importance"="Medium"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallBackground]
"CPU"="SoftCapFullAboveNormal"
"ExternalResources"="VoipBackground"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallBackgroundPriority]
"CPU"="SoftCapFullAboveNormal"
"ExternalResources"="VoipCall"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipActiveCallForeground]
"CPU"="SoftCapFullAboveNormal"
"ExternalResources"="VoipCall"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipForegroundWorker]
"CPU"="SoftCapFull"
"ExternalResources"="VoipLegacy"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipSuspendedBackground]
"CPU"="Paused"
"ExternalResources"="None"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\VoipWorker]
"CPU"="SoftCapFull"
"ExternalResources"="ApplicationService"
"Flags"="PPLE"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Vpn]
"CPU"="SoftCapFull"
"ExternalResources"="ForegroundAgent"
"Flags"="None"
"Importance"="Critical"
"IO"="NoCap"
"Memory"="NoCap"

[HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\WebAuthSignIn]
"CPU"="SoftCapFull"
"ExternalResources"="WebAuthSignIn"
"Flags"="Foreground"
"Importance"="High"
"IO"="NoCap"
"Memory"="NoCap"



; DWM

; Revert Advanced DWM Tweaks
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe]

; FlipPresent
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"ForceDirectDrawSync"=-
"FrameLatency"=-
"MaxQueuedPresentBuffers"=-

; Adjustablesd - jdallmann
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"DDisplayTestMode"=-
"DebugFailFast"=-
"DisableDeviceBitmaps"=-
"DisableHologramCompositor"=-
"DisableLockingMemory"=-
"DisableProjectedShadowsRendering"=-
"DisableProjectedShadows"=-
"DisallowNonDrawListRendering"=-
"EnableCpuClipping"=-
"EnableRenderPathTestMode"=-
"FlattenVirtualSurfaceEffectInput"=-
"InkGPUAccelOverrideVendorWhitelist"=-
"InteractionOutputPredictionDisabled"=-
"MPCInputRouterWaitForDebugger"=-
"OneCoreNoDWMRawGameController"=-
"ResampleInLinearSpace"=-
"SDRBoostPercentOverride"=-
"SuperWetEnabled"=-

; ImmediateRender - Kizzimo
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\DWM]
"AnimationAttributionEnabled"=-
"AnimationsShiftKey"=-
"DisableAdvancedDirectFlip"=-
"DisableDrawListCaching"=-
"EnableCommonSuperSets"=-
"EnableDesktopOverlays"=-
"EnableEffectCaching"=-
"EnableFrontBufferRenderChecks"=-
"EnableMegaRects"=-
"EnablePrimitiveReordering"=-
"EnableResizeOptimization"=-
"HighColor"=-
"MaxD3DFeatureLevel"=-
"OverlayQualifyCount"=-
"OverlayDisqualifyCount"=-
"ParallelModePolicy"=-
"ResampleModeOverride"=-
"RenderThreadWatchdogTimeoutMilliseconds"=-
"ResizeTimeoutGdi"=-
"ResizeTimeoutModern"=-
"UseHWDrawListEntriesOnWARP"=-




; set split treshold for svchost
; Restore Default Behavior
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control]
"SvcHostSplitThresholdInKB"=dword:380000



; MEDIA PLAYER
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Health]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Skins]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Player\Tasks]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\EqualizerSettings]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\HME]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\Preferences\ProxySettings]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\MediaPlayer\UIPlugins]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK\General]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Media\WMSDK\Namespace]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\JumplistData\Microsoft.Windows.MediaPlayer32]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/vnd.ms-wpl]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-mplayer2]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmd]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\application/x-ms-wmz]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/3gpp2]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/aiff]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/basic]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mid]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/midi]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp3]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mp4]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpeg]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/mpegurl]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-mpegurl]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-wav]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\midi/mid]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\audio/x-matroska]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/3gpp2]
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mp4]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpeg]
[-HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/mpg]
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/msvideo]
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\MIMEAssociations\video/quicktime]




; POWERSHELL
; disallow powershell scripts
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell]
"ExecutionPolicy"="Restricted"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell]
"ExecutionPolicy"="Restricted"




; W10 & W11 SERVICES ON
; graphic driver & defender services left out.

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ADPSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AarSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AJRouter]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ALG]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppIDSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Appinfo]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppMgmt]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppReadiness]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppVClient]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppXSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ApxSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AssignedAccessManagerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AudioEndpointBuilder]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Audiosrv]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\autotimesvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AxInstSV]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BcastDVRUserService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BDESVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BITS]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BluetoothUserService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Browser]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BrokerInfrastructure]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BTAGService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BthAvctpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\camsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CaptureService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\cbdhsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CDPSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CDPUserSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CertPropSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ClipSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CloudBackupRestoreSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\cloudidsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\COMSysApp]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ConsentUxUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CoreMessagingRegistrar]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CredentialEnrollmentManagerUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CryptSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CscService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DcomLaunch]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dcsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\defragsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceAssociationBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceAssociationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DeviceInstall]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevicePickerUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevicesFlowUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DevQueryBroker]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Dhcp]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DiagTrack]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DialogBlockingService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DispBrokerDesktopSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DisplayEnhancementService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DmEnrollmentSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Dnscache]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DoSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dot3svc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DPS]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DsmSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DsSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DusmSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EapHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdatem]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdate]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EFS]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\embeddedmode]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EntAppSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventSystem]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Fax]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\fdPHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FDResPub]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\fhsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FontCache]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FontCache3.0.0.0]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FrameServerMonitor]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FrameServer]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GameInputSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\gpsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GraphicsPerfSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\hidserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\hpatchmon]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\HvHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\icssvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\IKEEXT]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\InstallService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\InventorySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\iphlpsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\IpxlatCfgSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\KeyIso]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\KtmRm]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanWorkstation]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lfsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LicenseManager]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lltdsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\lmhosts]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LocalKdc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\logi_lamparray_service]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LSM]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LxpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MapsBroker]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\McpManagementService]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MDCoreSvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MessagingService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MixedRealityOpenXRSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mpssvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSDTC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSiSCSI]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\msiserver]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MsKeyboardFilter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NaturalAuthentication]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcbService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcdAutoSetup]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Netlogon]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Netman]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\netprofm]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetSetupSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetTcpPortSharing]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcCtnrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NlaSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NPSMSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nsi]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\OneSyncSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\p2pimsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\p2psvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\P9RdrService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PcaSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PeerDistSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PenService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\perceptionsimulation]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PerfHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PhoneSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PimIndexMaintenanceSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\pla]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PlugPlay]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PNRPAutoReg]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PNRPsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PolicyAgent]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Power]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintDeviceConfigurationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintNotify]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintScanBrokerService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ProfSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PushToInstall]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\QWAVE]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RasAuto]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RasMan]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\refsdedupsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteAccess]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteRegistry]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RetailDemo]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RmSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcEptMapper]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcLocator]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCardSvr]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ScDeviceEnum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Schedule]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCPolicySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SDRSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\seclogon]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SEMgrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensorDataService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensorService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SensrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SENS]
"Start"=dword:00000002

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense]
; "Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SessionEnv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedRealitySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ShellHWDetection]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\shpamsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\smphost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SmsRouter]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SNMPTrap]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\spectrum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Spooler]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\sppsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SSDPSRV]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ssh-agent]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SstpSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StateRepository]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\stisvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StiSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\StorSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\svsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\swprv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SysMain]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SystemEventsBroker]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TabletInputService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TapiSrv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TermService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TextInputManagementService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Themes]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TieringEngineService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TimeBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TokenBroker]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TrkWks]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TroubleshootingSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TrustedInstaller]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\tzautoupdate]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UdkUserSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UevAgentService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uhssvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UmRdpService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UnistoreSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\upnphost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UserDataSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UserManager]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UsoSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VacSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VaultSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vds]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicguestinterface]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicheartbeat]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmickvpexchange]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicrdv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicshutdown]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmictimesync]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvmsession]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvss]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VSS]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\W32Time]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WaaSMedicSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WalletService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WarpJITSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wbengine]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WbioSrvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Wcmsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wcncsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiServiceHost]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiSystemHost]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]
; "Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WebClient]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]
; "Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Wecsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WEPHOSTSVC]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wercplsupport]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WFDSConMgrSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\whesvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WiaRpc]
"Start"=dword:00000003

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinHttpAutoProxySvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Winmgmt]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinRM]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wisvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WlanSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wlidsvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wlpasvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WManSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wmiApSrv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WMPNetworkSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\workfolderssvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpcMonSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WPDBusEnum]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WSAIFabricSvc]
"Start"=dword:00000002

; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
; "Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WSearch]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wuauserv]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WwanSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblAuthManager]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblGameSave]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxGipSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxNetApiSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ZTHELPER]
"Start"=dword:00000003




; FrameSync Labs

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"CoalescingTimerInterval"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"TimerCoalescing"=-

[HKEY_CURRENT_USER\Control Panel\Desktop]
"ScreenSaveActive"=-
"ScreenSaveTimeOut"=-
"SCRNSAVE.EXE"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"EnablePreemption"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet]
"EnableActiveProbing"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"EventProcessorEnabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm]
"OverlayTestMode"=-
"OverlayMinFPS"=dword:0000001e

[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_FSEBehaviorMode"=dword:00000000
"GameDVR_FSEBehavior"=dword:00000000

[HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys]
"Flags"="62"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap]
"Enabled"=-
"OverrideServerSKU"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"ScopeType"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"SleepStudyDisabled"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"ThreadDpcEnable"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"QueuedPresentLimit"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"HwSchMode"=-
"HwSchTreatExperimentalAsStable"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"SerializeTimerExpiration"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System]
"EnableCpuQuota"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters]
"MouseDataQueueSize"=dword:00000064
"@

				Set-Content -Path "$env:TEMP\Registry Defaults.reg" -Value $MultilineComment -Force
				# edit reg file
				$path = "$env:TEMP\Registry Defaults.reg"
				(Get-Content $path) -replace "\?","$" | Out-File $path

				# Revert NTFS performance
    			fsutil behavior set disablelastaccess 0 | Out-Null 
    			fsutil behavior set disable8dot3 0 | Out-Null

				# Unpause Windows updates
				Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Aetherinox/pause-windows-updates/raw/refs/heads/main/windows-updates-unpause.reg" -OutFile "$env:TEMP\windows-updates-unpause.reg"
				Start-Process reg.exe -ArgumentList "import `"$env:TEMP\windows-updates-unpause.reg`"" -Wait
				
				# Resets Windows Update settings to default
				Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/ChrisTitusTech/winutil/raw/refs/heads/main/functions/public/Invoke-WPFUpdatesdefault.ps1" -OutFile "$env:TEMP\Invoke-WPFUpdatesdefault.ps1"
				(Get-Content "$env:TEMP\Invoke-WPFUpdatesdefault.ps1") | Where-Object {$_ -notmatch '\[System\.Windows\.MessageBox'} | Set-Content -Path "$env:TEMP\Invoke-WPFUpdatesdefault.ps1" -Encoding UTF8
								
				. "$env:TEMP\Invoke-WPFUpdatesdefault.ps1"
				if (Get-Command Invoke-WPFUpdatessecurity -ErrorAction SilentlyContinue) {
				    Invoke-WPFUpdatesdefault *> $null 2>&1
				}				

                # set account password to expire
                Get-LocalUser | ForEach-Object { Set-LocalUser -Name $_.Name -PasswordNeverExpires $false | Out-Null }

				# BCDEdit Revert
				netsh interface tcp set global autotuninglevel=normal				
				bcdedit /deletevalue disabledynamictick
				bcdedit /deletevalue useplatformtick
				bcdedit /set nx OptIn
				bcdedit /deletevalue integrityservices
				bcdedit /set hypervisorlaunchtype Auto
				bcdedit /deletevalue vsmlaunchtype
				bcdedit /deletevalue vm
				bcdedit /deletevalue isolatedcontext
				bcdedit /deletevalue useplatformclock
				bcdedit /set tscsyncpolicy Legacy			
				bcdedit /set bootmenupolicy Standard
				bcdedit /deletevalue quietboot
				bcdedit /deletevalue bootux
				bcdedit /deletevalue bootlog
				bcdedit /timeout 30
				bcdedit /event on				
				bcdedit /set bootdebug off
				bcdedit /set debug off
				bcdedit /set ems off
				bcdedit /set bootems off
				bcdedit /set sos off
				
				# Windows 11 Stuff
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {								
					reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /f *> $null
				}
				
				# import reg file
				Regedit.exe /S "$env:TEMP\Registry Defaults.reg"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				exit
				
			}
		} 
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}