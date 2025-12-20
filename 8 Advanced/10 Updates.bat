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

$Host.UI.RawUI.WindowTitle = 'Updates (Administrator)'

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
'@; $V='';'cmd','arg','id','key'|%{$V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';"}; sp $key $id $($V, $code) -type 7 -force -ea 0
	saps powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
} # lean & mean snippet by AveYo, 2022.01.28

Write-Host '1. Updates: Off'
Write-Host '2. Updates: Default'
	while ($true) {
    $choice = Read-Host ' '
    if ($choice -match '^[1-2]$') {
		switch ($choice) {
			1 {
				Clear-Host
				$ProgressPreference = 'SilentlyContinue'
				Write-Host 'Updates: Off. Please wait . . .'
				
				# download tsgrgo Windows Update Disabler
				$zip="$env:TEMP\wud.zip";$dir="$env:TEMP\windows-update-disabler-main";$bat="$dir\disable updates.bat"
				curl.exe -sSL -o $zip https://github.com/tsgrgo/windows-update-disabler/releases/latest/download/windows-update-disabler-main.zip
				# extract files
				Expand-Archive $zip $env:TEMP -Force
				# edit batch file
				(gc $bat)|?{$_ -notmatch 'if not "%[12]"=="(admin|system)"' -and $_ -notmatch '^\s*pause\s*$'}|sc $bat -Encoding ASCII
				# disable updates RunAsTI
				RunAsTI $bat; do{sleep 2}while(gwmi Win32_Process -Filter "Name='cmd.exe'"|? CommandLine -like '*disable updates.bat*')
				# hide updates settings
				ni HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force | Out-Null
				sp HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer SettingsPageVisibility "hide:windowsupdate"
				gps SystemSettings,Settings -ea 0|%{kill $_ -Force -ea 0}
				
				Clear-Host
				Write-Host 'Restart to apply . . .'
				$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
				saps ms-settings:windowsupdate
				exit
			}
			2 {
				Clear-Host
				$ProgressPreference = 'SilentlyContinue'
		        Write-Host 'Updates: Default. Please wait . . .'
				
				# download tsgrgo Windows Update Disabler
				$zip="$env:TEMP\wud.zip";$dir="$env:TEMP\windows-update-disabler-main";$bat="$dir\enable updates.bat"
				curl.exe -sSL -o $zip https://github.com/tsgrgo/windows-update-disabler/releases/latest/download/windows-update-disabler-main.zip
				# extract files
				Expand-Archive $zip $env:TEMP -Force
				# edit batch file
				(gc $bat)|?{$_ -notmatch 'if not "%[12]"=="(admin|system)"' -and $_ -notmatch '^\s*pause\s*$'}|sc $bat -Encoding ASCII
				# enable updates RunAsTI
				RunAsTI $bat; do{sleep 2}while(gwmi Win32_Process -Filter "Name='cmd.exe'"|? CommandLine -like '*enable updates.bat*')
				# show updates settings
				rp HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer SettingsPageVisibility -ea 0
				gps SystemSettings,Settings -ea 0|%{kill $_ -Force -ea 0}
				
				Clear-Host
				Write-Host 'Restart to apply . . .'
				$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
				saps ms-settings:windowsupdate
				exit
			}
		} 
	} else { Write-Host 'Invalid input. Please select a valid option (1-2).' } 
}