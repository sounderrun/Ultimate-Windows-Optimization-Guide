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

# Atlas Playbook
if ((Test-Path "$env:windir\AtlasModules"  -ea 0) -and (Test-Path "$env:windir\AtlasDesktop"  -ea 0)) {& "$env:windir\AtlasDesktop\7. Security\Defender\Toggle Defender.cmd"; exit 0}

$Host.UI.RawUI.WindowTitle = 'Security (Administrator)'

Write-Host '1. Security: Off'
Write-Host '2. Security: On'
while ($true) {
    $choice = Read-Host ' '
    if ($choice -match '^[1-2]$') {
		switch ($choice) {
			1 {
				Clear-Host
				$ProgressPreference = 'SilentlyContinue'
				
				# disable VBS
				bcdedit /set hypervisorlaunchtype off | Out-Null
				
				# Lost Zombie
				curl.exe -sS -L -o "$env:TEMP\AchillesScript.cmd" https://github.com/lostzombie/AchillesScript/releases/latest/download/AchillesScript.cmd
				if (Test-Path "$env:TEMP\AchillesScript.cmd" -ea 0) { & "$env:TEMP\AchillesScript.cmd" apply 4 }
				
				# FREETHY
				Clear-Host
				$ps1 = "$env:TEMP\SecurityOff.ps1"
				if (!(Test-Path $ps1)) {
				    $content = (iwr 'https://raw.githubusercontent.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/main/8%20Advanced/9%20Security.ps1' -UseBasicParsing).Content
				    $pattern = '(?s)(Write-Host "1\. Security: Off".*?Write-Host "2\. Security: On".*?)while \(\$true\) \{\s*\$choice = Read-Host "\s*"'
				    if ($content -match $pattern) {$content = $content -replace $pattern, '${1}while ($true) { $choice = "1"'}
				    sc $ps1 $content -Encoding UTF8
				}
				if (Test-Path $ps1) {$code = Get-Content $ps1 -Raw
				if ($code) {& ([scriptblock]::Create($code)) 2>$null}}
				
				exit 1
			}
			2 {
				Clear-Host
				$ProgressPreference = 'SilentlyContinue'
				
				# enable VBS
				bcdedit /deletevalue hypervisorlaunchtype | Out-Null
				
				# Lost Zombie
				$cmd = "$env:TEMP\AchillesScript.cmd"; ri $cmd -force -ea 0
				curl.exe -sS -L -o "$env:TEMP\AchillesScript.cmd" https://github.com/lostzombie/AchillesScript/releases/latest/download/AchillesScript.cmd
				if (Test-Path $cmd -ea 0) { & "$env:TEMP\AchillesScript.cmd" restore }
				
				# FREETHY
				Clear-Host
				$ps1 = "$env:TEMP\SecurityOn.ps1"
				if (!(Test-Path $ps1)) {
				    $content = (iwr 'https://raw.githubusercontent.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/main/8%20Advanced/9%20Security.ps1' -UseBasicParsing).Content
				    $pattern = '(?s)(Write-Host "1\. Security: Off".*?Write-Host "2\. Security: On".*?)while \(\$true\) \{\s*\$choice = Read-Host "\s*"'
				    if ($content -match $pattern) {$content = $content -replace $pattern, '${1}while ($true) { $choice = "2"'}
				    sc $ps1 $content -Encoding UTF8
				}
				if (Test-Path $ps1) {$code = Get-Content $ps1 -Raw
				if ($code) {& ([scriptblock]::Create($code)) 2>$null}}
				
				exit 1
			}
		}
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." }
}