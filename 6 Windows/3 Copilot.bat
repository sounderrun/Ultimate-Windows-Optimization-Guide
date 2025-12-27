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
@:: Running the script with PowerShell 7 can cause issues, to avoid this ensure you are running Windows PowerShell (5.1)
set "ps1=powershell"
%ps1% -nop -ep Bypass -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = 'Copilot (Administrator)'

Write-Host "1. Copilot: Off (Recommended)"
Write-Host "2. Copilot: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
				
                cls; $progresspreference = 'silentlycontinue'; powershell "& ([scriptblock]::Create((irm https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1))) -nonInteractive -backupMode -AllOptions"
				cls; Write-Host "Restart to apply . . ."; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown"); exit
				
			}
            2 {
				
                cls; $progresspreference = 'silentlycontinue'; powershell "& ([scriptblock]::Create((irm https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1))) -nonInteractive -revertMode -AllOptions"
				cls; Write-Host "Restart to apply . . ."; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown"); exit
				
			}
        }
    } else {Write-Host "Invalid input. Please select a valid option (1-2)."}
}
