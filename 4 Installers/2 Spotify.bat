<# : batch portion
@setlocal EnableDelayedExpansion
@echo off
where pwsh.exe >nul 2>&1 && set "ps1=pwsh" || set "ps1=powershell"
%ps1% -nop -ep Bypass -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

#Requires -Version 5.1
$Host.UI.RawUI.WindowTitle = 'Spotify'
$progresspreference = 'silentlycontinue'
# download & install SpotX
try {$bat="$env:TEMP\Install_New_theme.bat"; curl.exe -LSs -o $bat "https://raw.githack.com/amd64fox/SpotX/main/Install_New_theme.bat"; & $bat -ea 1} 
catch {iex "& { $(iwr -useb 'https://raw.githubusercontent.com/SpotX-Official/SpotX/refs/heads/main/run.ps1') } -new_theme"}