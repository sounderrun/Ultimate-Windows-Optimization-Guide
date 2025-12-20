<# : batch portion
@echo off
setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || >nul 2>&1 net session || (
    if not defined _elev (
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c', '!_PSarg!' -Verb RunAs" && exit /b 0
        exit /b 1
    )
)
where pwsh.exe>nul 2>&1 && set "PS1=pwsh" || set "PS1=powershell"
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = "Gamebar" + " (Administrator)"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

Write-Host "1. Gamebar Xbox: Off (Recommended)"
Write-Host "2. Gamebar Xbox: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
	            Clear-Host			
				$progresspreference = 'silentlycontinue'
				# disable gamebar regedit
				reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f | Out-Null
				reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f | Out-Null
				# disable open xbox game bar using game controller regedit
				reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f | Out-Null
				# disable gameinput service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable gamedvr and broadcast user service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox accessory management service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live auth manager service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live game save service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live networking service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable ms-gamebar notifications with xbox controller plugged in regedit
				# create reg file
				$MultilineComment = @"
Windows Registry Editor Version 5.00	
	
; disable ms-gamebar notifications with xbox controller plugged in	
[HKEY_CLASSES_ROOT\ms-gamebar]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebar"	
	
[HKEY_CLASSES_ROOT\ms-gamebar\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebarservices"	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamingoverlay"	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
"@
				# import reg file
				Set-Content -Path "$env:TEMP\MsGamebarNotiOff.reg" -Value $MultilineComment -Force; reg import "$env:TEMP\MsGamebarNotiOff.reg" *> $null								
				# stop gamebar and GameInput running
				$stop = "GameBar", "GameBarFTServer", "gamingservices", "gamingservicesnet", "GameInputSVC"; $stop | % { Stop-Process -Name $_ -Force -ea 0 }
				# uninstall gamebar & xbox apps
				Get-AppxPackage | ? { $_.Name -match 'Xbox|Gaming' } | Remove-AppxPackage -ea 0
				# uninstall gameinput
				$gameInput = Get-Package -ProviderName Programs -Name "*GameInput*" -ea 0;if ($gameInput) { $gameInput | Uninstall-Package -Force -ea 0 | Out-Null }
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Start-Process ms-settings:gaming-gamebar
				exit
			}
			2 {
				Clear-Host
				$progresspreference = 'silentlycontinue'
				# gamebar regedit
				reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f | Out-Null
				reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f | Out-Null
				# open xbox game bar using game controller regedit
				cmd.exe /c "reg delete `"HKCU\Software\Microsoft\GameBar`" /v `"UseNexusForGameBarEnabled`" /f >nul 2>&1"
				# gameinput service
				reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# gamedvr and broadcast user service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox accessory management service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live auth manager service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live game save service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live networking service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# ms-gamebar notifications with xbox controller plugged in regedit
				# create reg file
				$MultilineComment = @"
Windows Registry Editor Version 5.00

; ms-gamebar notifications with xbox controller plugged in regedit
[-HKEY_CLASSES_ROOT\ms-gamebar]
[-HKEY_CLASSES_ROOT\ms-gamebarservices]
[-HKEY_CLASSES_ROOT\ms-gamingoverlay\shell]

[HKEY_CLASSES_ROOT\ms-gamingoverlay]
"URL Protocol"=""
@="URL:ms-gamingoverlay"
"@
				Set-Content -Path "$env:TEMP\MsGamebarNotiOn.reg" -Value $MultilineComment -Force
				# import reg file
				Regedit.exe /S "$env:TEMP\MsGamebarNotiOn.reg"
				# install store, gamebar, xbox & gaming services apps
				'Store','Xbox','Gaming' | % { Get-AppxPackage -AllUsers "*$_*" | % { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ea 0 } }
				# install gameinput
				if (gcm winget -ea 0) {
				    winget list --id Microsoft.GameInput -e *>$null
				    if ($LASTEXITCODE -eq 0) { winget uninstall --id Microsoft.GameInput -e -h --accept-source-agreements *>$null }
				} else {
					# download and install 7zip
					$asset = (irm "https://api.github.com/repos/ip7z/7zip/releases/latest").assets | ? { $_.name -like "*x64.exe" } | select -First 1
					$exe = Join-Path $env:TEMP $asset.name
					curl.exe -sS -L -o $exe $asset.browser_download_url
					saps -Wait $exe -ArgumentList '/S'
					# download GameInput package
					$v = (irm https://api.nuget.org/v3-flatcontainer/microsoft.gameinput/index.json).versions[-1]
					$url = "https://api.nuget.org/v3-flatcontainer/microsoft.gameinput/$v/microsoft.gameinput.$v.nupkg"
					$pkgPath = "$env:TEMP\microsoft.gameinput.$v.nupkg"
					$dst = "$env:TEMP\GameInputPkg"
					curl.exe -sS -L -o $pkgPath $url
					# extract with 7zip
					& "C:\Program Files\7-Zip\7z.exe" x $pkgPath "-o$dst" -y | Out-Null
					# start GameInput installer
					$msi = "$env:TEMP\GameInputPkg\redist\GameInputRedist.msi"; saps msiexec.exe -Wait -ArgumentList "/i",$msi,"/quiet","/norestart"
				}
				# fix xbox sign in
				# enable UAC
				New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ea 0 | Out-Null
				New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -PropertyType Dword -ea 0 | Out-Null
				Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -ea 0 | Out-Null
				# stop edge running
				$stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"
				$stop | % { Stop-Process -Name $_ -Force -ea 0 }
				# clear edge blocks
				& {$(Invoke-RestMethod "https://github.com/he3als/EdgeRemover/raw/refs/heads/main/ClearUpdateBlocks.ps1")} -Silent | Out-Null
				# download edge webview installer
				curl.exe -sS -L -o "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
				# start edge webview installer
				saps -Wait "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" -ArgumentList "/silent /install"
				# download gamebar repair tool
				curl.exe -sS -L -o "$env:TEMP\GamingRepairTool.exe" "https://aka.ms/GamingRepairTool"
				# start gamebar repair tool
				saps -wait "$env:TEMP\GamingRepairTool.exe"
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Start-Process ms-settings:gaming-gamebar
                exit
            }
        } 
    } else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}