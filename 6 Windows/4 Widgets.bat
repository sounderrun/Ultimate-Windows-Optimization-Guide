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

$Host.UI.RawUI.WindowTitle = 'Widgets (Administrator)'

	function Get-FileFromWeb {
	param([string]$URL,[string]$File)
	function Show-Progress {
	param([single]$T,[single]$C,[int]$B=10)
	$p=$C/$T;$pc=$p*100
	if($psISE){Write-Progress '' -Id 0 -PercentComplete $pc}
	else{Write-Host -NoNewLine "`r  $(''.PadRight($B*$p,9608).PadRight($B,9617))  $($pc.ToString('##0.00').PadLeft(6)) % "}
	}
	[Net.ServicePointManager]::SecurityProtocol='Tls12,Tls13'
	Add-Type -A System.Net.Http -ea 0; $c=[Net.Http.HttpClient]::new()
	if($File -like '.\*'){$File=Join-Path (pwd) $File.Substring(2)}
	if($File -and !(Split-Path $File)){$File=Join-Path (pwd) $File}
	$d=[IO.Path]::GetDirectoryName($File);if($d -and !(Test-Path $d)){[IO.Directory]::CreateDirectory($d)|out-null}
	try{
	$r=$c.GetAsync($URL,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
	$r.EnsureSuccessStatusCode()|out-null
	$s=$r.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
	$len=[long]$r.Content.Headers.ContentLength
	$buf=[byte[]]::new(1mb)
	$fs=[IO.File]::Create($File)
	$t=0
	while(($n=$s.Read($buf,0,$buf.Length)) -gt 0){
	$fs.Write($buf,0,$n);$t+=$n
	if($len -gt 0){Show-Progress $len $t}
	}
	if($len -gt 0){Show-Progress $len $len}
	}finally{
	if($fs){$fs.Close()}
	if($s){$s.Close()}
	$c.Dispose()
	}
	}

Write-Host "1. Widgets: Off (Recommended)"
Write-Host "2. Widgets: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
    	switch ($choice) {
    		1 {

				Clear-Host
				# Windows 10
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {					
					# disable news and interests
					ni 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -force | out-null; sp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -name 'EnableFeeds' -Value 0 -Type DWord | out-null
				}
				# Windows 11
				elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
					# remove Widgets Platform Runtime, Windows Web Experience App & Start Experiences App
					$progresspreference = 'silentlycontinue'
					gsv -name AppXSVC, AppReadiness, ClipSVC, wuauserv, BITS | % {set-service -name $_.name -StartupType Manual -ea 0; sasv -name $_.name -ea 0 |out-null}
					Get-AppxPackage -allusers *Microsoft.WidgetsPlatformRuntime* | Remove-AppxPackage
					Get-AppxPackage -allusers *MicrosoftWindows.Client.WebExperience* | Remove-AppxPackage
					Get-AppxPackage -allusers *Microsoft.StartExperiencesApp* | Remove-AppxPackage
					# disable widgets
					reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f | out-null
					# remove windows widgets from taskbar regedit
					reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f | out-null
				}
				# restart explorer
				kill -Name explorer -Force -ea 0; sleep 1
				# open taskbar settings
				saps ms-settings:taskbar; exit
				
      		}
    		2 {
				
				# w10
				cls; if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
					# enable news and interests
					rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -ea 0; ri 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -ea 0
					Write-Host "Installing & Updating: Edge . . ."
					if (-not (Test-Path ${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe)) {
						# download edge installer
						Get-FileFromWeb "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&brand=M100" "$env:TEMP\MicrosoftEdgeSetup.exe"
						# start edge installer
						saps -wait "$env:TEMP\MicrosoftEdgeSetup.exe" "/silent /install"
					}
					cls; write-host "Installing & Updating: Edge Webview2 . . ."
					# download edge webview installer
					Get-FileFromWeb "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$env:TEMP\MicrosoftEdgeWebview2Setup.exe"
					start edge webview installer
					saps -wait "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" "/silent /install"					
				}
				# w11
				elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
					# widgets regedit
					reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "1" /f |out-null
					# windows widgets from taskbar regedit
					cmd /c "reg delete `"HKLM\SOFTWARE\Policies\Microsoft\Dsh`" /f >nul 2>&1"
					write-host "Installing & Updating: Edge . . ."
					# clear edge blocks
					& {$(Invoke-RestMethod "https://github.com/he3als/EdgeRemover/raw/refs/heads/main/ClearUpdateBlocks.ps1")} -Silent *>$null
					cls; write-host "Installing & Updating: Edge Webview2 . . ."
					# download edge webview installer
					Get-FileFromWeb "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$env:TEMP\MicrosoftEdgeWebview2Setup.exe"
					# start edge webview installer
					saps -wait "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" "/silent /install"
					# install Widgets Platform Runtime, Windows Web Experience App, Start Experiences App & store
					$ProgressPreference = 'SilentlyContinue'
					gsv -name AppXSVC, AppReadiness, ClipSVC, wuauserv, BITS | % {set-service -name $_.name -StartupType Manual -ea 0; sasv -name $_.name -ea 0 |out-null}
					Get-AppXPackage -AllUsers *Microsoft.WidgetsPlatformRuntime* | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *MicrosoftWindows.Client.WebExperience* | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *Microsoft.StartExperiencesApp* | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}
				}
				# restart explorer
				kill -Name explorer -Force -ea 0; sleep 1
				# open taskbar settings
				saps ms-settings:taskbar; exit
				
      		}
   		 }
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." }
}
