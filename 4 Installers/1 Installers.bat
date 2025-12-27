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
	
	$Host.UI.RawUI.WindowTitle = 'Installers (Administrator)'
	
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
	
	function show-menu {
	# temp folder cleanup
	gci "C:\Windows\Temp" *.* -recurse | ri -force -recurse -ea 0; gci $env:TEMP *.* -recurse | ri -force -recurse -ea 0 *>$null
	Clear-Host
	Write-Host "Game launchers, programs and web browsers:"
    Write-Host "-Disable hardware acceleration"
    Write-Host "-Turn off running at startup"
    Write-Host "-Deactivate overlays"
    Write-Host ""
    Write-Host "Lower GPU usage and higher framerates reduce latency."
    Write-Host "Optimize your game settings to achieve this."
    Write-Host "Further tuning can be done via config files or launch options."
	Write-Host ""
    Write-Host " 1. Exit		18. NanaZip		35. Everything"
    Write-Host " 2. 7-Zip		19. Brave		36. simplewall"
    Write-Host " 3. Battle.net		20. Revo Uninstaller	37. UniGetUI"
	Write-Host " 4. Discord		21. CoreTemp		38. Process Lasso"
    Write-Host " 5. Electronic Arts	22. LibreWolf		39. Fan Control"
    Write-Host " 6. Epic Games		23. Office 365"
    Write-Host " 7. Escape From Tarkov	24. Portmaster"
    Write-Host " 8. GOG launcher	25. PowerShell 7"
    Write-Host " 9. Google Chrome	26. Process Explorer"
    Write-Host "10. League Of Legends	27. StartXBack"
    Write-Host "11. Notepad ++		28. VLC media player"
    Write-Host "12. OBS Studio		29. Winget"
	Write-Host "13. Roblox		30. .NET Freamework 3.5"
    Write-Host "14. Rockstar Games	31. Edge WebView2"
    Write-Host "15. Steam		32. Firefox"
    Write-Host "16. Ubisoft Connect	33. Thorium AVX2"
    Write-Host "17. Valorant		34. Mullvad Browser"
	}

while ($true) {
    show-menu
    $choices = Read-Host " "
    if ($choices -match '^\d+(,\d+)*$') {
        foreach ($choice in $choices.Split(',')) {
            switch ($choice) {
				1 {
					Clear-Host
					# temp cleanup
                    gci -Path "C:\Windows\Temp" *.* -Recurse | ri -Force -Recurse -ea 0;gci -Path $env:TEMP *.* -Recurse | ri -Force -Recurse -ea 0	
					exit
				}
				2 {
					
					Clear-Host
					Write-Host 'Installing: 7Zip . . .'
					# download 7zip
					$a=(irm https://api.github.com/repos/ip7z/7zip/releases/latest).assets|? name -like '*x64.exe'|select -f 1;$exe=Join-Path $env:TEMP $a.name; Get-FileFromWeb $a.browser_download_url -File $exe
					# install 7zip
					saps $exe '/S' -Wait;$fm="$env:ProgramFiles\7-Zip\7zFM.exe";if(Test-Path $fm){
					  '7z','xz','bzip2','gzip','tar','zip','wim','apfs','ar','arj','cab','chm','cpio','cramfs','dmg','ext','fat','gpt','hfs','ihex','lzh','lzma','mbr','nsis','ntfs','qcow2',
					  'rar','rpm','squashfs','udf','uefi','vdi','vhd','vhdx','vmdk','xar','z' | % {cmd /c "assoc .$_=7zFM.exe" >$null};cmd /c "ftype 7zFM.exe=`"$fm`" `"%1`" `"%*`"" >$null
					}; $p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; if(Test-Path "$p\7-Zip\7-Zip File Manager.lnk"){
						ren "$p\7-Zip\7-Zip File Manager.lnk" '7-Zip.lnk' -Force -ea 0; mv  "$p\7-Zip\7-Zip.lnk" $p -Force -ea 0; ri  "$p\7-Zip" -Recurse -Force -ea 0
					}
					show-menu
					
				}
				3 {
					
					Clear-Host
					Write-Host 'Installing: Battle.net . . .'
					# download battle.net
					Get-FileFromWeb "https://downloader.battle.net/download/getInstaller?os=win&installer=Battle.net-Setup.exe" "$env:TEMP\Battle.net-Setup.exe"
					# install battle.net
					saps "$env:TEMP\Battle.net-Setup.exe" '--lang=enUS --installpath="C:\Program Files (x86)\Battle.net"'					
					# stop battle.net running
					while(-not(gps Battle.net -ea 0)){sleep -m 200}; kill -Name Battle.net,Agent -Force -ea 0
					# create battle.net shortcut
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs";if(!(Test-Path "$p\Battle.net.lnk")){mv "$p\Battle.net\Battle.net.lnk" $p -Force -ea 0;ri "$p\Battle.net" -Recurse -Force -ea 0}
					$WshShell = New-Object -comObject WScript.Shell
					$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Battle.net.lnk")
					$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Battle.net\Battle.net Launcher.exe"
					$Shortcut.Save()
					show-menu
					
				}
				4 {
					
					Clear-Host
					$progresspreference = 'silentlycontinue'
					Write-Host 'Installing: WebCord . . .'
					# download & install webcord
					$exe="$env:TEMP\webcord-squirrel-x64.exe"; Get-FileFromWeb "https://github.com/SpacingBat3/WebCord/releases/latest/download/webcord-squirrel-x64.exe" $exe; saps $exe -Wait
					# find executable
					$paths="$env:LOCALAPPDATA\Programs\WebCord\app-*\WebCord.exe","$env:LOCALAPPDATA\webcord\webcord.exe";$exe=(gci $paths -ea 0|select -f 1).FullName
					if($exe){
					  $icon=(Split-Path $exe)+'\discord.ico'; iwr 'https://raw.githubusercontent.com/sounderrun/old-discord-icon/main/Discord.ico' -o $icon; $sh=New-Object -ComObject WScript.Shell
					  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Discord.lnk","$env:PUBLIC\Desktop\Discord.lnk"|%{$sc=$sh.CreateShortcut($_);$sc.TargetPath=$exe;$sc.WorkingDirectory=(Split-Path $exe);$sc.IconLocation=$icon;$sc.Save()}
					}
					show-menu
					
				}
				5 {
					
					Clear-Host
					Write-Host "Installing: Electronic Arts . . ."
					# download & install electronic arts
					$exe = "$env:TEMP\EAappInstaller.exe"; Get-FileFromWeb "https://origin-a.akamaihd.net/EA-Desktop-Client-Download/installer-releases/EAappInstaller.exe" $exe; & $exe "/S" -Wait								
					# stop ea running
					while(!(gps EADesktop -ea 0)){sleep -m 200}; kill -Name EADesktop,EABackgroundService -Force -ea 0
					# create ea shortcut
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\EA\EA.lnk" $p -Force -ea 0; ri "$p\EA" -Recurse -Force -ea 0
					show-menu
					
				}
				6 {
					
					Clear-Host
					Write-Host "Installing: Epic Games . . ."
					# download & install epic games
					$msi = "$env:TEMP\EpicGamesLauncherInstaller.msi"; Get-FileFromWeb "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi" $msi; saps -wait $msi "/q"
					Clear-Host
					Write-Host "Uninstalling: Epic Online Services . . ."
					# uninstall epic online services
					cmd /c "msiexec.exe /x {57A956AB-4BCC-45C6-9B40-957E4E125568} /q >nul 2>&1"
					show-menu
					
				}
				7 {
					
					Clear-Host
					Write-Host "Installing: Escape From Tarkov . . ."
					# download & install escape from tarkov
					$exe = "$env:TEMP\BsgLauncher.exe"; Get-FileFromWeb "https://prod.escapefromtarkov.com/launcher/download" $exe; saps $exe "/verysilent" -Wait
					# create battlestate shortcut
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs";$d="$env:PUBLIC\Desktop";$lnk="$p\BattleState Games Launcher.lnk";mv "$p\BattleState Games\BattleState Games Launcher.lnk" $p -Force -ea 0
					cp $lnk $d -Force -ea 0;ri "$p\BattleState Games" -Recurse -Force -ea 0
					show-menu
					
				}
				8 {
					
					Clear-Host
					Write-Host "Installing: GOG launcher . . ."
					# download & install gog launcher
					$web="$env:TEMP\GOG_Galaxy_2.0.exe"; $dst="$env:TEMP\GOG_Setup_Copy"; Get-FileFromWeb "https://webinstallers.gog-statics.com/download/GOG_Galaxy_2.0.exe" $web; saps $web; while(!(gps GalaxySetup -ea 0)){sleep -m 100}
					$p = gps GalaxySetup|select -f 1; $src = Split-Path $p.Path -Parent; ri $dst -Recurse -Force -ea 0;cp $src $dst -Recurse -Force; kill -Name GalaxyInstaller,GalaxySetup -Force -ea 0; saps "$dst\GalaxySetup.exe" "/VERYSILENT" -Wait
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\GOG.com\GOG GALAXY\GOG GALAXY.lnk" $p -Force -ea 0; ri "$p\GOG.com" -Recurse -Force -ea 0
					# disable gog launcher startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*Galaxy*"} | % {
						sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0
					}
					show-menu
					
				}
				9 {
					
					Clear-Host
					Write-Host "Installing: Google Chrome . . ."
					# download & install google chrome
					$exe = "$env:TEMP\chrome_installer.exe"; Get-FileFromWeb 'https://dl.google.com/chrome/install/latest/chrome_installer.exe' $exe; saps $exe "/silent", "/install" -Wait				
					# create config for google chrome
					# create reg file
					$MultilineComment = @'
Windows Registry Editor Version 5.00	

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome]
"AlternateErrorPagesEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"DefaultBrowserSettingEnabled"=dword:00000000
"DefaultGeolocationSetting"=dword:00000002
"DefaultLocalFontsSetting"=dword:00000002
"DefaultNotificationsSetting"=dword:00000002
"DefaultSensorsSetting"=dword:00000002
"DefaultSerialGuardSetting"=dword:00000002
"HardwareAccelerationModeEnabled"=dword:00000000
"HighEfficiencyModeEnabled"=dword:00000000
"NetworkPredictionOptions"=dword:00000002
"PasswordDismissCompromisedAlertEnabled"=dword:00000000
"PasswordLeakDetectionEnabled"=dword:00000000
"PasswordManagerEnabled"=dword:00000000
"PasswordProtectionWarningTrigger"=dword:00000000
"PasswordSharingEnabled"=dword:00000000
"PolicyAtomicGroupsEnabled"=dword:00000001
"RelatedWebsiteSetsEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"UserFeedbackAllowed"=dword:00000000
"WebRtcEventLogCollectionAllowed"=dword:00000000
"AIModeSettings"=dword:00000001
"AbusiveExperienceInterventionEnforce"=dword:00000000
"AccessCodeCastEnabled"=dword:00000000
"AccessibilityImageLabelsEnabled"=dword:00000000
"AdvancedProtectionAllowed"=dword:00000000
"AllowBackForwardCacheForCacheControlNoStorePageEnabled"=dword:00000001
"AllowDeletingBrowserHistory"=dword:00000001
"AllowDinosaurEasterEgg"=dword:00000000
"AllowWebAuthnWithBrokenTlsCerts"=dword:00000000
"AlwaysOpenPdfExternally"=dword:00000001
"AudioProcessHighPriorityEnabled"=dword:00000001
"AudioSandboxEnabled"=dword:00000001
"AmbientAuthenticationInPrivateModesEnabled"=dword:00000000
"AutoFillEnabled"=dword:00000000
"AutofillAddressEnabled"=dword:00000000
"AutofillPredictionSettings"=dword:00000000
"AutomatedPasswordChangeSettings"=dword:00000000
"BoundSessionCredentialsEnabled"=dword:00000000
"BrowserNetworkTimeQueriesEnabled"=dword:00000000
"BasicAuthOverHttpEnabled"=dword:00000000
"BlockExternalExtensions"=dword:00000001
"BlockThirdPartyCookies"=dword:00000001
"BatterySaverModeAvailability"=dword:00000000
"BrowserAddPersonEnabled"=dword:00000000
"BrowserGuestModeEnforced"=dword:00000000
"BrowserLabsEnabled"=dword:00000000
"BrowserSwitcherEnabled"=dword:00000000
"BuiltInAIAPIsEnabled"=dword:00000000
"CACertificateManagementAllowed"=dword:00000000
"CAPlatformIntegrationEnabled"=dword:00000000
"CacheEncryptionEnabled"=dword:00000001
"ChromeForTestingAllowed"=dword:00000000
"ChromeVariations"=dword:00000000
"ClearWindowNameForNewBrowsingContextGroup"=dword:00000001
"ClickToCallEnabled"=dword:00000000
"CloudAPAuthEnabled"=dword:00000000
"CloudPrintProxyEnabled"=dword:00000000
"ComponentUpdatesEnabled"=dword:00000001
"CompressionDictionaryTransportEnabled"=dword:00000001
"DNSInterceptionChecksEnabled"=dword:00000001
"MetricsReportingEnabled"=dword:00000000
"DomainReliabilityAllowed"=dword:00000000
"FeedbackSurveysEnabled"=dword:00000000
"HttpsOnlyMode"="force_enabled"
"HttpsUpgradesEnabled"=dword:00000001
"NetworkServiceSandboxEnabled"=dword:00000001
"InsecureFormsWarningsEnabled"=dword:00000001
"OriginAgentClusterDefaultEnabled"=dword:00000001
"GeminiSettings"=dword:00000000
"HelpMeWriteSettings"=dword:00000000
"HideWebStoreIcon"=dword:00000001
"LensDesktopNTPSearchEnabled"=dword:00000000
"LensOverlaySettings"=dword:00000000
"LiveCaptionEnabled"=dword:00000000
"MediaRecommendationsEnabled"=dword:00000000
"NTPCardsVisible"=dword:00000000
"NTPCustomBackgroundEnabled"=dword:00000000
"NTPShortcuts"=dword:00000000
"HistoryClustersVisible"=dword:00000000
"GoogleSearchSidePanelEnabled"=dword:00000000
"EnableMediaRouter"=dword:00000000
"DesktopSharingHubEnabled"=dword:00000000
"PaymentMethodQueryEnabled"=dword:00000000
"PdfAnnotationsEnabled"=dword:00000000
"PasswordManagerPasskeysEnabled"=dword:00000000
"UrlKeyedMetricsAllowed"=dword:00000000
"ReportExtensionsAndPluginsData"=dword:00000000
"ReportMachineIDData"=dword:00000000
"ReportPolicyData"=dword:00000000
"ReportUserIDData"=dword:00000000
"ReportVersionData"=dword:00000000
"WebRtcTextLogCollectionAllowed"=dword:00000000
"PrivacySandboxAdMeasurementEnabled"=dword:00000000
"PrivacySandboxAdTopicsEnabled"=dword:00000000
"PrivacySandboxFingerprintingProtectionEnabled"=dword:00000000
"PrivacySandboxIpProtectionEnabled"=dword:00000000
"PrivacySandboxPromptEnabled"=dword:00000000
"PrivacySandboxSiteEnabledAdsEnabled"=dword:00000000
"ScrollToTextFragmentEnabled"=dword:00000000
"SearchSuggestEnabled"=dword:00000000
"WebRtcPostQuantumKeyAgreement"=dword:00000001
"SandboxExternalProtocolBlocked"=dword:00000001
"SitePerProcess"=dword:00000001
"RendererAppContainerEnabled"=dword:00000001
"RestrictCoreSharingOnRenderer"=dword:00000001
"SSLErrorOverrideAllowed"=dword:00000000
"RemoteDebuggingAllowed"=dword:00000000
"QuicAllowed"=dword:00000001
"PrefetchWithServiceWorkerEnabled"=dword:00000001
"ServiceWorkerAutoPreloadEnabled"=dword:00000001
"TLS13EarlyDataEnabled"=dword:00000001
"WebAudioOutputBufferingEnabled"=dword:00000001
"WindowOcclusionEnabled"=dword:00000001
"ReduceAcceptLanguageEnabled"=dword:00000001
"QRCodeGeneratorEnabled"=dword:00000000
"PromotionsEnabled"=dword:00000000
"SharedClipboardEnabled"=dword:00000000
"ShowAppsShortcutInBookmarkBar"=dword:00000000
"ShowCastIconInToolbar"=dword:00000000
"ShowCastSessionsStartedByOtherDevices"=dword:00000000
"ShowFullUrlsInAddressBar"=dword:00000000
"ShowHomeButton"=dword:00000000
"SideSearchEnabled"=dword:00000000
"TabCompareSettings"=dword:00000000
"UiAutomationProviderEnabled"=dword:00000000
"UrlKeyedAnonymizedDataCollectionEnabled"=dword:00000000
"UserAgentReduction"=dword:00000000
"TranslatorAPIAllowed"=dword:00000000
"WebRtcIPHandling"="disable_non_proxied_udp"
"SigninAllowed"=dword:00000000
"SigninInterceptionEnabled"=dword:00000000
"VideoCaptureAllowed"=dword:00000000 ; camera access
"WPADQuickCheckEnabled"=dword:00000000
"ScreenCaptureAllowed"=dword:00000000 ; screen sharing
"SavingBrowserHistoryDisabled"=dword:00000001
"SyncTypesListDisabled"=dword:00000001
"SafeBrowsingDeepScanningEnabled"=dword:00000000
"SafeBrowsingExtendedReportingEnabled"=dword:00000000
"SafeBrowsingForTrustedSourcesEnabled"=dword:00000000
"SafeBrowsingProtectionLevel"=dword:00000000
"SafeBrowsingProxiedRealTimeChecksAllowed"=dword:00000000
"SafeBrowsingSurveysEnabled"=dword:00000000
"SafeSitesFilterBehavior"=dword:00000000
"ForceSafeSearch"=dword:00000000
"DisableSafeBrowsingProceedAnyway"=dword:00000000
"ForceGoogleSafeSearch"=dword:00000000
"ForceYouTubeRestrict"=dword:00000000
"SharedClipboardEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SpellCheckServiceEnabled"=dword:00000000
"SpellcheckEnabled"=dword:00000000
"WebRtcLocalIpsAllowedUrls"=""
"WebRtcUdpPortRange"=""
"IntensiveWakeUpThrottlingEnabled"=dword:00000000
"NTPMiddleSlotAnnouncementVisible"=dword:00000000
"LensRegionSearchEnabled"=dword:00000000
"HomepageIsNewTabPage"=dword:00000001
"HomepageLocation"="https://search.brave.com/"
"DefaultPopupsSetting"=dword:00000002
"PrintingEnabled"=dword:00000000
"SuppressUnsupportedOSWarning"=dword:00000001
"DnsOverHttpsMode"="off"
"HistorySearchSettings"=dword:00000000
"AutoplayAllowed"=dword:00000000
"DefaultSearchProviderEnabled"=dword:00000001
"DefaultSearchProviderKeyword"="@brave"
"DefaultSearchProviderName"="Brave"
"DefaultSearchProviderSearchURL"="https://search.brave.com/search?q={searchTerms}"
"DefaultSearchProviderSuggestURL"="https://search.brave.com/api/suggest?q={searchTerms}"
"DefaultSearchProviderEncodings"="UTF-8"
"DefaultSearchProviderAlternateURLs"=""

[HKEY_LOCAL_MACHINE\Software\Policies\Thorium\AutoplayAllowlist]
"1"="https://www.youtube.com"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF] 
"EnrollmentState"=dword:00000001 
"EnrollmentType"=dword:00000000 
"IsFederated"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF]
"Flags"=dword:00d6fb7f
"AcctUId"="0x000000000000000000000000000000000000000000000000000000000000000000000000"
"RoamingCount"=dword:00000000
"SslClientCertReference"="MY;User;0000000000000000000000000000000000000000"
"ProtoVer"="1.2"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist]
"1"="cjpalhdlnbpafiamejdnhcphjbkeiagm" ; ublock origin
"2"="cafckninonjkogajnihihlnnimmkndgf" ; Disable HTML5 Autoplay

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem]
"Start"=dword:00000003
'@; Set-Content -Path "$env:TEMP\chrome.reg" -Value $MultilineComment -Force; reg import "$env:TEMP\chrome.reg"	2> $null
					
					# create google chrome shortcuts
					$p = @("${env:ProgramFiles}\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe","${env:LOCALAPPDATA}\Google\Chrome\Application\chrome.exe")
					$chrome = $p | ? { Test-Path $_ } | select -f 1
					ri "$env:USERPROFILE\Desktop\Google Chrome.lnk" -Force -ea 0; ri "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" -Force -ea 0; ri "$env:PUBLIC\Desktop\Google Chrome.lnk" -Force -ea 0				
					& {
						$WshShell = New-Object -ComObject WScript.Shell
						$Shortcut1 = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Google Chrome.lnk")
						$Shortcut1.TargetPath = $chrome
						$Shortcut1.Arguments = '--disable-features=ExtensionManifestV2Unsupported,ExtensionManifestV2Disabled'
						$Shortcut1.Save()
						
						$Shortcut2 = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk")
						$Shortcut2.TargetPath = $chrome
						$Shortcut2.Arguments = '--disable-features=ExtensionManifestV2Unsupported,ExtensionManifestV2Disabled'
						$Shortcut2.Save()
					} *>$null
					# disable google chrome services
					Get-Service | ? Name -match 'Google' | % {Set-Service $_.Name -StartupType Manual -ea 0; Stop-Service $_.Name -Force -ea 0}
					# disable google chrome tasks
					ri "$env:WINDIR\System32\Tasks\GoogleUserPEH" -Recurse -Force -ea 0; Get-ScheduledTask | ? { $_.TaskName -like "*Google*" } | % {Disable-ScheduledTask -TaskName $_.TaskName -ea 0}
					Get-ScheduledTask -ea 0 | ? { $_.TaskPath -match '\\Google' -or $_.TaskName -match 'Google(Update|Updater)' } | % { Disable-ScheduledTask -InputObject $_ -ea 0 }
					# disable google chrome startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*google*"} | % {
						Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0
					}
					# disable google chrome logon
					cmd /c "reg delete `"HKLM\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}`" /f >nul 2>&1"
					show-menu
					
				}
				10 {
					
					Clear-Host
					Write-Host "Installing: League Of Legends . . ."
					# download & install league of legends
					Get-FileFromWeb "https://lol.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.na.exe" "$env:TEMP\Install League of Legends na.exe"; saps "$env:TEMP\Install League of Legends na.exe"
					show-menu
					
				}
				11 {

					Clear-Host
					Write-Host "Installing: Notepad ++ . . ."
					# download notepad ++
					$release = irm "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest" -Headers @{ 'User-Agent'='PowerShell' }; $asset = $release.assets | ? { $_.name -like '*Installer*.x64.exe' } | select -f 1
					if ($asset) {$exe = Join-Path $env:TEMP $asset.name; Get-FileFromWeb $asset.browser_download_url $exe}
					# install notepad ++
					saps -wait $exe "/S"				
					# create config for notepad ++
					$MultilineComment = @"
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifInHiddenFolder="no" fifProjectPanel1="no" fifProjectPanel2="no" fifProjectPanel3="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="1" transparency="150" dotMatchesNewline="no" isSearch2ButtonsMode="no" regexBackward4PowerUser="no" bookmarkLine="no" purge="no">
        <Filter name="" />
        <Find name="" />
        <Find name="sharpening" />
        <Find name="sharpen" />
        <Find name="sharp" />
        <Replace name="" />
    </FindHistory>
    <History nbMaxFile="0" inSubMenu="no" customLength="-1" />
    <ProjectPanels>
        <ProjectPanel id="0" workSpaceFile="" />
        <ProjectPanel id="1" workSpaceFile="" />
        <ProjectPanel id="2" workSpaceFile="" />
    </ProjectPanels>
    <ColumnEditor choice="number">
        <text content="" />
        <number initial="-1" increase="-1" repeat="-1" formatChoice="dec" leadingChoice="none" />
    </ColumnEditor>
    <GUIConfigs>
        <GUIConfig name="ToolBar" visible="yes">small</GUIConfig>
        <GUIConfig name="StatusBar">show</GUIConfig>
        <GUIConfig name="TabBar" dragAndDrop="yes" drawTopBar="yes" drawInactiveTab="yes" reduce="yes" closeButton="yes" doubleClick2Close="no" vertical="no" multiLine="no" hide="no" quitOnEmpty="no" iconSetNumber="0" />
        <GUIConfig name="ScintillaViewsSplitter">vertical</GUIConfig>
        <GUIConfig name="UserDefineDlg" position="undocked">hide</GUIConfig>
        <GUIConfig name="TabSetting" replaceBySpace="no" size="4" />
        <GUIConfig name="AppPosition" x="148" y="77" width="1234" height="773" isMaximized="no" />
        <GUIConfig name="FindWindowPosition" left="460" top="338" right="1074" bottom="702" isLessModeOn="no" />
        <GUIConfig name="FinderConfig" wrappedLines="no" purgeBeforeEverySearch="no" showOnlyOneEntryPerFoundLine="yes" />
        <GUIConfig name="noUpdate" intervalDays="15" nextUpdateDate="20250326">yes</GUIConfig>
        <GUIConfig name="Auto-detection">yes</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="TrayIcon">no</GUIConfig>
        <GUIConfig name="MaintainIndent">yes</GUIConfig>
        <GUIConfig name="TagsMatchHighLight" TagAttrHighLight="yes" HighLightNonHtmlZone="no">yes</GUIConfig>
        <GUIConfig name="RememberLastSession">yes</GUIConfig>
        <GUIConfig name="KeepSessionAbsentFileEntries">no</GUIConfig>
        <GUIConfig name="DetectEncoding">yes</GUIConfig>
        <GUIConfig name="SaveAllConfirm">yes</GUIConfig>
        <GUIConfig name="NewDocDefaultSettings" format="0" encoding="4" lang="0" codepage="-1" openAnsiAsUTF8="yes" addNewDocumentOnStartup="no" />
        <GUIConfig name="langsExcluded" gr0="0" gr1="0" gr2="0" gr3="0" gr4="0" gr5="0" gr6="0" gr7="0" gr8="0" gr9="0" gr10="0" gr11="0" gr12="0" langMenuCompact="yes" />
        <GUIConfig name="Print" lineNumber="yes" printOption="3" headerLeft="" headerMiddle="" headerRight="" footerLeft="" footerMiddle="" footerRight="" headerFontName="" headerFontStyle="0" headerFontSize="0" footerFontName="" footerFontStyle="0" footerFontSize="0" margeLeft="0" margeRight="0" margeTop="0" margeBottom="0" />
        <GUIConfig name="Backup" action="0" useCustumDir="no" dir="" isSnapshotMode="no" snapshotBackupTiming="7000" />
        <GUIConfig name="TaskList">yes</GUIConfig>
        <GUIConfig name="MRU">yes</GUIConfig>
        <GUIConfig name="URL">0</GUIConfig>
        <GUIConfig name="uriCustomizedSchemes">svn:// cvs:// git:// imap:// irc:// irc6:// ircs:// ldap:// ldaps:// news: telnet:// gopher:// ssh:// sftp:// smb:// skype: snmp:// spotify: steam:// sms: slack:// chrome:// bitcoin:</GUIConfig>
        <GUIConfig name="globalOverride" fg="no" bg="no" font="no" fontSize="no" bold="no" italic="no" underline="no" />
        <GUIConfig name="auto-completion" autoCAction="3" triggerFromNbChar="1" autoCIgnoreNumbers="yes" insertSelectedItemUseENTER="yes" insertSelectedItemUseTAB="yes" autoCBrief="no" funcParams="yes" />
        <GUIConfig name="auto-insert" parentheses="no" brackets="no" curlyBrackets="no" quotes="no" doubleQuotes="no" htmlXmlTag="no" />
        <GUIConfig name="sessionExt"></GUIConfig>
        <GUIConfig name="workspaceExt"></GUIConfig>
        <GUIConfig name="MenuBar">show</GUIConfig>
        <GUIConfig name="Caret" width="1" blinkRate="600" />
        <GUIConfig name="openSaveDir" value="0" defaultDirPath="" lastUsedDirPath="" />
        <GUIConfig name="titleBar" short="no" />
        <GUIConfig name="insertDateTime" customizedFormat="yyyy-MM-dd HH:mm:ss" reverseDefaultOrder="no" />
        <GUIConfig name="wordCharList" useDefault="yes" charsAdded="" />
        <GUIConfig name="delimiterSelection" leftmostDelimiter="40" rightmostDelimiter="41" delimiterSelectionOnEntireDocument="no" />
        <GUIConfig name="largeFileRestriction" fileSizeMB="200" isEnabled="yes" allowAutoCompletion="no" allowBraceMatch="no" allowSmartHilite="no" allowClickableLink="no" deactivateWordWrap="yes" suppress2GBWarning="no" />
        <GUIConfig name="multiInst" setting="0" clipboardHistory="no" documentList="no" characterPanel="no" folderAsWorkspace="no" projectPanels="no" documentMap="no" fuctionList="no" pluginPanels="no" />
        <GUIConfig name="MISC" fileSwitcherWithoutExtColumn="no" fileSwitcherExtWidth="50" fileSwitcherWithoutPathColumn="yes" fileSwitcherPathWidth="50" fileSwitcherNoGroups="no" backSlashIsEscapeCharacterForSql="yes" writeTechnologyEngine="1" isFolderDroppedOpenFiles="no" docPeekOnTab="no" docPeekOnMap="no" sortFunctionList="no" saveDlgExtFilterToAllTypes="no" muteSounds="no" enableFoldCmdToggable="no" hideMenuRightShortcuts="no" />
        <GUIConfig name="Searching" monospacedFontFindDlg="no" fillFindFieldWithSelected="yes" fillFindFieldSelectCaret="yes" findDlgAlwaysVisible="no" confirmReplaceInAllOpenDocs="yes" replaceStopsWithoutFindingNext="no" inSelectionAutocheckThreshold="1024" />
        <GUIConfig name="searchEngine" searchEngineChoice="2" searchEngineCustom="" />
        <GUIConfig name="MarkAll" matchCase="no" wholeWordOnly="yes" />
        <GUIConfig name="SmartHighLight" matchCase="no" wholeWordOnly="yes" useFindSettings="no" onAnotherView="no">yes</GUIConfig>
        <GUIConfig name="DarkMode" enable="yes" colorTone="0" customColorTop="2105376" customColorMenuHotTrack="4210752" customColorActive="4210752" customColorMain="2105376" customColorError="176" customColorText="14737632" customColorDarkText="12632256" customColorDisabledText="8421504" customColorLinkText="65535" customColorEdge="6579300" customColorHotEdge="10197915" customColorDisabledEdge="4737096" enableWindowsMode="no" darkThemeName="DarkModeDefault.xml" darkToolBarIconSet="0" darkTabIconSet="2" darkTabUseTheme="no" lightThemeName="" lightToolBarIconSet="4" lightTabIconSet="0" lightTabUseTheme="yes" />
        <GUIConfig name="ScintillaPrimaryView" lineNumberMargin="show" lineNumberDynamicWidth="yes" bookMarkMargin="show" indentGuideLine="show" folderMarkStyle="box" isChangeHistoryEnabled="1" lineWrapMethod="aligned" currentLineIndicator="1" currentLineFrameWidth="1" virtualSpace="no" scrollBeyondLastLine="yes" rightClickKeepsSelection="no" disableAdvancedScrolling="no" wrapSymbolShow="hide" Wrap="no" borderEdge="yes" isEdgeBgMode="no" edgeMultiColumnPos="" zoom="4" zoom2="0" whiteSpaceShow="hide" eolShow="hide" eolMode="1" npcShow="hide" npcMode="1" npcCustomColor="no" npcIncludeCcUniEOL="no" npcNoInputC0="yes" ccShow="yes" borderWidth="2" smoothFont="no" paddingLeft="0" paddingRight="0" distractionFreeDivPart="4" lineCopyCutWithoutSelection="yes" multiSelection="yes" columnSel2MultiEdit="yes" />
        <GUIConfig name="DockingManager" leftWidth="200" rightWidth="200" topHeight="200" bottomHeight="200">
            <ActiveTabs cont="0" activeTab="-1" />
            <ActiveTabs cont="1" activeTab="-1" />
            <ActiveTabs cont="2" activeTab="-1" />
            <ActiveTabs cont="3" activeTab="-1" />
        </GUIConfig>
    </GUIConfigs>
</NotepadPlus>
"@; sc "$env:AppData\Notepad++\config.xml" -Value $MultilineComment -Force

					$MultilineComment = @"
Windows Registry Editor Version 5.00

; Created by: Shawn Brink
; http://www.tenforums.com
; Tutorial: http://www.tenforums.com/tutorials/8703-default-file-type-associations-restore-windows-10-a.html
; enhanced by WillingMost7

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
@="C:\\Program Files\\Notepad++\\notepad++.exe,0"	
	
[HKEY_CLASSES_ROOT\txtfile\shell\open\command]	
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""	
	
[-HKEY_CLASSES_ROOT\txtfile\shell\print]	
	
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

[HKEY_CLASSES_ROOT\regfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\regfile\shell\print]	

[HKEY_CLASSES_ROOT\batfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\batfile\shell\print]

[HKEY_CLASSES_ROOT\VBSFile\Shell\Edit\Command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\VBSFile\Shell\Print]

[HKEY_CLASSES_ROOT\cmdfile\shell\edit\command]
@="\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"%1\""

[-HKEY_CLASSES_ROOT\cmdfile\shell\print]

[-HKEY_CLASSES_ROOT\xbox-tcui]
[-HKEY_CLASSES_ROOT\xboxmusic]
"@; $reg = "$env:TEMP\Notepad.reg"; sc $reg -Value $MultilineComment -Force; reg import $reg *>$null
					show-menu
					
				}
				12 {
					
					Clear-Host
					Write-Host "Installing: OBS Studio . . ."
					# download & install obs studio
					$release = irm https://api.github.com/repos/obsproject/obs-studio/releases/latest -Headers @{ 'User-Agent'='PowerShell' }; $asset = $release.assets | ? { $_.name -like '*x64-Installer.exe' } | select -f 1
					if ($asset) {$exe = Join-Path $env:TEMP $asset.name;Get-FileFromWeb $asset.browser_download_url -File $exe}; saps $exe "/S" -wait
					show-menu
					
				}
				13 {
					
					Clear-Host
					Write-Host "Installing: Roblox . . ."
					# download roblox
					Get-FileFromWeb -URL "https://www.roblox.com/download/client?os=win" -File "$env:TEMP\Roblox.exe"
					# install roblox
					Start-Process "$env:TEMP\Roblox.exe" "/S" -wait
					show-menu
					
				}
				14 {
					
					Clear-Host
					Write-Host "Installing: Rockstar Games . . ."
					# download rockstar games
					Get-FileFromWeb -URL "https://gamedownloads.rockstargames.com/public/installer/Rockstar-Games-Launcher.exe" -File "$env:TEMP\Rockstar Games.exe"
					# install rockstar games
					Start-Process "$env:TEMP\Rockstar Games.exe" "/S" -wait
					show-menu
					
				}
				15 {
					
					Clear-Host
					Write-Host "Installing: Steam . . ."
					# download & install steam
					$exe = "$env:TEMP\SteamSetup.exe"; Get-FileFromWeb "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe" $exe; saps $exe '/S' -Wait
					# update steam
					saps "${env:ProgramFiles(x86)}\Steam\steam.exe"
					# delete steam shortcuts
					ri $env:PUBLIC\Desktop\Steam.lnk -Force -ea 0; ri "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Steam" -Recurse -Force -ea 0
					# create reg file
					$MultilineComment = @"
Windows Registry Editor Version 5.00

; This reg file implements all the changes can be done on Steam by regedit to achieve better gaming performance. By imribiy#0001

[HKEY_CURRENT_USER\SOFTWARE\Valve\Steam]
"SmoothScrollWebViews"=dword:00000000
"DWriteEnable"=dword:00000000
"StartupMode"=dword:00000000
"H264HWAccel"=dword:00000000
"DPIScaling"=dword:00000000
"GPUAccelWebViews"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Steam"=-
"@; Set-Content -Path "$env:TEMP\Steam.reg" -Value $MultilineComment -Force -ea 0; reg import "$env:TEMP\Steam.reg" *>$null
					
					while (!(Get-Process -Name 'steamwebhelper' -ea 0)) {sleep -m 200}; cls; if (-not (test-path "$STEAM\steam.exe") -or -not (test-path "$STEAM\steamapps\libraryfolders.vdf")) {
						# message
						Write-Host 'Sign into Steam to generate config location'
						do {$STEAM = (gp HKCU:\SOFTWARE\Valve\Steam -ea 0).SteamPath; sleep -m 200} until ($STEAM -and (Test-Path "$STEAM\steam.exe") -and (Test-Path "$STEAM\steamapps\libraryfolders.vdf"))
					}
						$STEAM = resolve-path (gp "HKCU:\SOFTWARE\Valve\Steam" -ea 0).SteamPath; if ((Test-Path "$STEAM\steam.exe") -and (Test-Path "$STEAM\steamapps\libraryfolders.vdf")) {
						# create batch file
						$batchCode = @'
@(set "0=%~f0" '& set 1=%*) & powershell -nop -c "type -lit $env:0 | out-string | powershell -nop -c -" & exit /b ');.{

" Steam_min : always restarts in SmallMode with reduced ram and cpu usage when idle - AveYo, 2025.08.23 "

$FriendsSignIn = 0					
$FriendsAnimed = 0					
$ShowGameIcons = 0					
$NoJoystick    = 1					
$NoShaders     = 1					
$NoGPU         = 1					

##  AveYo: steam launch options
$QUICK = "-dev -silent -quicklogin -forceservice -vrdisable -oldtraymenu -nofriendsui -no-dwrite -nointro -nobigpicture -nofasthtml -nocrashmonitor -no-shared-textures -disablehighdpi -single_core -disable-winh264 -noverifyfiles -nobootstrapupdate -skipinitialbootstrap -norepairfiles " + ("","-nojoy ")[$NoJoystick -eq 1]
$QUICK+= ("","-noshaders ")[$NoShaders -eq 1] + ("","-nodirectcomp -cef-disable-gpu -cef-disable-gpu-sandbox -cef-disable-d3d11 -cef-force-32bit ")[$NoGPU -eq 1]
$QUICK+= "-cef-single-process -cef-in-process-gpu -cef-disable-sandbox -no-cef-sandbox -cef-disable-breakpad -cef-allow-browser-underlay -cef-delaypageload -cef-force-occlusion -cef-disable-hang-timeouts -console -overridepackageurl steam://open/minigameslist"

## AveYo: abort if steam not found
$STEAM = resolve-path (gp "HKCU:\SOFTWARE\Valve\Steam" -ea 0).SteamPath
if (-not (test-path "$STEAM\steam.exe") -or -not (test-path "$STEAM\steamapps\libraryfolders.vdf")) {
  write-host " Steam not found! " -fore Black -back Yellow; sleep 7; return
}

## AveYo: close steam gracefully if already running
$focus = $false
if ((gp "HKCU:\Software\Valve\Steam\ActiveProcess" -ea 0).pid -gt 0 -and (gps -name steamwebhelper -ea 0)) {
  start "$STEAM\Steam.exe" -args '-ifrunning -silent -shutdown +quit now' -wait; $focus = $true
}
## AveYo: force close steam if needed
while ((gps -name steamwebhelper -ea 0) -or (gps -name steam -ea 0)) {
  kill -name 'steamwebhelper','steam' -force -ea 0; del "$STEAM\.crash" -force -ea 0; $focus = $true; sleep -m 250
}
if ($focus) { $QUICK+= " -foreground" }

##  AveYo: lean and mean helper functions to process steam vdf files
function vdf_parse {
  param([string[]]$vdf, [ref]$line = ([ref]0), [string]$re = '\A\s*("(?<k>[^"]+)"|(?<b>[\{\}]))\s*(?<v>"(?:\\"|[^"])*")?\Z')
  $obj = new-object System.Collections.Specialized.OrderedDictionary # ps 3.0: [ordered]@{}
  while ($line.Value -lt $vdf.count) {
    if ($vdf[$line.Value] -match $re) {
      if ($matches.k) { $key = $matches.k }
      if ($matches.v) { $obj[$key] = $matches.v }
      elseif ($matches.b -eq '{') { $line.Value++; $obj[$key] = vdf_parse -vdf $vdf -line $line }
      elseif ($matches.b -eq '}') { break }
    }
    $line.Value++
  }
  return $obj
}
function vdf_print {
  param($vdf, [ref]$indent = ([ref]0))
  if ($vdf -isnot [System.Collections.Specialized.OrderedDictionary]) {return}
  foreach ($key in $vdf.Keys) {
    if ($vdf[$key] -is [System.Collections.Specialized.OrderedDictionary]) {
      $tabs = "${\t}" * $indent.Value
      write-output "$tabs""$key""${\n}$tabs{${\n}"
      $indent.Value++; vdf_print -vdf $vdf[$key] -indent $indent; $indent.Value--
      write-output "$tabs}${\n}"
    } else {
      $tabs = "${\t}" * $indent.Value
      write-output "$tabs""$key""${\t}${\t}$($vdf[$key])${\n}"
    }
  }
}
function vdf_mkdir {
  param($vdf, [string]$path = ''); $s = $path.split('\',2); $key = $s[0]; $recurse = $s[1]
  if ($key -and $vdf.Keys -notcontains $key) { $vdf[$key] = new-object System.Collections.Specialized.OrderedDictionary }
  if ($recurse) { vdf_mkdir $vdf[$key] $recurse }
}
function sc-nonew($fn, $txt) {
  if ((Get-Command set-content).Parameters['nonewline']) { set-content -lit $fn $txt -nonewline -force }
  else { [IO.File]::WriteAllText($fn, $txt -join [char]10) } # ps2.0
}
@{'\t'=9; '\n'=10; '\f'=12; '\r'=13; '\"'=34; '\$'=36}.getenumerator() | foreach {set $_.Name $([char]($_.Value)) -force}

##  AveYo: change steam startup location to Library window and set friendsui perfomance options
dir "$STEAM\userdata\*\7\remote\sharedconfig.vdf" -Recurse |foreach {
  $file = $_; $write = $false; $vdf = vdf_parse -vdf (gc $file -force)
  if ($vdf.count -eq 0) { $vdf = vdf_parse @('"UserRoamingConfigStore"','{','}') }
  vdf_mkdir $vdf.Item(0) 'Software\Valve\Steam\FriendsUI'
  $key = $vdf.Item(0)["Software"]["Valve"]["Steam"]
  if ($key["SteamDefaultDialog"] -ne '"#app_games"') { $key["SteamDefaultDialog"] = '"#app_games"'; $write = $true }
  $ui = $key["FriendsUI"]["FriendsUIJSON"]; if ($ui -notlike '*{*') { $ui = '' }
  if ($FriendsSignIn -eq 0 -and ($ui -like '*bSignIntoFriends\":true*' -or $ui -like '*PersonaNotifications\":1*') ) {
	$ui = $ui.Replace('bSignIntoFriends\":true','bSignIntoFriends\":false')
    $ui = $ui.Replace('PersonaNotifications\":1','PersonaNotifications\":0'); $write = $true
  }
  if ($FriendsAnimed -eq 0 -and ($ui -like '*bAnimatedAvatars\":true*' -or $ui -like '*bDisableRoomEffects\":false*') ) {
    $ui = $ui.Replace('bAnimatedAvatars\":true','bAnimatedAvatars\":false')
    $ui = $ui.Replace('bDisableRoomEffects\":false','bDisableRoomEffects\":true'); $write = $true
  }
  $key["FriendsUI"]["FriendsUIJSON"] = $ui; if ($write) { sc-nonew $file $(vdf_print $vdf); write-output " $file " }
}

##  AveYo: enable Small Mode and library performance options
$opt = @{LibraryDisableCommunityContent=1; LibraryLowBandwidthMode=1; LibraryLowPerfMode=1; LibraryDisplayIconInGameList=0}
if ($ShowGameIcons -eq 1) {$opt.LibraryDisplayIconInGameList = 1}
dir "$STEAM\userdata\*\config\localconfig.vdf" -Recurse |foreach {
  $file = $_; $write = $false; $vdf = vdf_parse -vdf (gc $file -force)
  if ($vdf.count -eq 0) { $vdf = vdf_parse @('"UserLocalConfigStore"','{','}') }
  vdf_mkdir $vdf.Item(0) 'Software\Valve\Steam'; vdf_mkdir $vdf.Item(0) 'friends'
  $key = $vdf.Item(0)["Software"]["Valve"]["Steam"]
  if ($key["SmallMode"] -ne '"1"') { $key["SmallMode"] = '"1"'; $write = $true }
  foreach ($o in $opt.Keys) { if ($vdf.Item(0)["$o"] -ne """$($opt[$o])""") {
    $vdf.Item(0)["$o"] = """$($opt[$o])"""; $write = $true
  }}
  if ($FriendsSignIn -eq 0) {
    $key = $vdf.Item(0)["friends"]
    if ($key["SignIntoFriends"] -ne '"0"') { $key["SignIntoFriends"] = '"0"'; $write = $true }
  }
  if ($write) { sc-nonew $file $(vdf_print $vdf); write-output " $file " }
}

##  AveYo: save to steam if pasted directly into powershell or content does not match
$file = "$STEAM\steam_min.ps1"; $file_lines = if (test-path -lit $file) {(gc -lit $file) -ne ''} else {'file'}
$env0 = if ($env:0 -and (test-path -lit $env:0)) {gc -lit $env:0} else {'env0'} ; $env0_lines = $env0 -ne ''
$text = "@(set ""0=%~f0"" '${0=%~f0}');.{$($MyInvocation.MyCommand.Definition)} #_press_Enter_if_pasted_in_powershell"
$text = $text -split '\r?\n'; $text_lines = $text -ne ''
if (diff $text_lines $env0_lines) { if (diff $file_lines $text_lines) { $text | set-content -force $file} }
else { if (diff $file_lines $env0_lines) {$env0 | set-content -force $file} }

##  AveYo: refresh Steam_min desktop shortcut
$wsh = new-object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\Steam.lnk")
$lnk.Description = "$STEAM\steam.exe"; $lnk.IconLocation = "$STEAM\steam.exe,0"; $lnk.WindowStyle = 7
$lnk.TargetPath  = "powershell"; $lnk.Arguments = "-nop -nol -ep remotesigned -file ""$STEAM\steam_min.ps1"""
$lnk.Save(); $lnk = $null

##  AveYo: refresh Steam_min start menu shortcut
$wsh = new-object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Steam.lnk")
$lnk.Description = "$STEAM\steam.exe"; $lnk.IconLocation = "$STEAM\steam.exe,0"; $lnk.WindowStyle = 7
$lnk.TargetPath  = "powershell"; $lnk.Arguments = "-nop -nol -ep remotesigned -file ""$STEAM\steam_min.ps1"""
$lnk.Save(); $lnk = $null

##  AveYo: start Steam with quick launch options
[void]$wsh.Run("""$STEAM\Steam.exe"" $QUICK", 1, "false"); $wsh = $null

} #_press_Enter_if_pasted_in_powershell
'@; $bat = "$env:TEMP\steam_min.bat"; Set-Content -Path $bat -Value $batchCode -Encoding ASCII -Force; & $bat | Out-Null					
					}
					# message
					cls; Write-Host "Steam config applied . . ."; while (!(Get-Process -Name 'steamwebhelper' -ea 0)) {sleep -m 200}; kill -Name 'steam','steamwebhelper' -ea 0
					show-menu
					
				}
				16 {
					
					cls; Write-Host "Installing: Ubisoft Connect . . ."
					# download & install ubisoft connect
					$exe="$env:TEMP\Ubisoft Connect.exe"; Get-FileFromWeb "https://static3.cdn.ubi.com/orbit/launcher_installer/UbisoftConnectInstaller.exe" $exe; saps -wait $exe "/S"
					# debloat start menu shortcut
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\Ubisoft\Ubisoft Connect\Ubisoft Connect.lnk" $p -Force -ea 0; ri "$p\Ubisoft" -Recurse -Force -ea 0
					show-menu
					
				}
				17 {
					
					cls; Write-Host "Installing: Valorant . . ."
					# download & install valorant
					$exe = "$env:TEMP\Valorant.exe"; Get-FileFromWeb "https://valorant.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.live.ap.exe" $exe; saps $exe
					show-menu
					
				}
				18 {
					
					Clear-Host
					$progresspreference = 'silentlycontinue'
					Write-Host 'Installing: NanaZip . . .'
					# download & install nanazip
					$api=irm https://api.github.com/repos/M2Team/NanaZip/releases/latest -ea 0; $xml =$api.assets | ? name -like '*.xml' | select -f 1; $msix=$api.assets | ? name -like '*.msixbundle' | select -f 1
					if($xml -and $msix){
					  $l="$env:TEMP\$(Split-Path $xml.browser_download_url -Leaf)"; $p="$env:TEMP\$(Split-Path $msix.browser_download_url -Leaf)"
					  Get-FileFromWeb $xml.browser_download_url  $l; Get-FileFromWeb $msix.browser_download_url $p; Add-AppxProvisionedPackage -Online -PackagePath $p -LicensePath $l|out-null
					}
					show-menu
					
				}
				19 {
					
					cls; Write-Host "Installing: Brave Browser . . ."
					# download & install brave
					$exe = "$env:TEMP\BraveBrowserSetup.exe"; Get-FileFromWeb "https://laptop-updates.brave.com/latest/winx64" $exe; saps -wait $exe "/silent /install"
					# stop brave runnig
					Get-Process | ? {$_.ProcessName -like "*brave*"} | kill -Force -ea 0
					# create brave shortcuts
					@("$env:USERPROFILE\Desktop\Brave.lnk","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Brave.lnk","$env:PUBLIC\Desktop\Brave.lnk")|%{ri $_ -force -ea 0}
					$b = Join-Path $env:ProgramFiles "BraveSoftware\Brave-Browser\Application\brave.exe"
					$WshShell = New-Object -ComObject WScript.Shell;$silentFlags = '--no-first-run --disable-features=WelcomePage'
					$shortcuts = @(@{Path="$env:USERPROFILE\Desktop\Brave.lnk"; Type="Desktop"},@{Path="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Brave.lnk";Type="Start Menu"})
					foreach ($sc in $shortcuts) {$shortcut = $WshShell.CreateShortcut($sc.Path);$shortcut.TargetPath = $b;$shortcut.Arguments = $silentFlags;$shortcut.IconLocation = "$b, 0";$shortcut.Save()}
					# create config file
					$dir = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";$prefs = Join-Path $dir "Default\Preferences";ni -Path (Split-Path $prefs) -Type Directory -Force *>$null;$utf8 = [Text.UTF8Encoding]::new($false)
					$cfgText = @'
{
  "browser": {
    "enable_window_closing_confirm": false,
    "first_run_finished": true
  },
  "enable_do_not_track": true,
  "https_only_mode_enabled": true,
  "media_router": {
    "enable_media_router": false
  },
  "user_experience_metrics": {
    "reporting_enabled": false
  },
  "privacy_sandbox": {
    "first_party_sets_data_access_allowed_initialized": true,
    "first_party_sets_enabled": false,
    "m1": {
      "ad_measurement_enabled": false,
      "fledge_enabled": false,
      "topics_enabled": false
    }
  },
  "brave": {
    "brave_search": {
      "show-ntp-search": false
    },
    "brave_vpn": {
      "show_button": false
    },
    "enable_window_closing_confirm": false,
    "has_seen_brave_welcome_page": true,
    "new_tab_page": {
      "hide_all_widgets": true,
      "show_background_image": false,
      "show_brave_news": false,
      "show_brave_vpn": false,
      "show_rewards": false,
      "show_stats": false,
      "show_together": false,
      "shows_options": 2
    },
    "p3a": {
      "enabled": false,
      "notice_acknowledged": true
    },
    "rewards": {
      "inline_tip_buttons_enabled": false,
      "show_brave_rewards_button_in_location_bar": false
    },
    "shields": {
      "advanced_view_enabled": true
    },
    "show_side_panel_button": false,
    "sidebar": {
      "hidden_built_in_items": [3, 4],
      "sidebar_show_option": 3
    },
    "stats": {
      "reporting_enabled": false
    },
    "top_site_suggestions_enabled": false,
    "wallet": {
      "show_wallet_icon_on_toolbar": false
    }
  },
  "profile": {
    "content_settings": {
      "default_content_setting_values": {
        "autoplay": 2,
        "httpsUpgrades": 2
      },
      "exceptions": {
        "autoplay": {},
        "cosmeticFilteringV2": {
          "*,*": {
            "setting": {
              "cosmeticFilteringV2": 1
            }
          }
        },
        "shieldsAds": {
          "*,*": {
            "setting": 1
          }
        },
        "trackers": {
          "*,*": {
            "setting": 1
          }
        }
      },
      "pref_version": 1
    }
  }
}
'@; [System.IO.File]::WriteAllText($prefs, $cfgText, $utf8)
					
					# create reg file
					$MultilineComment = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]
"ImportHistory"=dword:00000000
"HistoryClustersVisible"=dword:00000000
"HistorySearchSettings"=dword:00000000
"SavingBrowserHistoryDisabled"=dword:00000001
"SpellCheckServiceEnabled"=dword:00000000
"SpellcheckEnabled"=dword:00000000
"AIModeSettings"=dword:00000000
"BrowserLabsEnabled"=dword:00000000
"BrowserAddPersonEnabled"=dword:00000000
"HardwareAccelerationModeEnabled"=dword:00000000
"TorDisabled"=dword:00000001
"BraveNewsDisabled"=dword:00000001
"BraveP3AEnabled"=dword:00000000
"BraveSpeedreaderEnabled"=dword:00000000
"BraveStatsPingEnabled"=dword:00000000
"BraveTalkDisabled"=dword:00000001
"BraveVPNDisabled"=dword:00000001
"BraveWalletDisabled"=dword:00000001
"BraveWaybackMachineEnabled"=dword:00000000
"BraveWebDiscoveryEnabled"=dword:00000000
"BraveRewardsDisabled"=dword:00000001
"BraveAIChatEnabled"=dword:00000000
"BraveSyncUrl"=""
"DefaultGeolocationSetting"=dword:00000002
"DefaultSensorsSetting"=dword:00000002
"DefaultNotificationsSetting"=dword:00000002
"DefaultLocalFontsSetting"=dword:00000002
"DefaultSerialGuardSetting"=dword:00000002
"PasswordManagerEnabled"=dword:00000000
"PasswordSharingEnabled"=dword:00000000
"PasswordLeakDetectionEnabled"=dword:00000000
"SafeBrowsingExtendedReportingEnabled"=dword:00000000
"SafeBrowsingSurveysEnabled"=dword:00000000
"SafeBrowsingDeepScanningEnabled"=dword:00000000
"AlternateErrorPagesEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"MetricsReportingEnabled"=dword:00000000
"RelatedWebsiteSetsEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"UserFeedbackAllowed"=dword:00000000
"UrlKeyedAnonymizedDataCollectionEnabled"=dword:00000000
"FeedbackSurveysEnabled"=dword:00000000
"SafeBrowsingProtectionLevel"=dword:00000000
"AutofillAddressEnabled"=dword:00000000
"WebRtcIPHandling"="disable_non_proxied_udp"
"QuicAllowed"=dword:00000000
"BlockThirdPartyCookies"=dword:00000001
"ForceGoogleSafeSearch"=dword:00000000
"IPFSEnabled"=dword:00000000
"BasicAuthOverHttpEnabled"=dword:00000000
"HttpsOnlyMode"="force_enabled"
"HttpsUpgradesEnabled"=dword:00000001
"DnsOverHttpsMode"="off"
"MediaRecommendationsEnabled"=dword:00000000
"AlwaysOpenPdfExternally"=dword:00000001
"TranslateEnabled"=dword:00000001
"PromotionsEnabled"=dword:00000000
"SearchSuggestEnabled"=dword:00000000
"PrintingEnabled"=dword:00000000
"DomainReliabilityAllowed"=dword:00000000
"PrivacySandboxAdMeasurementEnabled"=dword:00000000
"PrivacySandboxAdTopicsEnabled"=dword:00000000
"PrivacySandboxPromptEnabled"=dword:00000000
"DefaultBrowserSettingEnabled"=dword:00000001
"DefaultSearchProviderEnabled"=dword:00000001
"DefaultSearchProviderName"="Brave"
"DefaultSearchProviderKeyword"="br"
"DefaultSearchProviderSearchURL"="https://search.brave.com/search?q={searchTerms}"
"DefaultSearchProviderSuggestURL"="https://search.brave.com/api/suggest?q={searchTerms}"
"DefaultSearchProviderNewTabURL"="https://search.brave.com/newtab"
"DefaultSearchProviderImageURL"="https://cdn.search.brave.com/serp/favicon.ico" ;"https://search.brave.com/static/icons/icon-128.png"
"DefaultSearchProviderEncodings"="UTF-8"
"DefaultSearchProviderAlternateURLs"=""
"PromptForDownloadLocation"=dword:00000001
"ImportAutofillFormData"=dword:00000000
"ImportHistory"=dword:00000000
"ImportSavedPasswords"=dword:00000000
"ImportSearchEngine"=dword:00000000
"HomepageLocation"="https://search.brave.com"
"LiveCaptionEnabled"=dword:00000000
"LiveTranslateEnabled"=dword:00000000
"VideoCaptureAllowed"=dword:00000000
"SharedClipboardEnabled"=dword:00000000
"RemoteDebuggingAllowed"=dword:00000000
"AllowDinosaurEasterEgg"=dword:00000000
"AutoplayAllowed"=dword:00000000
"ChromeForTestingAllowed"=dword:00000000
"ChromeVariations"=dword:00000000
"DefaultBraveFingerprintingV2Setting"=dword:00000003
"DisableScreenshots"=dword:00000001
"HideWebStoreIcon"=dword:00000001
"HighEfficiencyModeEnabled"=dword:00000000
"PaymentMethodQueryEnabled"=dword:00000000
"PrefetchWithServiceWorkerEnabled"=dword:00000000
"ProfileReauthPrompt"=dword:00000000
"QuicAllowed"=dword:00000001
"BrowserSwitcherEnabled"=dword:00000000
"ManagedConfigurationPerOrigin"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist]
"1"="cjpalhdlnbpafiamejdnhcphjbkeiagm"

[HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave\ClearBrowsingDataOnExitList]
"1"="browsing_history"
"2"="download_history"
"4"="cached_images_and_files"
"5"="password_signin"
"6"="autofill"
"7"="site_settings"
"8"="hosted_app_data"

[HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave\AutoplayAllowlist]
"1"="https://www.youtube.com"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF]
"EnrollmentState"=dword:00000001
"EnrollmentType"=dword:00000000
"IsFederated"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF]
"Flags"=dword:00d6fb7f
"AcctUId"="0x000000000000000000000000000000000000000000000000000000000000000000000000"
"RoamingCount"=dword:00000000
"SslClientCertReference"="MY;User;0000000000000000000000000000000000000000"
"ProtoVer"="1.2"

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineCore]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineUA]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components\{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{56CA197F-543C-40DC-953C-B9C6196C92A5}]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{0948A341-8E1E-479F-A667-6169E4D5CB2A}]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0948A341-8E1E-479F-A667-6169E4D5CB2A}]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{56CA197F-543C-40DC-953C-B9C6196C92A5}]
'@; $reg = "$env:TEMP\Brave.reg"; Set-Content -Path $reg -Value $MultilineComment -Force; reg import $reg 2>$null;ri $reg -Force -ea 0
					# disable brave services
					gsv | ? Name -match 'Brave' | % { Set-Service $_.Name -StartupType Manual; Stop-Service $_.Name -Force }
					# disable brave scheduled tasks
					Get-ScheduledTask | ? TaskName -like "*Brave*" | % { Disable-ScheduledTask -TaskName $_.TaskName -ea 0 > $null }
					# disable brave startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*brave*"} | % {sp -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0}
					show-menu
					
				}
				20 {
					
					cls; Write-Host "Installing: Revo Uninstaller . . ."
					# download & install revo uninstaller
					$exe = "$env:TEMP\revosetup.exe"; Get-FileFromWeb "https://download.revouninstaller.com/download/revosetup.exe" $exe; saps -wait $exe "/verysilent"
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\Revo Uninstaller\Revo Uninstaller.lnk" $p -Force -ea 0; ri "$p\Revo Uninstaller" -Recurse -Force -ea 0
					# create reg file
					$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\VS Revo Group\Revo Uninstaller\General]
"NeverShowAgain"=dword:00000000
"Skip Warn"=dword:00000001
"AU on startup"=dword:00000000
"Skip Info"=dword:00000001

[HKEY_CURRENT_USER\Software\VS Revo Group\Revo Uninstaller\Helper]
"NeverShowAgain"=dword:00000000
"HelperEnabled"=dword:00000000

[HKEY_CURRENT_USER\Software\VS Revo Group\Revo Uninstaller\Junk Files\General]
"Delete to bin"=dword:00000000
"Ignore last 24 fours"=dword:00000001

[HKEY_CURRENT_USER\Software\VS Revo Group\Revo Uninstaller\Uninstaller]
"Show System Components"=dword:00000001
"FastLoadMode"=dword:00000001
"Use Reg Install Date"=dword:00000000
"Disable scan after uninstall"=dword:00000000
"Create System Restore Pont"=dword:00000000
"Maximize uninstall wizard"=dword:00000000
"Select leftovers by default"=dword:00000001
"StopRunExe"=dword:00000001
"DelToBin"=dword:00000001

[HKEY_CURRENT_USER\Software\VS Revo Group\Revo Uninstaller\View]
"Small Icons"=dword:00000000
"Show Text"=dword:00000001
"Small Icons in Details"=dword:00000001
'@; $reg = "$env:TEMP\revo.reg"; Set-Content -Path $reg -Value $MultilineComment -Force; reg import $reg 2> $null
					show-menu
					
				}
				21 {
					
					cls; Write-Host "Installing Core Temp . . ."
					# download & install core temp
					$exe = "$env:TEMP\CoreTempSetup.exe"; Get-FileFromWeb "https://www.alcpu.com/CoreTemp/Core-Temp-setup.exe" $exe; saps -wait $exe '/verysilent'
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\Core Temp\Core Temp.lnk" $p -Force -ea 0; ri "$p\Core Temp" -Recurse -Force -ea 0; ri "$env:PUBLIC\Desktop\Goodgame Empire.url" -Force -ea 0
					# 
					reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Core Temp" /t REG_SZ /d "C:\Program Files\Core Temp\Core Temp.exe /STARTMINIMIZED" /f >$null 2>&1
					# create reg file
					$MultilineComment = @'
[General]
ReadInt=1000;
LogInt=10;
Language=English;
Plugins=0;
EnLog=0;
SingleInstance=1;
AutoUpdateCheck=0;

[Display]
Fahr=0;
Minimized=1;
CloseToSystray=0;
HideTaskbarButton=0;
TextColor=FF000000;
StatusColor=C0FF,FF;
LabelColor=FF000000;

[System tray]
SystrayOption=2;
SystrayTransparentBack=1;
SystrayColorAllBack=0,0;
SystrayColorAllText=D8FF,90FF00;
SystrayColorHighCpuBack=0;
SystrayColorHighCpuText=D8FF;
SystrayColorHighBack=0;
SystrayColorHighText=D8FF;
SystrayColorClockBack=0;
SystrayColorClockText=C0C0C0;
SystrayColorLoadBack=0;
SystrayColorLoadText=C0C0C0;
SystrayColorRamBack=0;
SystrayColorRamText=C0C0C0;
SystrayColorPowerBack=0;
SystrayColorPowerText=C0C0C0;
SystrayDisplayFrequency=0;
SystrayDisplayLoad=0;
SystrayDisplayRam=1;
SystrayDisplayPower=1;
SystrayFontName=Tahoma;
SystrayFontSize=8;

[Windows 7 Taskbar button settings]
W7TBEnable=1;
W7TBOption=0;
W7TBCycleDelay=10;
W7TBFrequencyColor=2;
W7TBDisableMinimizeToTray=0;

[G15 LCD settings]
G15BuiltInFont=1;
G15Time=1;
G1524HTime=0;
G15FontName=Tahoma;
G15FontSize=8;

[Advanced]
ShowDTJ=0;
BusClk=0;
SnmpSharedMemory=0;

[Overheat protection settings]
EnableOHP=0;
NotifyHot=0;
Balloon=1;
Flash=0;
Execute=;
EnableShutDown=0;
ProtectionType=0;
ActivateAt=0;
Seconds=30;
ExecuteOnce=1;
Degrees=90;

[Misc]
Version=0;
TjMaxOffset=0;
AlwaysOnTop=0;
MiniMode=0;
AltFreq=0;

[UI]
SPX=276;
SPY=149;
CoreFrequencySelector=-1;
'@; Set-Content -Path "C:\Program Files\Core Temp\CoreTemp.ini" -Value $MultilineComment -Force
					show-menu
					
				}
				22 {
					
					cls; write-Host "Installing: LibreWolf . . ."
					$l = "$env:ProgramFiles\LibreWolf\librewolf.exe"
					$api = "https://gitlab.com/api/v4/projects/librewolf-community%2Fbrowser%2Fbsys6/releases"
					$releases = Invoke-RestMethod -Uri $api
					foreach ($rel in $releases) {
					    foreach ($asset in $rel.assets.links) {
					        if ($asset.url -match "windows" -and $asset.url -match "\-windows-x86_64-setup.exe$") {
					            $url = $asset.url
					            $originalFileName = [System.IO.Path]::GetFileName($asset.url)
					            break
					        }
					    }
					    if ($url) { break }
					}
					if (-not $url) { throw "No Windows installer found.";$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');exit 1};$dest = "$env:TEMP\$originalFileName";Get-FileFromWeb -Url $url -File $dest;Start-Process $dest "/S" -Wait
					$librewolfExe = "C:\Program Files\LibreWolf\librewolf.exe"
					Start-Process $librewolfExe -ArgumentList "--headless" -PassThru|Out-Null;Sleep 15;Stop-Process -Name "librewolf" -Force -ea 0
					# LibreWolf WinUpdater
					$ProgressPreference = 'SilentlyContinue'
					$TargetDir = "$env:APPDATA\LibreWolf\WinUpdater"
					$DesktopPath = [Environment]::GetFolderPath('Desktop')
					$ShortcutPath = "$DesktopPath\LibreWolf WinUpdater.lnk"
					$LatestRelease = Invoke-RestMethod -Uri "https://codeberg.org/api/v1/repos/ltguillaume/librewolf-winupdater/releases/latest"
					$LatestZip = $LatestRelease.assets | Where-Object { $_.name -like "LibreWolf-WinUpdater_*.zip" }
					$TempZip = "$env:TEMP\$($LatestZip.name)"
					if (-not (Test-Path $TargetDir)) { New-Item -ItemType Directory -Path $TargetDir -Force *> $null }
					iwr -Uri $LatestZip.browser_download_url -OutFile $TempZip
					Expand-Archive -Path $TempZip -DestinationPath $TargetDir -Force
					Remove-Item -Path $TempZip -Force
					$WshShell = New-Object -ComObject WScript.Shell
					$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
					$Shortcut.TargetPath = "$TargetDir\LibreWolf-WinUpdater.exe"
					$Shortcut.Save()
					# overrides
					$MultilineComment = @'
// credit @PrivacyIsFreedom
// https://codeberg.org/PrivacyIsFreedom/Librewolf/src/branch/main/librewolf.overrides.cfg

defaultPref("privacy.window.maxInnerWidth", 1920);
defaultPref("privacy.window.maxInnerHeight", 1080);
defaultPref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
defaultPref("browser.urlbar.suggest.engines", false);
defaultPref("browser.urlbar.suggest.bookmark", false);
defaultPref("browser.urlbar.suggest.history", false);
defaultPref("browser.urlbar.suggest.openpage", false);
defaultPref("browser.urlbar.suggest.topsites", false);
defaultPref("layout.spellcheckDefault", 0);
defaultPref("media.hardwaremediakeys.enabled", false);	
defaultPref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);
defaultPref("places.history.enabled", false);
defaultPref("privacy.clearOnShutdown.siteSettings", true);
defaultPref("privacy.cpd.offlineApps", true);
defaultPref("privacy.cpd.siteSettings", true);	
defaultPref("privacy.userContext.enabled", false);	
defaultPref("ui.osk.enabled", false);
defaultPref("dom.push.connection.enabled", false);

// My Overrides
// Stop LibreWolf from resuming after a crash
defaultPref("browser.sessionstore.resume_from_crash", false);
// PREF: Show Bookmarks on New Tab
defaultPref("browser.toolbars.bookmarks.visibility", "newtab");
// PREF: preserve cookies
defaultPref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);
// PREF: Use a stricter autoplay policy
defaultPref("media.autoplay.blocking_policy", 2);
// PREF: Autohide download button
defaultPref("browser.download.autohideButton", true);
// PREF: Set blank Home and new tab page
defaultPref("browser.startup.homepage", "about:blank");
defaultPref("browser.newtabpage.enabled", false);
// PREF: Disable WebRTC
defaultPref("media.peerconnection.enabled", false);
// PREF: Enable letterboxing
defaultPref("privacy.resistFingerprinting.letterboxing", true);
// PREF: Disable the creation of these jump list shortcuts
defaultPref("browser.taskbar.lists.enabled", false);
// PREF: Force ublock origin
defaultPref("browser.policies.runOncePerModification.extensionsInstall", ["https://addons.mozilla.org/firefox/downloads/latest/uBlock0@raymondhill.net/latest.xpi"]);
defaultPref("extensions.webextensions.ExtensionStorageIDB.migrated.uBlock0@raymondhill.net", true);
'@;$path="$env:USERPROFILE\.librewolf";if(!(Test-Path $path)){ni -ItemType Directory -Path $path -Force|Out-Null};sc -Path "$path\librewolf.overrides.cfg" -Value $MultilineComment -Force
					# policies
			        $basePath = "C:\Program Files\LibreWolf"
			        $filePath = Join-Path $basePath "distribution\policies.json"
			        if (Test-Path $filePath) {
			            $policiesJson = gc $filePath -Raw;$policiesObject = $policiesJson | ConvertFrom-Json;$policiesObject.policies.SearchEngines.Default = "Brave"    
			            $braveSearchEngine = @{
			                Name = "Brave"
			                URLTemplate = "https://search.brave.com/search?q={searchTerms}"
			                Method = "GET"
			                IconURL = "https://cdn.search.brave.com/serp/favicon.ico"
			                Alias = "@brave"
			                Description = "Brave's privacy-focused search engine"
			                SuggestURLTemplate = "https://search.brave.com/suggestions?q={searchTerms}"
			            }
			            $policiesObject.policies.SearchEngines.Add += $braveSearchEngine;$policiesObject | ConvertTo-Json -Depth 10 | Out-File $filePath -Encoding ASCII -Force
			        }
			        # shortcuts
			        # desktop
			        $s = "$env:USERPROFILE\Desktop\LibreWolf.lnk";$wshell = New-Object -ComObject WScript.Shell;$lnk = $wshell.CreateShortcut($s);$lnk.TargetPath = $l;$lnk.Save()
			        # start menu
			        $p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs";mi "$p\LibreWolf\LibreWolf.lnk" $p -Force -ea 0;ri "$p\LibreWolf" -Recurse -Force -ea 0
			        # remove "LibreWolf Private Browsing" from start menu
					1..3 | % {ri "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\LibreWolf Private Browsing.lnk","$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\LibreWolf Private Browsing.lnk" -Force -ea 0;sleep 2}		
					show-menu
				}
				23 {
				
					cls; write-host "Installing: Microsoft Office 365 . . ."; $ProgressPreference = 'SilentlyContinue'
					# download & install Microsoft Office 365
					$exe="$env:TEMP\OfficeSetup.exe"; Get-FileFromWeb "https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365AppsBasicRetail&platform=x64&language=en-us&version=O16GA" $exe; saps $exe -wait
					# activate microsoft 365
					kill -name OfficeC2RClient -force -ea 0; iex "& {$((irm https://get.activated.win))} /Ohook"
					# disable onedrive startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*OneDrive*"} | % {sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0}
					# disable onenote startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*ONENOTEM*"} | % {sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0}					
					show-menu
					
				}
				24 {
					
					cls; write-host 'Installing: Portmaster . . .'; $ProgressPreference = 'SilentlyContinue'
					# download & install portmaster
					$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"; $html = iwr "https://safing.io/download/" -Headers @{ "User-Agent" = $ua } -UseBasicParsing
					$url = ($html.Links | ? { $_.href -match '\.exe$' } | select -f 1).href; $filename = [System.IO.Path]::GetFileName($url); $file="$env:TEMP\$filename"; Get-FileFromWeb $url $file; saps $file '/S' -wait
					show-menu
					
				}
				25 {
					
					cls; Write-Host "Installing: Powershell 7 . . ."; $ProgressPreference = 'SilentlyContinue'	
					# download & install pwsh 7
					$r=irm https://api.github.com/repos/PowerShell/PowerShell/releases/latest
					$a=$r.assets|? name -like '*win-x64.msi'|select -f 1
					$msi="$env:TEMP\$(Split-Path $a.browser_download_url -Leaf)"
					Get-FileFromWeb $a.browser_download_url $msi
					saps msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q ADD_PATH=1 ENABLE_PSREMOTING=1"					
					# fix start menu shortcut
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
					mi "$p\PowerShell\PowerShell 7 (x64).lnk" $p -force -ea 0
					ren "$p\PowerShell 7 (x64).lnk" "PowerShell 7.lnk" -force -ea 0
					ri "$p\PowerShell" -recurse -force -ea 0
					
					cls; Write-Host "Installing Windows Terminal..."
					# install windows terminal
					Get-AppXPackage -AllUsers *Microsoft.WindowsTerminal* | % {Add-AppxPackage -DisableDevelopmentMode -Register -ea 0 "$($_.InstallLocation)\AppXManifest.xml"}	
					# This will edit the config file of the Windows Terminal Replacing the Powershell 5 to Powershell 7
					if (Get-Command "wt" -ea 0) {
						$settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"; if (Test-Path -Path $settingsPath) {
							$settingsContent = Get-Content -Path $settingsPath | ConvertFrom-Json; $ps7Profile = $settingsContent.profiles.list | ? { $_.name -eq $targetTerminalName }
					        if ($ps7Profile) {$settingsContent.defaultProfile = $ps7Profile.guid; $updatedSettings = $settingsContent | ConvertTo-Json -Depth 100; Set-Content -Path $settingsPath -Value $updatedSettings}
						}
					}	
					show-menu
					
				}
				26 {

					cls; Write-Host "Installing: Process Explorer . . ."; $ProgressPreference = 'SilentlyContinue'	
					# download process explorer
					$Zip="$env:TEMP\ProcessExplorer.zip"; $pe="$env:ProgramFiles\Process Explorer"; Get-FileFromWeb "https://download.sysinternals.com/files/ProcessExplorer.zip" $Zip
					# exctract files
					if (!(Test-Path $pe)) {ni $pe -ItemType Directory -Force | Out-Null}; Expand-Archive $Zip $pe -Force
					# replace task manager
					$exe="$pe\procexp64.exe"; ni "HKCU:\SOFTWARE\Sysinternals\Process Explorer" -Force | Out-Null; ni "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -Force | Out-Null
					sp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -name "Debugger" -Value "`"$exe`" /e"
					# create process explorer shortcuts
					$lnk="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Process Explorer.lnk"; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($lnk); $s.TargetPath=$exe; $s.Save()				
					# create reg file
					$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Sysinternals]
"EulaAccepted"=dword:00000001

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer]
"ShowDllView"=dword:00000000
"HandleSortColumn"=dword:00000000
"HandleSortDirection"=dword:00000001
"DllSortColumn"=dword:00000000
"DllSortDirection"=dword:00000001
"ProcessSortDirection"=dword:00000001
"HighlightServices"=dword:00000001
"HighlightOwnProcesses"=dword:00000001
"HighlightRelocatedDlls"=dword:00000000
"HighlightJobs"=dword:00000000
"HighlightNewProc"=dword:00000001
"HighlightDelProc"=dword:00000001
"HighlightImmersive"=dword:00000001
"HighlightProtected"=dword:00000000
"HighlightPacked"=dword:00000001
"HighlightNetProcess"=dword:00000000
"HighlightSuspend"=dword:00000001
"ShowCpuFractions"=dword:00000001
"ShowAllUsers"=dword:00000001
"ShowProcessTree"=dword:00000001
"SymbolWarningShown"=dword:00000000
"HideWhenMinimized"=dword:00000000
"AlwaysOntop"=dword:00000000
"OneInstance"=dword:00000001
"NumColumnSets"=dword:00000000
"DefaultProcPropPage"=dword:00000000
"DefaultSysInfoPage"=dword:00000000
"DefaultDllPropPage"=dword:00000000
"SymbolPath"=""
"ShowAllCpus"=dword:00000000
"ShowAllGpus"=dword:00000000
"GpuNodeUsageMask"=dword:00000001
"GpuNodeUsageMask1"=dword:00000000
"VerifySignatures"=dword:00000000
; "VirusTotalCheck"=dword:00000001
; "VirusTotalSubmitUnknown"=dword:00000001
"UseGoogle"=dword:00000000
"ShowNewProcesses"=dword:00000000
"TrayCPUHistory"=dword:00000000
"ShowIoTray"=dword:00000000
"ShowNetTray"=dword:00000000
"ShowDiskTray"=dword:00000000
"ShowPhysTray"=dword:00000000
"ShowCommitTray"=dword:00000000
"ShowGpuTray"=dword:00000000
"FormatIoBytes"=dword:00000001
"ETWstandardUserWarning"=dword:00000000
"ShowUnnamedHandles"=dword:00000000
"ConfirmKill"=dword:00000000
"ShowLowerpane"=dword:00000000
'@; $reg="$env:TEMP\ProcessExplorerSettings.reg"; Set-Content -Path $reg -Value $MultilineComment -Force; reg import $reg *>$null
					show-menu
				
				}
				27 {
					
					cls; if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -lt 22000) {
						Write-Host "Installing: StartIsBack . . ."
						# download & install startisback
						Get-FileFromWeb "https://startisback.sfo3.cdn.digitaloceanspaces.com/StartIsBackPlusPlus_setup.exe" "$env:TEMP\StartIsBackPlusPlus_setup.exe"
						saps "$env:TEMP\StartIsBackPlusPlus_setup.exe" "/silent" -Wait
						$sib = if (Test-Path "$env:LOCALAPPDATA\StartIsBack") { "$env:LOCALAPPDATA\StartIsBack" } elseif (Test-Path "${env:ProgramFiles(x86)}\StartIsBack") { "${env:ProgramFiles(x86)}\StartIsBack" }
						# download orb
						Get-FileFromWeb "https://github.com/sounderrun/files/raw/refs/heads/main/6801-6009.bmp" "$env:LOCALAPPDATA\StartIsBack\Orbs\6801-6009.bmp"
						ni HKCU:\Software\StartIsBack -force|out-null; sp HKCU:\Software\StartIsBack OrbBitmap "$sib\Orbs\6801-6009.bmp"|out-null
						# create reg file
						$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\StartIsBack]
"ModernIconsColorized"=dword:00000000
"WelcomeShown"=dword:00000002
"Start_LargeMFUIcons"=dword:00000002
"StartMetroAppsMFU"=dword:00000000
"StartScreenShortcut"=dword:00000000
"Start_LargeAllAppsIcons"=dword:00000000
"StartMetroAppsFolder"=dword:00000001
"Start_SortFoldersFirst"=dword:00000000
"Start_NotifyNewApps"=dword:00000000
"Start_AutoCascade"=dword:00000001
"Start_AskCortana"=dword:00000000
"Start_RightPaneIcons"=dword:00000002
"Start_ShowUser"=dword:00000001
"Start_ShowMyDocs"=dword:00000001
"Start_ShowMyPics"=dword:00000001
"Start_ShowMyMusic"=dword:00000001
"Start_ShowVideos"=dword:00000000
"Start_ShowDownloads"=dword:00000001
"Start_ShowSkyDrive"=dword:00000000
"StartMenuFavorites"=dword:00000000
"Start_ShowRecentDocs"=dword:00000000
"Start_ShowNetPlaces"=dword:00000000
"Start_ShowNetConn"=dword:00000001
"Start_ShowMyComputer"=dword:00000001
"Start_ShowControlPanel"=dword:00000001
"Start_ShowPCSettings"=dword:00000001
"Start_AdminToolsRoot"=dword:00000000
"Start_ShowPrinters"=dword:00000000
"Start_ShowSetProgramAccessAndDefaults"=dword:00000000
"Start_ShowCommandPrompt"=dword:00000000
"Start_ShowRun"=dword:00000001
"Start_MinMFU"=dword:0000000a
"Start_JumpListItems"=dword:0000000a
"AutoUpdates"=dword:00000002
"Disabled"=dword:00000000
"StartIsApps"=dword:00000000
"NoXAMLPrelaunch"=dword:00000001
"TerminateOnClose"=dword:00000001
"AllProgramsFlyout"=dword:00000000
"CombineWinX"=dword:00000001
"HideUserFrame"=dword:00000001
"TaskbarLargerIcons"=dword:00000000
"TaskbarSpacierIcons"=dword:00000000
"TaskbarJumpList"=dword:00000001
"HideOrb"=dword:00000000
"HideSecondaryOrb"=dword:00000000
"StartMenuMonitor"=dword:00000001
"ImmersiveMenus"=dword:ffffffff
"WinkeyFunction"=dword:00000000
"MetroHotkeyFunction"=dword:00000000
"MetroHotKey"=dword:0000000a
"TaskbarStyle"="C:\\Users\\Admin\\AppData\\Local\\StartIsBack\\Styles\\Windows 10.msstyles"
"AlterStyle"="C:\\Users\\Admin\\AppData\\Local\\StartIsBack\\Styles\\Plain10.msstyles"
"TaskbarCenterIcons"=dword:00000000
"TaskbarTranslucentEffect"=dword:00000000
"SettingsVersion"=dword:00000005
'@; Set-Content -Path "$env:TEMP\StartIsBack.reg" -Value $MultilineComment -Force; reg import "$env:TEMP\StartIsBack.reg" *> $null
					} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
						cls; Write-Host "Installing: StartAllBack . . ."
						# download & install startallback
						$exe = "$env:TEMP\StartAllBack_setup.exe"; Get-FileFromWeb "https://www.startallback.com/download.php/StartAllBack_setup.exe" "$exe"; saps $exe "/silent" -Wait						
						# Create reg file
						$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\StartIsBack]
"AutoUpdates"=dword:00000000
"SettingsVersion"=dword:00000006
"WelcomeShown"=dword:00000003
"UpdateCheck"=hex:a2,06,b2,19,3d,0a,dc,01
"FrameStyle"=dword:00000000
"AlterStyle"=""
"TaskbarStyle"=""
"SysTrayStyle"=dword:00000000
"BottomDetails"=dword:00000000
"Start_LargeAllAppsIcons"=dword:00000000
"StartMenuFavorites"=dword:00000000
"Start_NotifyNewApps"=dword:00000000
"Start_LargeSearchIcons"=dword:00000000
"HideUserFrame"=dword:00000001
"TaskbarSpacierIcons"=dword:fffffffe
"TaskbarOneSegment"=dword:00000000
"TaskbarCenterIcons"=dword:00000000
"FatTaskbar"=dword:00000000
"TaskbarTranslucentEffect"=dword:00000000
"SysTrayClockFormat"=dword:00000003
'@; $reg="$env:TEMP\StartAllBack.reg"; Set-Content -Path $reg -Value $MultilineComment -Force; reg import $reg *>$null
					}
					# StartXBack
					Get-FileFromWeb "https://github.com/WitherOrNot/StartXBack/releases/latest/download/StartXBack.cmd" "$env:TEMP\StartXBack.cmd"
					(gc "$env:TEMP\StartXBack.cmd") | ? { $_ -ne 'pause' } | Set-Content "$env:TEMP\StartXBack.cmd"; & "$env:TEMP\StartXBack.cmd" *> $null
					if (Test-Path $sib -ea 0) {
						Get-FileFromWeb "https://github.com/WitherOrNot/StartXBack/releases/download/release/version_x86.dll" "$sib\version.dll"
					} elseif (Test-Path "$env:ProgramFiles\StartAllBack" -ea 0) {
						Get-FileFromWeb "https://github.com/WitherOrNot/StartXBack/releases/download/release/version_x64.dll" "$env:ProgramFiles\StartAllBack\version.dll"
					}
					show-menu
					
				}
				28 {
					
					cls; Write-Host "Installing: VLC media player . . ."
					# download & install vlc media player
					$exe = Join-Path $env:TEMP 'vlc-win64.exe'; Get-FileFromWeb 'https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe' $exe; saps $exe '/S' -Wait
					$p="$env:ProgramData\Microsoft\Windows\Start Menu\Programs"; mv "$p\Videolan\VLC media player.lnk" $p -Force -ea 0; ri "$p\Videolan" -Recurse -Force -ea 0
					show-menu
					
				}
				29 {
					
					clear
					$progresspreference = 'silentlycontinue'					
					powershell "irm https://asheroto.com/winget | iex" -ea 1
					# force upgrade winget dependencies
					winget upgrade --id Microsoft.AppInstaller -h --accept-package-agreements --accept-source-agreements --force --nowarn --disable-interactivity | Out-Null
					winget upgrade --id Microsoft.UI.Xaml.2.8 -h --accept-package-agreements --accept-source-agreements --force --nowarn --disable-interactivity | Out-Null
					winget upgrade --id Microsoft.VCLibs.Desktop.14 -h --accept-package-agreements --accept-source-agreements --force --nowarn --disable-interactivity | Out-Null
					clear
					# upgrade all apps, skip spotify (breaks spotx patch)
					winget pin add --id Spotify.Spotify; winget upgrade --all -h --accept-package-agreements --accept-source-agreements --nowarn --disable-interactivity
					$winget = Get-Command winget.exe -ea 0; if (-not $winget) {
						clear
						$build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild; if (Get-Command choco.exe -ea 0) { choco upgrade chocolatey -y --ignore-checksums }
						else { ri "C:\ProgramData\Chocolatey*","C:\ProgramData\ChocolateyHttpCache" -Recurse -Force -ea 0; irm https://community.chocolatey.org/install.ps1 | iex }
						if ($winget) { choco upgrade winget -y --ignore-checksums } else { choco install winget -y --force --ignore-checksums }
					}
					show-menu
					
				}
				30 {
					
					clear
					$ProgressPreference = 'SilentlyContinue'
					$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild # OS build
					function show-info {
						$reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
						$build    = [int]$reg.CurrentBuildNumber
						$edition  = $reg.EditionID
						if ($build -ge 22000) {$os = "Windows 11"} else {$os = "Windows 10"}
						Write-Host "Installing: Microsoft .NET Framework 3.5 . . ."
						Write-Host "Edition "  -NoNewLine; Write-Host "$os $edition" -ForegroundColor DarkGray
						Write-Host "OS build " -NoNewLine; Write-Host $build -ForegroundColor DarkGray
						Write-Host ""
					}
					
					# for Windows 10 build 14393/15063/16299 - dotNet2035_W10P1.exe
					if ($build -le 16299) {
						show-info
						$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P1.exe"; $File = "$env:TEMP\dotNet2035_W10P1.exe"
						Get-FileFromWeb $URL $File; saps $File "/ai" -Wait
					}
					
					# for Windows 10 17134/17363/18362/19041  -dotNet2035_W10P2.exe
					elseif ($build -ge 16299 -and $build -lt 19041) {
						show-info
						$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P2.exe"
						$File = "$env:TEMP\dotNet2035_W10P2.exe"
						Get-FileFromWeb $URL $File; saps $File "/ai" -Wait
					}
					
					# Only for Windows 10 build 19041 (including EKB versions 19042 - 19045)
					elseif ($build -ge 19041 -and $build -le 19045) {
						show-info
						$URL = "https://github.com/abbodi1406/dotNetFx35W10/releases/download/v0.25.11/dotNetFx35_WX_10_x86_x64.exe"
						$File = "$env:TEMP\dotNetFx35_WX_10_x86_x64.exe"
						Get-FileFromWeb $URL $File; saps $File "/ai" -Wait
					}
					
					# for Windows 11 22000/22621 - dotNet2035_W11.exe
					elseif ($build -ge 22000 -and $build -le 22621) {
						show-info
						$URL = "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W11.exe"
						$File = "$env:TEMP\dotNet2035_W11.exe"
						Get-FileFromWeb $URL $File; saps $File "/ai" -Wait -ea 1
						Start-Sleep -Seconds 5
						$feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3
						if ($feature.State -eq 'Enabled') {$null} 
						else {
							$URL = "https://github.com/akbarhabiby/Windows11_dotNET-3.5/archive/refs/tags/v1.1.zip"; $File = "$env:TEMP\v1.1.zip"
							Get-FileFromWeb $URL $File; Expand-Archive $File $env:TEMP -Force
							$batch = "$env:TEMP\Windows11_dotNET-3.5-1.1\app\start.bat"; (gc $batch) | ? {$_ -notmatch '^\s*pause\s*$'} | Set-Content $batch; saps -Wait $batch
						}
					}
					# unsupported build
					else {show-info; dism.exe /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart}
					show-menu
					
				}
				31 {
					
					clear
					Write-Host "Installing & Updating: EdgeWebView 2 . . ."				
					# stop edge running
					$stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"; $stop | % { Stop-Process -Name $_ -force -ea 0 }
					# download & install edge webview
					$exe="$env:TEMP\MicrosoftEdgeWebview2Setup.exe"; Get-FileFromWeb "https://go.microsoft.com/fwlink/p/?LinkId=2124703" $exe; saps $exe -wait
					show-menu
					
				}
				32 {
					
					clear
					Write-Host "Installing: Mozilla Firefox . . ."
					# download & install firefox					
					Get-FileFromWeb "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US" "$env:TEMP\Firefox Setup.exe"; saps "$env:TEMP\Firefox Setup.exe" '/S' -Wait
					# stop firefox running
					kill -name firefox -force -ea 0
					# create reg file
					$MultilineComment = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox]
; Allow file selection dialogs.
"AllowFileSelectionDialogs"=dword:00000001
; Enable or disable automatic application update.
"AppAutoUpdate"=dword:00000000
; Enable autofill for addresses.
"AutofillAddressEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundAppUpdate"=dword:00000000
"BlockAboutAddons"=dword:00000000
"BlockAboutConfig"=dword:00000000
"BlockAboutProfiles"=dword:00000000
"BlockAboutSupport"=dword:00000000
"CaptivePortal"=dword:00000000
"DisableAccounts"=dword:00000001
"DisableAppUpdate"=dword:00000000
"DisableBuiltinPDFViewer"=dword:00000001
"DisableDefaultBrowserAgent"=dword:00000001
"DisableDeveloperTools"=dword:00000001
"DisableEncryptedClientHello"=dword:00000001
"DisableFeedbackCommands"=dword:00000001
"DisableFirefoxAccounts"=dword:00000001
"DisableFirefoxScreenshots"=dword:00000001
"DisableFirefoxStudies"=dword:00000001
; Prevent access to the Forget button.
"DisableForgetButton"=dword:00000001
"DisableMasterPasswordCreation"=dword:00000001
"DisablePasswordReveal"=dword:00000001
"DisablePrivateBrowsing"=dword:00000000
"DisableProfileImport"=dword:00000000
"DisableProfileRefresh"=dword:00000000
"DisableSafeMode"=dword:00000001
"DisableSetDesktopBackground"=dword:00000001
"DisableSystemAddonUpdate"=dword:00000001
"DisableTelemetry"=dword:00000001
; Prevent the user from blocking third-party modules that get injected into the Firefox process.
"DisableThirdPartyModuleBlocking"=dword:00000001
"DisplayBookmarksToolbar"="newtab"
"DisablePocket"=dword:00000001
; Display the Menu Bar by default.
"DisplayMenuBar"="never"
"DontCheckDefaultBrowser"=dword:00000001
"ExtensionUpdate"=dword:00000001
"GoToIntranetSiteForSingleWordEntryInAddressBar"=dword:00000000
"HardwareAcceleration"=dword:00000000
"HttpsOnlyMode"="enabled"
"LegacyProfiles"=dword:00000000
; Allow manual updates only and do not notify the user about updates.
"ManualAppUpdateOnly"=dword:00000001
"MicrosoftEntraSSO"=dword:00000000
"NetworkPrediction"=dword:00000000
"NewTabPage"=dword:00000000
"NoDefaultBookmarks"=dword:00000001
; Enforce the setting to allow Firefox to offer to remember saved logins and passwords. Both true and false values are accepted.
"OfferToSaveLoginsDefault"=dword:00000000
"OverridePostUpdatePage"=""
"PasswordManagerEnabled"=dword:00000000
"PostQuantumKeyAgreementEnabled"=dword:00000000
; Require or prevent using a Primary Password.
"PrimaryPassword"=dword:00000000
; disable printing	
"PrintingEnabled"=dword:00000000
"PrivateBrowsingModeAvailability"=dword:00000000
; "PromptForDownloadLocation"=dword:00000001
"SearchBar"="unified"
"SearchSuggestEnabled"=dword:00000000
"ShowHomeButton"=dword:00000000
"SkipTermsOfUse"=dword:00000001
; Enable or disable webpage translation.
"TranslateEnabled"=dword:00000001
; Set the minimum SSL version.
"SSLVersionMin"="tls1.2"
"UseSystemPrintDialog"=dword:00000000
"VisualSearchEnabled"=dword:00000000
"WindowsSSO"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Cookies]
"Behavior"="reject-foreign"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\DisableSecurityBypass]
"InvalidCertificate"=dword:00000000
"SafeBrowsing"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS]
"Enabled"=dword:00000000
"ProviderURL"=""
"Locked"=dword:00000000

; Enable or disable Encrypted Media Extensions and optionally lock it.
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions]
"Enabled"=dword:00000000

; Enable or disable Picture-in-Picture.
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\PictureInPicture]
"Enabled"=dword:00000000

; Extensions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings\uBlock0@raymondhill.net]
"installation_mode"="force_installed"
"install_url"="https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
"Locked"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install]
"1"="https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
"Locked"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Uninstall]
"1"="amazondotcom@search.mozilla.org"
"2"="ebay@search.mozilla.org"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome]
"Search"=dword:00000000
"TopSites"=dword:00000000
"SponsoredTopSites"=dword:00000000
"Highlights"=dword:00000000
"Pocket"=dword:00000000
"Stories"=dword:00000000
"SponsoredPocket"=dword:00000000
"SponsoredStories"=dword:00000000
"Snippets"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\FirefoxSuggest]
"WebSuggestions"=dword:00000000
"SponsoredSuggestions"=dword:00000000
"ImproveSuggest"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\GenerativeAI]
"Enabled"=dword:00000001
"Chatbot"=dword:00000001
"LinkPreviews"=dword:00000000
"TabGroups"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Homepage]
"StartPage"="none"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission\Allow\1]
@="https://addons.mozilla.org"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission]
"Default"=dword:00000001

; Permissions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Camera]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Microphone]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Location]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Notifications]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\VirtualReality]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\ScreenShare]
"BlockNewRequests"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay]
"Default"="block-audio-video"
"Locked"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay\Allow]
"1"="https://www.youtube.com"

; Enable or disable Picture-in-Picture.
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\PictureInPicture]
"Enabled"=dword:00000000

; Allow certain websites to display popups and be redirected by third-party frames
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking]
"Default"=dword:00000001

; Clear navigation data on shutdown
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown]
"Cache"=dword:00000001
"Cookies"=dword:00000000
"FormData"=dword:00000001
"History"=dword:00000001
"Sessions"=dword:00000001
"SiteSettings"=dword:00000001
"Locked"=dword:00000000

; Configure search engine settings
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines]
"PreventInstalls"=dword:00000000
"Default"="Brave"

; Brave
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines\Add\1]
"Name"="Brave"
"URLTemplate"="https://search.brave.com/search?q={searchTerms}"
"Method"="GET"
"IconURL"="https://cdn.search.brave.com/serp/favicon.ico" ;"https://www.vectorlogo.zone/logos/brave/brave-icon.svg"
"Alias"="@brave"
"Description"="Brave's privacy-focused search engine"
"SuggestURLTemplate"="https://search.brave.com/suggestions?q={searchTerms}"
"PostData"=""

; SearXNG
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\SearchEngines\Add\2]
"Name"="SearXNG"
"Description"="A privacy-respecting, hackable metasearch engine"
"Alias"=""
"Method"="POST"
"URLTemplate"="https://searx.stream/?q={searchTerms}"
"PostData"="q={searchTerms}&time_range=&language=en-US&category_general=on"
"IconURL"="https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/searxng.svg"

; Remove
[HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\SearchEngines\Remove]
"1"="Google"
"2"="Bing"
"3"="Amazon.com"
"4"="eBay"
"5"="Twitter"
"6"="Wikipedia (en)"
"7"="Qwant"
"8"="Ecosia"
"9"="DuckDuckGo"

; Dont show certain messages to the user
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging]
"ExtensionRecommendations"=dword:00000000
"FeatureRecommendations"=dword:00000000
"UrlbarInterventions"=dword:00000000
"SkipOnboarding"=dword:00000000
"MoreFromMozilla"=dword:00000000
"FirefoxLabs"=dword:00000000
'@;$reg = "$env:TEMP\FirefoxPolicies.reg"; Set-Content -Path $reg -Value $MultilineComment -Force; reg import $reg *>$null

# profile
$firefoxExe = "C:\Program Files\Mozilla Firefox\firefox.exe";$profilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
Start-Process $firefoxExe -ArgumentList "--headless" -PassThru|Out-Null;Sleep 3;Stop-Process -Name "firefox" -Force -ea 0
$profileDir = gci -Path $profilesPath -Directory -ea 0|? { $_.Name -match '\.default-release$' }|sort LastWriteTime -Descending|select -First 1;$profilePath = $profileDir.FullName
$json = @'
//
/* You may copy+paste this file and use it as it is.
 *
 * If you make changes to your about:config while the program is running, the
 * changes will be overwritten by the user.js when the application restarts.
 *
 * To make lasting changes to preferences, you will have to edit the user.js.
 */

/****************************************************************************
 * Betterfox                                                                *
 * "Ad meliora"                                                             *
 * version: 144                                                             *
 * url: https://github.com/yokoffing/Betterfox                              *
****************************************************************************/

/****************************************************************************
 * SECTION: FASTFOX                                                         *
****************************************************************************/
/** GENERAL ***/
user_pref("gfx.content.skia-font-cache-size", 32);

/** GFX ***/
user_pref("gfx.canvas.accelerated.cache-items", 32768);
user_pref("gfx.canvas.accelerated.cache-size", 4096);
user_pref("webgl.max-size", 16384);

/** DISK CACHE ***/
user_pref("browser.cache.disk.enable", false);

/** MEMORY CACHE ***/
user_pref("browser.cache.memory.capacity", 131072);
user_pref("browser.cache.memory.max_entry_size", 20480);
user_pref("browser.sessionhistory.max_total_viewers", 4);
user_pref("browser.sessionstore.max_tabs_undo", 10);

/** MEDIA CACHE ***/
user_pref("media.memory_cache_max_size", 262144);
user_pref("media.memory_caches_combined_limit_kb", 1048576);
user_pref("media.cache_readahead_limit", 600);
user_pref("media.cache_resume_threshold", 300);

/** IMAGE CACHE ***/
user_pref("image.cache.size", 10485760);
user_pref("image.mem.decode_bytes_at_a_time", 65536);

/** NETWORK ***/
user_pref("network.http.max-connections", 1800);
user_pref("network.http.max-persistent-connections-per-server", 10);
user_pref("network.http.max-urgent-start-excessive-connections-per-host", 5);
user_pref("network.http.request.max-start-delay", 5);
user_pref("network.http.pacing.requests.enabled", false);
user_pref("network.dnsCacheEntries", 10000);
user_pref("network.dnsCacheExpiration", 3600);
user_pref("network.ssl_tokens_cache_capacity", 10240);

/** SPECULATIVE LOADING ***/
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.places.speculativeConnect.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);

/****************************************************************************
 * SECTION: SECUREFOX                                                       *
****************************************************************************/
/** TRACKING PROTECTION ***/
user_pref("browser.contentblocking.category", "strict"); // EnableTrackingProtection
user_pref("privacy.trackingprotection.allow_list.baseline.enabled", true);
user_pref("browser.download.start_downloads_in_tmp_dir", false);
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.uitour.enabled", false);
user_pref("privacy.globalprivacycontrol.enabled", true);


/** OCSP & CERTS / HPKP ***/
user_pref("security.OCSP.enabled", 0);
user_pref("security.csp.reporting.enabled", false);

/** SSL / TLS ***/
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);
user_pref("security.tls.enable_0rtt_data", false);

/** DISK AVOIDANCE ***/
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("browser.sessionstore.interval", 60000);

/** SHUTDOWN & SANITIZING ***/
user_pref("privacy.history.custom", true);
user_pref("browser.privatebrowsing.resetPBM.enabled", true);

/** SEARCH / URL BAR ***/
user_pref("browser.urlbar.trimHttps", true);
user_pref("browser.urlbar.untrimOnUserInteraction.featureGate", true);
user_pref("browser.search.separatePrivateDefault.ui.enabled", true);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.groupLabels.enabled", false);
user_pref("browser.formfill.enable", false);
user_pref("network.IDN_show_punycode", true);

/** PASSWORDS ***/
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.privateBrowsingCapture.enabled", false);
user_pref("network.auth.subresource-http-auth-allow", 1);
user_pref("editor.truncate_user_pastes", false);

/** MIXED CONTENT + CROSS-SITE ***/
user_pref("security.mixed_content.block_display_content", true);
user_pref("pdfjs.enableScripting", false);

/** EXTENSIONS ***/
user_pref("extensions.enabledScopes", 5);

/** HEADERS / REFERERS ***/
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

/** CONTAINERS ***/
user_pref("privacy.userContext.ui.enabled", true);

/** SAFE BROWSING ***/
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

/** MOZILLA ***/
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.geo", 2);
user_pref("geo.provider.network.url", "https://beacondb.net/v1/geolocate");
user_pref("browser.search.update", false);
user_pref("permissions.manager.defaultsUrl", "");
user_pref("extensions.getAddons.cache.enabled", false);

/** TELEMETRY ***/
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("default-browser-agent.enabled", false);
user_pref("services.settings.server", false); // service endpoint to consult for remote-disablement
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("datareporting.usage.uploadEnabled", false);

/** EXPERIMENTS ***/
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

/** CRASH REPORTS ***/
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

/****************************************************************************
 * SECTION: PESKYFOX                                                        *
****************************************************************************/
/** MOZILLA UI ***/
user_pref("browser.privatebrowsing.vpnpromourl", "");
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.preferences.moreFromMozilla", false);
user_pref("browser.aboutConfig.showWarning", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.profiles.enabled", true);

/** THEME ADJUSTMENTS ***/
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("browser.compactmode.show", true);
user_pref("browser.privateWindowSeparation.enabled", false); // WINDOWS

/** AI ***/
user_pref("browser.ml.enable", false);
// user_pref("browser.ml.chat.enabled", false); // chatbots
// user_pref("browser.ml.chat.menu", false); // chatbots
user_pref("browser.tabs.groups.smart.enabled", false);
user_pref("browser.ml.linkPreview.enabled", false);

/** FULLSCREEN NOTICE ***/
user_pref("full-screen-api.transition-duration.enter", "0 0");
user_pref("full-screen-api.transition-duration.leave", "0 0");
user_pref("full-screen-api.warning.timeout", 0);

/** URL BAR ***/
user_pref("browser.urlbar.trending.featureGate", false);

/** NEW TAB PAGE ***/
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredCheckboxes", false);

/** DOWNLOADS ***/
user_pref("browser.download.manager.addToRecentDocs", false);

/** PDF ***/
user_pref("browser.download.open_pdf_attachments_inline", true);

/** TAB BEHAVIOR ***/
user_pref("browser.bookmarks.openInTabClosesMenu", false);
user_pref("browser.menu.showViewImageInfo", true);
user_pref("findbar.highlightAll", true);
user_pref("layout.word_select.eat_space_to_next_word", false);

/****************************************************************************
 * START: MY OVERRIDES                                                      *
****************************************************************************/
// visit https://github.com/yokoffing/Betterfox/wiki/Common-Overrides
// visit https://github.com/yokoffing/Betterfox/wiki/Optional-Hardening
// Enter your personal overrides below this line:

// PREF: revert back to Standard ETP
user_pref("browser.contentblocking.category", "standard");

// PREF: make Strict ETP less aggressive
// user_pref("browser.contentblocking.features.strict", "tp,tpPrivate,cookieBehavior5,cookieBehaviorPBM5,cm,fp,stp,emailTP,emailTPPrivate,-lvl2,rp,rpTop,ocsp,qps,qpsPBM,fpp,fppPrivate,3pcd,btp");

// PREF: improve font rendering by using DirectWrite everywhere like Chrome [WINDOWS]
user_pref("gfx.font_rendering.cleartype_params.rendering_mode", 5);
user_pref("gfx.font_rendering.cleartype_params.cleartype_level", 100);
user_pref("gfx.font_rendering.directwrite.use_gdi_table_loading", false);
//user_pref("gfx.font_rendering.cleartype_params.enhanced_contrast", 50); // 50-100 [OPTIONAL]

// PREF: disable Firefox Sync
user_pref("identity.fxaccounts.enabled", false);

// PREF: disable the Firefox View tour from popping up
user_pref("browser.firefox-view.feature-tour", "{\"screen\":\"\",\"complete\":true}");

// PREF: disable login manager
user_pref("signon.rememberSignons", false); // Control whether or not Firefox offers to save passwords

// PREF: disable address and credit card manager
user_pref("extensions.formautofill.addresses.enabled", false); // disables autofill for addresses
user_pref("extensions.formautofill.creditCards.enabled", false); // disables autofill for payment methods

// PREF: do not allow embedded tweets, Instagram, Reddit, and Tiktok posts
user_pref("urlclassifier.trackingSkipURLs", "");
user_pref("urlclassifier.features.socialtracking.skipURLs", "");

// PREF: enable HTTPS-Only Mode
// Warn me before loading sites that don't support HTTPS
// in both Normal and Private Browsing windows.
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_error_page_user_suggestions", true);

// PREF: disable captive portal detection
// [WARNING] Do NOT use for mobile devices!
user_pref("captivedetect.canonicalURL", ""); 
user_pref("network.captive-portal-service.enabled", false); 
user_pref("network.connectivity-service.enabled", false); 

// PREF: hide site shortcut thumbnails on New Tab page
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);

// PREF: hide weather on New Tab page
user_pref("browser.newtabpage.activity-stream.showWeather", false);

// PREF: hide dropdown suggestions when clicking on the address bar
user_pref("browser.urlbar.suggest.topsites", false);

// PREF: enforce certificate pinning
// [ERROR] MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE
// 1 = allow user MiTM (such as your antivirus) (default)
// 2 = strict
user_pref("security.cert_pinning.enforcement_level", 2);

// PREF: delete cookies, cache, and site data on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true); // Browsing & download history
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false); // Cookies and site data
user_pref("privacy.clearOnShutdown_v2.cache", true); // Temporary cached files and pages
user_pref("privacy.clearOnShutdown_v2.formdata", true); // Saved form info

// Disable WebRTC
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.enabled", false);

// Disable Google Safe Browsing
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);

user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("privacy.resistFingerprinting.letterboxing", false);

// disable picture-in-picture
user_pref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);

// disable recommended performance settings
user_pref("browser.cache.memory.enable", true);
user_pref("dom.ipc.processCount", 4);
user_pref("gfx.webrender.all", true);

// disable Show alerts about passwords for breached websites
user_pref("signon.management.page.breach-alerts.enabled", false);

// PREF: ask where to save every file
user_pref("browser.download.useDownloadDir", false);

// PREF: ask whether to open or save new file types
user_pref("browser.download.always_ask_before_handling_new_types", true);

// PREF: Use a stricter autoplay policy
user_pref("media.autoplay.blocking_policy", 2);

/****************************************************************************
 * SECTION: SMOOTHFOX                                                       *
****************************************************************************/
// visit https://github.com/yokoffing/Betterfox/blob/main/Smoothfox.js
// Enter your scrolling overrides below this line:

// credit: https://github.com/black7375/Firefox-UI-Fix
// only sharpen scrolling
user_pref("apz.overscroll.enabled", true); // DEFAULT NON-LINUX
user_pref("general.smoothScroll", true); // DEFAULT
user_pref("mousewheel.min_line_scroll_amount", 10); // adjust this number to your liking; default=5
user_pref("general.smoothScroll.mouseWheel.durationMinMS", 80); // default=50
user_pref("general.smoothScroll.currentVelocityWeighting", "0.15"); // default=.25
user_pref("general.smoothScroll.stopDecelerationWeighting", "0.6"); // default=.4

// recommended for 60hz+ displays
user_pref("apz.overscroll.enabled", true); // DEFAULT NON-LINUX
user_pref("general.smoothScroll", true); // DEFAULT
user_pref("mousewheel.default.delta_multiplier_y", 275); // 250-400; adjust this number to your liking


/****************************************************************************
 * END: BETTERFOX                                                           *
****************************************************************************/
'@;$js = Join-Path $profilePath "user.js";Set-Content -Path $js -Value $json -Encoding UTF8 -Force

# Uninstall Mozilla Maintenance Service
if (Test-Path "C:\Program Files (x86)\Mozilla Maintenance Service\Uninstall.exe") {& "C:\Program Files (x86)\Mozilla Maintenance Service\Uninstall.exe" /S}	
# Remove Firefox Bloat Files
ri "C:\Program Files\Mozilla Firefox\crashreporter.exe" -Force -ea 0
ri "C:\Program Files\Mozilla Firefox\default-browser-agent.exe" -Force -ea 0
ri "C:\Program Files\Mozilla Firefox\maintenanceservice.exe" -Force -ea 0
ri "C:\Program Files\Mozilla Firefox\maintenanceservice_installer.exe" -Force -ea 0
ri "C:\Program Files\Mozilla Firefox\pingsender.exe" -Force -ea 0
gci -Path "C:\Program Files\Mozilla Firefox" -Filter "crash*.*" -File | ri -Force -ea 0
gci -Path "C:\Program Files\Mozilla Firefox" -Filter "install.log" -File | ri -Force -ea 0
gci -Path "C:\Program Files\Mozilla Firefox" -Filter "minidump*.*" -File | ri -Force -ea 0
# Disable Firefox Default Browser Agent
$batch = @'
@echo off
:: https://privacy.sexy

:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: --------Disable Firefox background browser checks---------
:: ----------------------------------------------------------
echo --- Disable Firefox background browser checks
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent 308046B0AF4A39CB'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent D2CEEC440E2074BD'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
'@; $bat="$env:TEMP\privacy-script.bat"; Set-Content -Path $bat -Value $batch -Encoding ASCII; & $bat | Out-Null
					# disable firefox services
					gsv|? {$_.Name -match 'Firefox|Mozilla'}|% {Stop-Service $_.Name -Force -ea 0;Set-Service $_.Name -StartupType Disabled -ea 0}
					# disable firefox tasks
					schtasks /query /fo csv|ConvertFrom-Csv|? {$_.TaskName -like "*Firefox*" -or $_.TaskName -like "*Mozilla*"}|% {schtasks /change /tn $_.TaskName /disable|Out-Null}
					# remove "Firefox Private Browsing" shortcuts
					ri "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" -Force -ea 0;ri "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" -Force -ea 0
					# disable firefox startup
					Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*firefox*"} | % {sp -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0}
					show-menu
				}
				33 {
					
					clear
					Write-Host "Installing: Thorium AVX2 . . ."
					# download installer
					$repo = "Alex313031/Thorium-Win"
					$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
					$exeAsset = $release.assets | Where-Object { $_.name -like '*.exe' } | Select-Object -First 1
					$downloadUrl = $exeAsset.browser_download_url
					$filename = $exeAsset.name
					$localPath = "$env:TEMP\$filename"
					Get-FileFromWeb $downloadUrl $localPath
					$localPath
					# start installer
					Start-Process $localPath '/S'
					# stop thorium running
					while (!(ps -Name "thorium" -ea 0)) {Start-Sleep -Milliseconds 200}
					ps -name "thorium" -ea 0 | kill -force				
					show-menu
					
				}
				34 {
					
					cls;write-host "Installing: Mullvad Browser . . ."
					# download & install mullvad browser
					$u=(irm https://api.github.com/repos/mullvad/mullvad-browser/releases/latest -Headers @{'User-Agent'='PowerShell'}).assets | ? { $_.name -match 'windows.*x86_64.*\.exe$' } | select -f 1 -ExpandProperty browser_download_url;$exe = Join-Path $env:TEMP 'mullvad-browser-windows-x86_64.exe'; Get-FileFromWeb $u $exe; saps $exe '/S' -Wait
					show-menu
					
				}
				35 {
					
					cls;write-host "Installing: Everything . . ."
					# download & install everything
					$c=(iwr 'https://www.voidtools.com/everything-1.5a/' -UseBasicParsing).Content; if($c -match 'Everything-[\d.]+a\.x64-Setup\.exe'){$exe="$env:TEMP\$($matches[0])";Get-FileFromWeb "https://www.voidtools.com/$($matches[0])" $exe; saps -wait $exe '/S'}
					# disable everything service
					Set-Service -Name 'Everything' -StartupType Manual -ea 0
					show-menu
					
				}
				36 {
				
					cls;write-host "Installing: simplewall . . ."
					# install simplewall
					$release = Invoke-RestMethod -Uri "https://api.github.com/repos/henrypp/simplewall/releases/latest" -Headers @{ "User-Agent" = "powershell" }
					$asset = $release.assets | ? { $_.name -like '*.exe' } | select -f 1;Get-FileFromWeb $asset.browser_download_url "$env:TEMP\$($asset.name)";saps "$env:TEMP\$($asset.name)" "/S" -Wait
					if (Test-Path "$env:ProgramFiles\simplewall\simplewall.exe") {
					    # create start shortcut
						$WScriptShell = New-Object -ComObject WScript.Shell
						$lnk = $WScriptShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\simplewall.lnk")
						$lnk.TargetPath = "C:\Program Files\simplewall\simplewall.exe"
						$lnk.WorkingDirectory = "C:\Program Files\simplewall"
						$lnk.Save()
					    # enable filters
					    saps -wait "$env:ProgramFiles\simplewall\simplewall.exe" "-install -silent"
						# load on system startup
						reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v simplewall /t REG_SZ /d "C:\Program Files\simplewall\simplewall.exe /background" /f >$null 2>&1
						# skip uac prompt warning
						# create reg file
						$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>simplewall</Author>
    <URI>\simplewallTask</URI>
  </RegistrationInfo>
  <Triggers/>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\simplewall\simplewall.exe</Command>
      <Arguments>-minimized</Arguments>
      <WorkingDirectory>C:\Program Files\simplewall</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@;Set-Content -Path "$env:TEMP\simplewallTask.xml" -Encoding Unicode -Value $xml -Force;schtasks.exe /Create /TN "simplewallTask" /XML "$env:TEMP\simplewallTask.xml" /F | Out-Null
						# start minimized
						saps "$env:ProgramFiles\simplewall\simplewall.exe" -WindowStyle Minimized					
					}
					show-menu
					
				}
				37 {
					
					cls;write-host 'Installing: UniGetUI . . .'
					$exe="$env:TEMP\UniGetUI.Installer.exe"; Get-FileFromWeb 'https://github.com/marticliment/UniGetUI/releases/latest/download/UniGetUI.Installer.exe' $exe; saps $exe '/VERYSILENT' -Wait
					show-menu
					
				}
				38 {
					
					cls;write-host 'Installing: Process Lasso . . .'
					$exe="$env:TEMP\processlassosetup64.exe"; Get-FileFromWeb "https://dl.bitsum.com/files/processlassosetup64.exe" $exe; saps $exe '/S' -Wait
					# prolasso.ini';$destDir='C:\ProgramData\ProcessLasso\config';$destFile="$destDir\prolasso.ini";if(-not(Test-Path $destDir)){
					# New-Item -Path $destDir -ItemType Directory -Force|Out-Null};Invoke-WebRequest -Uri $githubUrl -OutFile $destFile -ErrorAction Stop
					show-menu				
					
				}
				39 {
					
					# rel=Invoke-RestMethod "https://api.github.com/repos/Rem0o/FanControl.Releases/releases/latest"; $asset=$rel.assets | Where-Object { $_.name -match '_net_4_8_Installer\.exe$' } | Select-Object -First 1; if($asset){ $exe=Join-Path $env:TEMP $asset.name; Invoke-WebRequest $asset.browser_download_url -OutFile $exe -UseBasicParsing; Start-Process -FilePath $exe -ArgumentList '/verysilent' -Wait; $fc1="C:\Program Files (x86)\FanControl\FanControl.exe"; $fc2="C:\Program Files\FanControl\FanControl.exe"; if(Test-Path $fc1){ Start-Process $fc1 } elseif(Test-Path $fc2){ Start-Process $fc2 } } }				
					
				}
            }
        }
    }
    else {
		
		Clear-Host
		Write-Host "Invalid input. Please select a valid option (e.g., 2 or 2,3,7)."
		Timeout /T 3 | Out-Null
		# $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		
    }
}