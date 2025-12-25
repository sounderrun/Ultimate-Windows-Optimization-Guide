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

$Host.UI.RawUI.WindowTitle = 'Edge Updates (Administrator)'
$ProgressPreference = 'SilentlyContinue'

# Clear Edge Blocks
& {$(Invoke-RestMethod "https://github.com/he3als/EdgeRemover/raw/refs/heads/main/ClearUpdateBlocks.ps1")} -Silent *>$null

# policies
$MultilineComment = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
[-HKEY_CURRENT_USER\Software\Policies\Microsoft\Edge]
[-HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\EdgeUpdate]
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker]
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"ApplicationGuardFavoritesSyncEnabled"=dword:00000000
"ApplicationGuardPassiveModeEnabled"=dword:00000000
"ApplicationGuardTrafficIdentificationEnabled"=dword:00000000
"ApplicationGuardUploadBlockingEnabled"=dword:00000000
"TyposquattingCheckerEnabled"=dword:00000000
"EdgeWorkspacesEnabled"=dword:00000000
"ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled"=dword:00000001
"BlockExternalExtensions"=dword:00000000
"GenAILocalFoundationalModelSettings"=dword:00000001
"ImplicitSignInEnabled"=dword:00000000
"ProactiveAuthWorkflowEnabled"=dword:00000000
"SeamlessWebToBrowserSignInEnabled"=dword:00000000
"WebToBrowserSignInEnabled"=dword:00000000
"EdgeManagementEnabled"=dword:00000000
"EdgeManagementExtensionsFeedbackEnabled"=dword:00000000
"MAMEnabled"=dword:00000000
"PasswordManagerEnabled"=dword:00000000
"PasswordMonitorAllowed"=dword:00000000
"PasswordExportEnabled"=dword:00000000
"PasswordGeneratorEnabled"=dword:00000000
"PasswordRevealEnabled"=dword:00000000
"ExtensionsPerformanceDetectorEnabled"=dword:00000000
"PerformanceDetectorEnabled"=dword:00000000
"PinBrowserEssentialsToolbarButton"=dword:00000000
"StartupBoostEnabled"=dword:00000000
"RelatedWebsiteSetsEnabled"=dword:00000000
"ScarewareBlockerProtectionEnabled"=dword:00000000
"SmartScreenEnabled"=dword:00000000
"SmartScreenPuaEnabled"=dword:00000000
"SmartScreenForTrustedDownloadsEnabled"=dword:00000000
"SmartScreenDnsRequestsEnabled"=dword:00000000
"NewTabPageAllowedBackgroundTypes"=dword:00000000
"NewTabPageAppLauncherEnabled"=dword:00000000
"NewTabPageBingChatEnabled"=dword:00000000
"NewTabPageContentEnabled"=dword:00000000
"NewTabPageHideDefaultTopSites"=dword:00000001
"NewTabPagePrerenderEnabled"=dword:00000000
"NewTabPageQuickLinksEnabled"=dword:00000000
"AADWebSiteSSOUsingThisProfileEnabled"=dword:00000000
"AccessibilityImageLabelsEnabled"=dword:00000000
"AIGenThemesEnabled"=dword:00000000
"AllowGamesMenu"=dword:00000000
"AlternateErrorPagesEnabled"=dword:00000000
"AmbientAuthenticationInPrivateModesEnabled"=dword:00000000
"BingAdsSuppression"=dword:00000001
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"ComposeInlineEnabled"=dword:00000000
"ConfigureDoNotTrack"=dword:00000001
"DiagnosticData"=dword:00000000
"Edge3PSerpTelemetryEnabled"=dword:00000000
"EdgeAssetDeliveryServiceEnabled"=dword:00000000
"EdgeCollectionsEnabled"=dword:00000000
"EdgeEDropEnabled"=dword:00000000
"EdgeHistoryAISearchEnabled"=dword:00000000
"EdgeShoppingAssistantEnabled"=dword:00000000
"EdgeWalletCheckoutEnabled"=dword:00000000
"EdgeWalletEtreeEnabled"=dword:00000000
"ExperimentationAndConfigurationServiceControl"=dword:00000000
"ForceSync"=dword:00000000
"HttpsUpgradesEnabled"=dword:00000001
"HubsSidebarEnabled"=dword:00000000
"InAppSupportEnabled"=dword:00000000
"InternetExplorerIntegrationLevel"=dword:00000000
"LiveCaptionsAllowed"=dword:00000000
"LocalProvidersEnabled"=dword:00000000
"MicrosoftEdgeInsiderPromotionEnabled"=dword:00000000
"MicrosoftEditorProofingEnabled"=dword:00000000
"MicrosoftEditorSynonymsEnabled"=dword:00000000
"MicrosoftOfficeMenuEnabled"=dword:00000000
"NonRemovableProfileEnabled"=dword:00000000
"PaymentMethodQueryEnabled"=dword:00000000
"PersonalizationReportingEnabled"=dword:00000000
"PersonalizeTopSitesInCustomizeSidebarEnabled"=dword:00000000
"PictureInPictureOverlayEnabled"=dword:00000000
"PromotionalTabsEnabled"=dword:00000000
"PromptForDownloadLocation"=dword:00000001
"ReadAloudEnabled"=dword:00000000
"ResolveNavigationErrorsUseWebService"=dword:00000000
"SearchSuggestEnabled"=dword:00000000
"SharedLinksEnabled"=dword:00000000
"ShowAcrobatSubscriptionButton"=dword:00000000
"ShowMicrosoftRewards"=dword:00000000
"ShowOfficeShortcutInFavoritesBar"=dword:00000000
"ShowRecommendationsEnabled"=dword:00000000
"SpeechRecognitionEnabled"=dword:00000000
"SpellcheckEnabled"=dword:00000000
"StandaloneHubsSidebarEnabled"=dword:00000000
"TextPredictionEnabled"=dword:00000000
"TranslateEnabled"=dword:00000001
"UploadFromPhoneEnabled"=dword:00000000
"UrlDiagnosticDataEnabled"=dword:00000000
"UserFeedbackAllowed"=dword:00000000
"VisualSearchEnabled"=dword:00000000
"WalletDonationEnabled"=dword:00000000
"WebWidgetAllowed"=dword:00000000
"DefaultGeolocationSetting"=dword:00000002
"DefaultNotificationsSetting"=dword:00000002
"DefaultLocalFontsSetting"=dword:00000002
"DefaultSensorsSetting"=dword:00000002
"DefaultSerialGuardSetting"=dword:00000002
"SafeBrowsingDeepScanningEnabled"=dword:00000000
"SafeBrowsingProxiedRealTimeChecksAllowed"=dword:00000000
"SafeBrowsingSurveysEnabled"=dword:00000000
"ForceGoogleSafeSearch"=dword:00000000
"BatterySaverModeAvailability"=dword:00000000
"VideoCaptureAllowed"=dword:00000000
"WPADQuickCheckEnabled"=dword:00000000
"ScreenCaptureAllowed"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"DefaultBrowserSettingEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"ExtensionManifestV2Availability"=dword:00000002
"HideFirstRunExperience"=dword:00000001
"SearchInSidebarEnabled"=dword:00000002
"GuidedSwitchEnabled"=dword:00000000
"EdgeDefaultProfileEnabled"="Default"
"AutoImportAtFirstRun"=dword:00000004
"BrowserAddProfileEnabled"=dword:00000000
"ConfigureOnPremisesAccountAutoSignIn"=dword:00000000
"ConfigureOnlineTextToSpeech"=dword:00000000
"ConfigureShare"=dword:00000000
"DefaultBrowserSettingsCampaignEnabled"=dword:00000000
"ImportOnEachLaunch"=dword:00000000
"LocalBrowserDataShareEnabled"=dword:00000000
"MSAWebSiteSSOUsingThisProfileAllowed"=dword:00000000
"PinningWizardAllowed"=dword:00000000
"QuickSearchShowMiniMenu"=dword:00000000
"QuickViewOfficeFilesEnabled"=dword:00000000
"RemoteDebuggingAllowed"=dword:00000000
"RoamingProfileSupportEnabled"=dword:00000000
"SearchForImageEnabled"=dword:00000000
"SearchFiltersEnabled"=dword:00000000
"SearchbarAllowed"=dword:00000000
"SearchbarIsEnabledOnStartup"=dword:00000000
"NewTabPageSearchBox"="redirect"
"PasswordProtectionWarningTrigger"=dword:00000000
"AskBeforeCloseEnabled"=dword:00000000
"AutofillAddressEnabled"=dword:00000000
"AutofillMembershipsEnabled"=dword:00000000
"AADWebSSOAllowed"=dword:00000000
"AccessCodeCastEnabled"=dword:00000000
"AdsTransparencyEnabled"=dword:00000000
"EdgeAdminCenterEnabled"=dword:00000000
"NetworkPredictionOptions"=dword:00000002
"TrackingPrevention"=dword:00000003
"SigninInterceptionEnabled"=dword:00000000
"SideSearchEnabled"=dword:00000000
"ShowPDFDefaultRecommendationsEnabled"=dword:00000000
"ShowHomeButton"=dword:00000000
"PasswordDismissCompromisedAlertEnabled"=dword:00000000
"HighEfficiencyModeEnabled"=dword:00000000
"DesktopSharingHubEnabled"=dword:00000000
"CopilotPageContextEnabled"=dword:00000000
"CopilotPageContext"=dword:00000000
"QRCodeGeneratorEnabled"=dword:00000000
"SpotlightExperiencesAndRecommendationsEnabled"=dword:00000000
"EdgeAutofillMlEnabled"=dword:00000000
"EdgeEntraCopilotPageContext"=dword:00000000
"MouseGestureEnabled"=dword:00000000
"DisableScreenshots"=dword:00000000
"WebCaptureEnabled"=dword:00000001
"AddressBarWorkSearchResultsEnabled"=dword:00000000
"AddressBarTrendingSuggestEnabled"=dword:00000000
"BuiltInAIAPIsEnabled"=dword:00000000
"AllowSystemNotifications"=dword:00000000
"AutoplayAllowed"=dword:00000000
"ClickOnceEnabled"=dword:00000000
"InternetExplorerIntegrationReloadInIEModeAllowed"=dword:00000000
"HideInternetExplorerRedirectUXForIncompatibleSitesEnabled"=dword:00000001
"FamilySafetySettingsEnabled"=dword:00000000
"Microsoft365CopilotChatIconEnabled"=dword:00000000
"HttpsOnlyMode"="force_enabled"
"DnsOverHttpsMode"="off"
"BlockThirdPartyCookies"=dword:00000001
"WebRtcLocalhostIpHandling"="disable_non_proxied_udp"
"LiveVideoTranslationEnabled"=dword:00000000
"HomepageIsNewTabPage"=dword:00000001
"HomepageLocation"="https://search.brave.com/"
"NewTabPageLocation"="data:text/html,<html><head><title>New tab</title><meta name='color-scheme' content='light dark'><style>html,body{margin:0;padding:0;height:100%;}@media (prefers-color-scheme: dark){body{background-color:#000000;}}@media (prefers-color-scheme: light){body{background-color:#FFFFFF;}}</style></head><body></body></html>"
"PrintingEnabled"=dword:00000000
"SuppressUnsupportedOSWarning"=dword:00000001
"DefaultPopupsSetting"=dword:00000002
"DefaultSearchProviderEnabled"=dword:00000001
"DefaultSearchProviderName"="Brave"
"DefaultSearchProviderSearchURL"="https://search.brave.com/search?q={searchTerms}"
"DefaultSearchProviderSuggestURL"="https://search.brave.com/api/suggest?q={searchTerms}"
"EdgeAutofillMlEnabled"=dword:00000000
"HardwareAccelerationModeEnabled"=dword:00000000
"TabServicesEnabled"=dword:00000000
"AllowDeletingBrowserHistory"=dword:00000001
"ClearCachedImagesAndFilesOnExit"=dword:00000001
"ClearWindowNameForNewBrowsingContextGroup"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist]
"1"="odfafepnkmbhccpbejgmiehpchacaeak;https://edge.microsoft.com/extensionwebstorebase/v1/crx"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled]
"1"="favorites"
"2"="settings"
"3"="passwords"
"4"="addressesAndMore"
"5"="extensions"
"6"="history"
"7"="openTabs"
"8"="edgeWallet"
"9"="collections"
"10"="apps"
"11"="edgeFeatureUsage"

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

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"CreateDesktopShortcutDefault"=dword:00000000
"UpdateDefault"=dword:00000001
"UpdateDefault"=dword:00000001
"AutoUpdateCheckPeriodMinutes"=dword:00000000
"Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"=dword:00000001
"Update{2CD8A007-E189-4D47-B5A4-DD5A7A6D2766}"=dword:00000001
"Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}"=dword:00000001

[HKEY_CLASSES_ROOT\.pdf]
@="AcroExch.Document.DC"

[HKEY_CLASSES_ROOT\.pdf\OpenWithProgids]
"AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723"=-

[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"MicrosoftEdgeDataOptIn"=dword:00000000

[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader]
"AllowTabPreloading"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Wow6432Node\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000
'@; Set-Content -Path "$env:TEMP\Edge.reg" -Value $MultilineComment -Force -Encoding ASCII; reg import "$env:TEMP\Edge.reg" *>$null
# disable edge scheduled tasks
Get-ScheduledTask | ? { $_.TaskName -like "*Edge*" } | % { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }
# disable startup
Get-CimInstance Win32_StartupCommand | ? {$_.Name -like "*edge*"} | % {sp -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name $_.Name -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -ea 0}
# open web browser
saps "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"