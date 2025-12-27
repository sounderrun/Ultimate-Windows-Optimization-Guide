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

$Host.UI.RawUI.WindowTitle = 'Direct X (Administrator)'

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

# temp folder cleanup
gci "C:\Windows\Temp" *.* -recurse | ri -force -recurse -ea 0
gci $env:TEMP *.* -recurse | ri -force -recurse -ea 0

$progresspreference = 'silentlycontinue'
Write-Host "Installing: Direct X . . ."
# download & install direct x
ri "$env:TEMP\DirectX" -recurse -force -ea 0
try {
	Get-FileFromWeb "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe" "$env:TEMP\DirectX.exe"
	saps "$env:TEMP\DirectX.exe" -WindowStyle Hidden "/q /t:`"$env:TEMP\DirectX`"" -wait
	saps "$env:TEMP\DirectX\DXSETUP.exe" "/silent" -wait
} catch {
	$exe="$env:TEMP\dxwebsetup.exe"
	Get-FileFromWeb "https://download.microsoft.com/download/1/7/1/1718ccc4-6315-4d8e-9543-8e28a4e18c4c/dxwebsetup.exe" $exe
	saps $exe '/Q' -wait
}

# remove "DirectX Configuration Database" capability
Remove-WindowsCapability -Online -Name "DirectX.Configuration.Database~~~~0.0.1.0" | Out-Null

# direct x tweaks
# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

; Clear DirectX recent application history
[-HKEY_CURRENT_USER\Software\Microsoft\Direct3D\MostRecentApplication]

[HKEY_CURRENT_USER\Software\Microsoft\Direct3D\MostRecentApplication]

; directx
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectDraw]
"DisableAGPSupport"=dword:00000000
"UseNonLocalVidMem"=dword:00000001
"DisableDDSCAPSInDDSD"=dword:00000000
"EmulationOnly"=dword:00000000
"EmulatePointSprites"=dword:00000000
"EmulateStateBlocks"=dword:00000000
"DisableMMX"=dword:00000000
"ForceNoSysLock"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\DirectDraw]
"DisableAGPSupport"=dword:00000000
"UseNonLocalVidMem"=dword:00000001
"DisableDDSCAPSInDDSD"=dword:00000000
"EmulationOnly"=dword:00000000
"EmulatePointSprites"=dword:00000000
"EmulateStateBlocks"=dword:00000000
"DisableMMX"=dword:00000000
"ForceNoSysLock"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D]
"UseNonLocalVidMem"=dword:00000001
"EnableDebugging"=dword:00000000
"FullDebug"=dword:00000000
"DisableDM"=dword:00000001
"EnableMultimonDebugging"=dword:00000000
"LoadDebugRuntime"=dword:00000000
"FewVertices"=dword:00000001
"DisableMMX"=dword:00000000
"MMX Fast Path"=dword:00000001
"MMXFastPath"=dword:00000001
"UseMMXForRGB"=dword:00000001
"DisableVidMemVBs"=dword:00000000
"FlipNoVsync"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Direct3D]
"UseNonLocalVidMem"=dword:00000001
"FewVertices"=dword:00000001
"DisableMMX"=dword:00000000
"MMX Fast Path"=dword:00000001
"MMXFastPath"=dword:00000001
"UseMMXForRGB"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Drivers]
"ForceRgbRasterizer"=dword:00000000
"EnumReference"=dword:00000001
"EnumSeparateMMX"=dword:00000001
"EnumRamp"=dword:00000001
"EnumNullDevice"=dword:00000001
"UseMMXForRGB"=dword:00000001
"SoftwareOnly"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers]
"ForceRgbRasterizer"=dword:00000000
"EnumReference"=dword:00000001
"EnumSeparateMMX"=dword:00000001
"EnumRamp"=dword:00000001
"EnumNullDevice"=dword:00000001
"UseMMXForRGB"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"DpiMapIommuContiguous"=dword:00000001
"HwSchedMode"=dword:00000002

; Tweak directx driver service
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl]
"MonitorLatencyTolerance"=dword:00000001
"MonitorRefreshLatencyTolerance"=dword:00000001

; disable variable refresh rate & enable optimizations for windowed games
[HKEY_CURRENT_USER\Software\Microsoft\DirectX\UserGpuPreferences]
"DirectXUserGlobalSettings"="SwapEffectUpgradeEnable=1;VRROptimizeEnable=0;"

; D3D11 - D3D12 Tweaks
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX]
"D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE"=dword:00000001
"D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS"=dword:00000001
"D3D12_RESOURCE_ALIGNMENT"=dword:00000001
"D3D11_MULTITHREADED"=dword:00000001
"D3D12_MULTITHREADED"=dword:00000001
"D3D11_DEFERRED_CONTEXTS"=dword:00000001
"D3D12_DEFERRED_CONTEXTS"=dword:00000001
"D3D11_ALLOW_TILING"=dword:00000001
"D3D11_ENABLE_DYNAMIC_CODEGEN"=dword:00000001
"D3D12_ALLOW_TILING"=dword:00000001
"D3D12_CPU_PAGE_TABLE_ENABLED"=dword:00000001
"D3D12_HEAP_SERIALIZATION_ENABLED"=dword:00000001
"D3D12_MAP_HEAP_ALLOCATIONS"=dword:00000001
"D3D12_RESIDENCY_MANAGEMENT_ENABLED"=dword:00000001

; DirectX Driver DXGKrnl Advanced Tweaks (2)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl]
"CreateGdiPrimaryOnSlaveGPU"=dword:00000001
"DriverSupportsCddDwmInterop"=dword:00000001
"DxgkCddSyncDxAccess"=dword:00000001
"DxgkCddSyncGPUAccess"=dword:00000001
"DxgkCddWaitForVerticalBlankEvent"=dword:00000001
"DxgkCreateSwapChain"=dword:00000001
"DxgkFreeGpuVirtualAddress"=dword:00000001
"DxgkOpenSwapChain"=dword:00000001
"DxgkShareSwapChainObject"=dword:00000001
"DxgkWaitForVerticalBlankEvent"=dword:00000001
"DxgkWaitForVerticalBlankEvent2"=dword:00000001
"SwapChainBackBuffer"=dword:00000001
"TdrResetFromTimeoutAsync"=dword:00000001
'@
set-content "$env:TEMP\DirectX.reg" -value $MultilineComment -force
# import reg file
reg import "$env:TEMP\DirectX.reg" 2> $null