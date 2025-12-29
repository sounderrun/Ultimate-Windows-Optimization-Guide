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

$Host.UI.RawUI.WindowTitle = 'Overclock (Administrator)'	

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
	
cls
write-host "Installing: OCCT . . ."
# download occt
$exe="$env:TEMP\OCCT.exe"
Get-FileFromWeb 'https://www.ocbase.com/download/edition:Personal/os:Windows' $exe
# start occt
& $exe
cls
write-host ''
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
