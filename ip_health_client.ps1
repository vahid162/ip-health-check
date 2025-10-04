# ip_health_client.ps1 -- Windows PowerShell
# Outputs: table + ip_health_results.csv in the script folder.

$IPs = @(
  "1.1.1.1","8.8.8.8"
)

# Optional: map hostnames for SNI tests (if you own domains)
$SniMap = @{
  # "45.76.81.223" = "yourdomain.com"
}

function Get-OpenSSLExe {
  $cmd = Get-Command openssl -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "$env:SystemRoot\System32\openssl.exe"
  )
  foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
  return $null
}

$OpenSSL = Get-OpenSSLExe
if (-not $OpenSSL) { Write-Host "Note: OpenSSL not found; TLS tests will be skipped." }

function Test-HttpHead {
  param([string]$IP)
  try {
    $out = & "$env:SystemRoot\System32\curl.exe" -I --max-time 6 "http://$IP/" 2>&1
    return [bool]($out -match "HTTP\/[0-3\.]+\s+(2|3)\d\d")
  } catch { return $false }
}

function Test-TlsBundle {
  param([string]$IP, [string]$HostName)

  if (-not $OpenSSL) {
    return [pscustomobject]@{ TLS13=$null; TLS12=$null; ALPN=$null; NoSNI=$null; WithSNI=$null }
  }

  # خروجی‌های ممکن s_client: CONNECTION ESTABLISHED | CONNECTED(...) | Protocol version:
  $successRegex = '(?ms)(CONNECTION ESTABLISHED|^CONNECTED|\bProtocol version:)'

  function Run-SSLArgs {
    param([string[]]$ArgList)
    $out = ("" | & $OpenSSL @ArgList 2>&1) -join "`n"
    $code = $LASTEXITCODE
    $isFail = ($out -match 'handshake failure|alert handshake|unexpected eof')
    return ,$out,$code,$isFail
  }

  $res = [ordered]@{ TLS13=$false; TLS12=$false; ALPN=$null; NoSNI=$false; WithSNI=$null }

  # TLS 1.3
  $r = Run-SSLArgs @('s_client','-connect',"$IP`:443",'-tls1_3','-brief','-alpn','h2,http/1.1','-ign_eof')
  $o13,$c13,$f13 = $r[0],$r[1],$r[2]
  if (($o13 -match $successRegex -or $c13 -eq 0) -and -not $f13) { $res.TLS13 = $true }
  if ($o13 -match 'ALPN protocol:\s*(\S+)') { $res.ALPN = $Matches[1] }

  # TLS 1.2
  $r = Run-SSLArgs @('s_client','-connect',"$IP`:443",'-tls1_2','-brief','-ign_eof')
  $o12,$c12,$f12 = $r[0],$r[1],$r[2]
  if (($o12 -match $successRegex -or $c12 -eq 0) -and -not $f12) { $res.TLS12 = $true }

  # بدون SNI
  $r = Run-SSLArgs @('s_client','-connect',"$IP`:443",'-brief','-ign_eof')
  $o0,$c0,$f0 = $r[0],$r[1],$r[2]
  if (($o0 -match $successRegex -or $c0 -eq 0) -and -not $f0) { $res.NoSNI = $true }

  # با SNI (اگر دامنه دادی)
  if ($HostName) {
    $r = Run-SSLArgs @('s_client','-connect',"$IP`:443",'-servername',$HostName,'-brief','-alpn','h2,http/1.1','-ign_eof')
    $oS,$cS,$fS = $r[0],$r[1],$r[2]
    $res.WithSNI = (($oS -match $successRegex -or $cS -eq 0) -and -not $fS)
    if (-not $res.ALPN -and $oS -match 'ALPN protocol:\s*(\S+)') { $res.ALPN = $Matches[1] }
  }

  return [pscustomobject]$res
}

$rows = @()

foreach ($ip in $IPs) {
  # ICMP (optional)
  $icmpOK = $false
  try { $icmpOK = Test-Connection -TargetName $ip -Count 1 -Quiet -ErrorAction Stop } catch { $icmpOK = $false }

  # TCP
  $t80  = Test-NetConnection -ComputerName $ip -Port 80  -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
  $t443 = Test-NetConnection -ComputerName $ip -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

  # HTTP HEAD
  $httpHeadOK = $false
  if ($t80 -and $t80.TcpTestSucceeded) { $httpHeadOK = Test-HttpHead -IP $ip }

  # TLS bundle
  $hn = $SniMap[$ip]
  $tls = Test-TlsBundle -IP $ip -HostName $hn

  # Verdict
  $verdict = "Unknown"
  if ($t443 -and $t443.TcpTestSucceeded)      { $verdict = "TCP 443 OK" }
  elseif ($t80 -and $t80.TcpTestSucceeded)    { $verdict = "TCP 80 OK" }
  elseif ($icmpOK)                             { $verdict = "Ping OK but 80/443 closed" }
  else                                         { $verdict = "ICMP blocked; check TCP" }

  $rows += [pscustomobject]@{
    IP            = $ip
    ICMP          = [bool]$icmpOK
    TCP80         = if ($t80)  { [bool]$t80.TcpTestSucceeded } else { $false }
    TCP443        = if ($t443) { [bool]$t443.TcpTestSucceeded } else { $false }
    HTTP_Head80   = [bool]$httpHeadOK
    TLS13         = $tls.TLS13
    TLS12         = $tls.TLS12
    TLS_NoSNI443  = $tls.NoSNI
    TLS_WithSNI443= $tls.WithSNI
    ALPN          = $tls.ALPN
    SNI_Host      = $hn
    Verdict       = $verdict
  }
}

$rows | Format-Table -AutoSize
$csv = Join-Path $PSScriptRoot 'ip_health_results.csv'
$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host "`nSaved CSV: $csv"
