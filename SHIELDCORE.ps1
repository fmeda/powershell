<#
.SYNOPSIS
  AEGIS-NET OPS - SecurityOps Enterprise — ProdReady Fixed v2
  Correções adicionais: remove $using:, robust count, param validation, safer Ensure-Module.
.DESCRIPTION
  Execute primeiro em DryRun com ranges pequenos.
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(Mandatory=$true, HelpMessage="Ranges: CIDR(s) separadas por vírgula/; ou intervalos start-end")]
    [string]$Ranges,

    [Parameter(Mandatory=$false)]
    [switch]$EnableMDE,

    [Parameter(Mandatory=$false)]
    [switch]$EnableIntune,

    [Parameter(Mandatory=$false)]
    [switch]$DryRun,

    [Parameter(Mandatory=$false)]
    [switch]$EnableRemediate,

    [Parameter(Mandatory=$false)]
    [switch]$ConfirmRemediate,

    [Parameter(Mandatory=$false)]
    [ValidateSet("ManagedIdentity","KeyVault","CredentialManager","Interactive")]
    [string]$AuthMode = "ManagedIdentity",

    [Parameter(Mandatory=$false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory=$false)]
    [string]$CredentialTarget = "SecurityOpsGraph",

    [Parameter(Mandatory=$false)]
    [ValidateRange(1,200)]
    [int]$Threads = 25,

    [Parameter(Mandatory=$false)]
    [string]$Export = "csv,json",

    [Parameter(Mandatory=$false)]
    [string]$SiemEndpoint,

    [Parameter(Mandatory=$false)]
    [switch]$VerboseMode
)

# Basic validation
if ($Threads -le 0) { throw "Threads deve ser > 0" }
if (-not $Ranges) { throw "Informe --Ranges" }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TimeStamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$LogDir = Join-Path $ScriptRoot "logs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir "aegisnetops_securityops_$TimeStamp.json"
$ReportDir = Join-Path $ScriptRoot "reports"
if (-not (Test-Path $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory | Out-Null }

$Telemetry = [ordered]@{
    startTime = (Get-Date).ToString('o')
    totalIPs = 0
    processed = 0
    mdeFound = 0
    intuneFound = 0
    avgLatencyMs = 0.0
    errors = 0
}

function Ensure-Module {
    param([string]$Name)
    try {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-Log ("Módulo {0} não encontrado localmente. Por favor instale manualmente: Install-Module -Name {0} -Scope CurrentUser" -f $Name) "WARN"
            return $false
        }
        Import-Module $Name -ErrorAction Stop
        return $true
    } catch {
        $err = $_.Exception.Message
        Write-Log ("Falha ao importar módulo {0}: {1}" -f $Name, $err) "WARN"
        return $false
    }
}

# Try to import commonly required modules; if not present, warn and continue
$mods = @('Az.Accounts','Az.KeyVault','CredentialManager','Microsoft.Graph')
foreach ($m in $mods) { Ensure-Module -Name $m | Out-Null }

function Sanitize-Context {
    param([hashtable]$ctx)
    if (-not $ctx) { return $null }
    $safe = @{}
    foreach ($k in $ctx.Keys) {
        if ($k -match '(token|secret|password|passwd|client_secret|clientsecret|authorization)') {
            $safe[$k] = '***REDACTED***'
        } else {
            $safe[$k] = $ctx[$k]
        }
    }
    return $safe
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("DEBUG","INFO","WARN","ERROR")][string]$Level = "INFO",
        [hashtable]$Context = $null
    )
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        level     = $Level
        message   = $Message
        context   = (Sanitize-Context -ctx $Context)
        host      = $env:COMPUTERNAME
        user      = $env:USERNAME
    }
    $entry | ConvertTo-Json -Depth 6 | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($VerboseMode -or $Level -eq "ERROR" -or $Level -eq "WARN") {
        switch ($Level) {
            "ERROR" { Write-Host ("[ERROR] {0}" -f $Message) -ForegroundColor Red }
            "WARN"  { Write-Host ("[WARN]  {0}" -f $Message) -ForegroundColor Yellow }
            default { Write-Host ("[INFO]  {0}" -f $Message) -ForegroundColor Cyan }
        }
    }
}

# EventLog safe creation
try {
    $sourceName = "AEGIS-NETOPS-SecurityOps"
    if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
        try { New-EventLog -LogName Application -Source $sourceName -ErrorAction Stop; Write-Log ("EventLog source criado: {0}" -f $sourceName) "INFO" } catch { Write-Log "Não foi possível criar EventLog source (provavelmente sem privilégios). Continuando." "WARN" }
    }
} catch { Write-Log ("Erro EventLog check: {0}" -f $_.Exception.Message) "WARN" }

function Invoke-WithRetry {
    param(
        [ScriptBlock]$Script,
        [int]$MaxAttempts = 4,
        [int]$BaseDelayMs = 500
    )
    for ($i=1; $i -le $MaxAttempts; $i++) {
        try {
            return & $Script
        } catch {
            $exMsg = $_.Exception.Message
            $isTransient = $false
            if ($exMsg -match "429" -or $exMsg -match "timeout" -or $exMsg -match "5\d{2}") { $isTransient = $true }

            if ($exMsg -match "401" -or $exMsg -match "403") {
                Write-Log "401/403 detectado - tentando refresh tokens (uma vez)..." "WARN"
                try {
                    $global:Tokens = Get-AuthTokens
                    Write-Log "Tokens atualizados via Get-AuthTokens." "INFO"
                    if ($i -lt $MaxAttempts) { continue }
                } catch {
                    Write-Log ("Falha refresh tokens: {0}" -f $_.Exception.Message) "ERROR"
                    throw $_
                }
            }

            if (-not $isTransient -or $i -eq $MaxAttempts) {
                Write-Log ("Erro final após tentativas: {0}" -f $exMsg) "ERROR"
                throw $_
            }
            $delay = [int]([math]::Pow(2,$i) * $BaseDelayMs)
            Write-Log ("Retry {0}/{1} depois de {2}ms. Erro: {3}" -f $i, $MaxAttempts, $delay, $exMsg) "WARN"
            Start-Sleep -Milliseconds $delay
        }
    }
}

function Get-AuthTokens {
    param()
    $out = @{ GraphToken = $null; DefenderToken = $null }
    switch ($AuthMode) {
        "ManagedIdentity" {
            Write-Log "AuthMode: ManagedIdentity" "INFO"
            try {
                $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/" -ErrorAction Stop
                $out.GraphToken = $token.Token
                $def = Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com" -ErrorAction Stop
                $out.DefenderToken = $def.Token
                return $out
            } catch { Write-Log ("ManagedIdentity auth falhou: {0}" -f $_.Exception.Message) "ERROR"; throw $_ }
        }
        "KeyVault" {
            if (-not $KeyVaultName) { throw "KeyVaultName obrigatório" }
            Write-Log "AuthMode: KeyVault" "INFO"
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $clientSecret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "GraphClientSecret" -ErrorAction Stop).SecretValueText
            $clientId = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "GraphClientId" -ErrorAction Stop).SecretValueText
            $tenantId = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "GraphTenantId" -ErrorAction Stop).SecretValueText
            $body = @{ client_id=$clientId; scope="https://graph.microsoft.com/.default"; client_secret=$clientSecret; grant_type="client_credentials" }
            $resp = Invoke-WithRetry -Script { Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body -ErrorAction Stop }
            $out.GraphToken = $resp.access_token
            $body.scope = "https://api.securitycenter.microsoft.com/.default"
            $resp2 = Invoke-WithRetry -Script { Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body -ErrorAction Stop }
            $out.DefenderToken = $resp2.access_token
            return $out
        }
        "CredentialManager" {
            Write-Log "AuthMode: CredentialManager" "INFO"
            $cred = Get-StoredCredential -Target $CredentialTarget -ErrorAction Stop
            if (-not $cred) { throw "Credencial não encontrada: $CredentialTarget" }
            $clientId = $cred.UserName; $clientSecret = $cred.Password
            $tenant = (Get-ItemProperty HKLM:\SOFTWARE\SecurityOps -ErrorAction SilentlyContinue).TenantId
            if (-not $tenant) { throw "TenantId não encontrado no registry." }
            $body = @{ client_id=$clientId; scope="https://graph.microsoft.com/.default"; client_secret=$clientSecret; grant_type="client_credentials" }
            $resp = Invoke-WithRetry -Script { Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $body -ErrorAction Stop }
            $out.GraphToken = $resp.access_token
            $body.scope = "https://api.securitycenter.microsoft.com/.default"
            $resp2 = Invoke-WithRetry -Script { Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $body -ErrorAction Stop }
            $out.DefenderToken = $resp2.access_token
            return $out
        }
        "Interactive" {
            Write-Log "AuthMode: Interactive" "INFO"
            Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All","SecurityEvents.Read.All" -ErrorAction Stop
            $ctx = Get-MgContext
            $out.GraphToken = $ctx.AccessToken
            $out.DefenderToken = $ctx.AccessToken
            return $out
        }
        default { throw ("AuthMode inválido: {0}" -f $AuthMode) }
    }
}

if ($DryRun) {
    Write-Log "DryRun ativo: tokens não serão solicitados" "WARN"
    $global:Tokens = @{ GraphToken = $null; DefenderToken = $null }
} else {
    $global:Tokens = Get-AuthTokens
}

function Get-IPChunksFromRange {
    param([string]$RangeString, [int]$ChunkSize=1000)
    if ($RangeString -match "/") {
        $parts = $RangeString.Split('/')
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        $prefix = [int]$parts[1]
        if ($prefix -lt 1 -or $prefix -gt 32) { throw "Prefix inválido: $prefix" }
        if ($prefix -lt 16) { Write-Log ("Prefix {0} é amplo (<= /15). Considere reduzir o escopo." -f $prefix) "WARN" }
        $bytes = $ip.GetAddressBytes(); [Array]::Reverse($bytes); $net = [BitConverter]::ToUInt32($bytes,0)
        $hostBits = 32 - $prefix
        $count = [int]([math]::Pow(2,$hostBits) - 2)
        if ($count -le 0) { return }
        $start = $net + 1; $end = $net + $count; $cur = $start
        while ($cur -le $end) {
            $list = New-Object System.Collections.Generic.List[string]
            for ($i=0; $i -lt $ChunkSize -and $cur -le $end; $i++, $cur++) {
                $b = [BitConverter]::GetBytes([uint32]$cur); [Array]::Reverse($b)
                $list.Add([System.Net.IPAddress]::new($b).ToString())
            }
            Write-Output $list.ToArray()
        }
    } elseif ($RangeString -match "-") {
        $parts = $RangeString.Split('-')
        $start = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes(); [Array]::Reverse($start); $si = [BitConverter]::ToUInt32($start,0)
        $end = [System.Net.IPAddress]::Parse($parts[1]).GetAddressBytes(); [Array]::Reverse($end); $ei = [BitConverter]::ToUInt32($end,0)
        $cur = $si
        while ($cur -le $ei) {
            $list = New-Object System.Collections.Generic.List[string]
            for ($i=0; $i -lt $ChunkSize -and $cur -le $ei; $i++, $cur++) {
                $b = [BitConverter]::GetBytes([uint32]$cur); [Array]::Reverse($b)
                $list.Add([System.Net.IPAddress]::new($b).ToString())
            }
            Write-Output $list.ToArray()
        }
    } else {
        Write-Output $RangeString
    }
}

$rangeList = $Ranges -split ';|,|\s+' | Where-Object { $_ -ne '' }
if ($rangeList.Count -eq 0) { throw "Nenhum range válido informado." }

$blocked = @("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
foreach ($r in $rangeList) {
    if ($blocked -contains $r) { Write-Log ("Range bloqueado por política: {0}" -f $r) "ERROR"; throw ("Range bloqueado: {0}" -f $r) }
}

function Invoke-Parallel {
    param([string[]]$IpList, [int]$MaxThreads, [ScriptBlock]$Work, [object[]]$WorkArgs)
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $Host)
    $pool.Open()
    $psList = @()
    foreach ($ip in $IpList) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $ps.AddScript($Work) | Out-Null
        foreach ($a in $WorkArgs) { $ps.AddArgument($a) | Out-Null }
        $ps.AddArgument($ip) | Out-Null
        $async = $ps.BeginInvoke()
        $psList += @{ ps = $ps; async = $async }
    }
    $results = @()
    foreach ($item in $psList) {
        try {
            $res = $item.ps.EndInvoke($item.async)
            $results += $res
            $item.ps.Dispose()
        } catch {
            Write-Log ("Runspace error: {0}" -f $_.Exception.Message) "ERROR"
            $Telemetry.errors++
        }
    }
    $pool.Close()
    return $results
}

$WorkScript = {
    param(
        [bool]$EnableMDE_in,
        [bool]$EnableIntune_in,
        [bool]$DryRun_in,
        [string]$GraphToken_in,
        [string]$DefenderToken_in,
        [string]$ip_in
    )

    function Get-JsonSafe { param($uri, $hdr) try { return Invoke-RestMethod -Uri $uri -Headers $hdr -Method Get -TimeoutSec 12 -ErrorAction Stop } catch { return $null } }

    $res = [ordered]@{ ip = $ip_in; ping = $false; rdns = $null; mde = $null; intune = $null; latencyMs = 0; errors = $null }

    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ip_in,1200)
        if ($reply.Status -eq 'Success') { $res.ping = $true; $res.latencyMs = $reply.RoundtripTime }
    } catch { $res.errors = $_.Exception.Message }

    try { $entry = [System.Net.Dns]::GetHostEntry($ip_in); $res.rdns = $entry.HostName.Split('.')[0] } catch {}

    if ($EnableMDE_in -and -not $DryRun_in -and $DefenderToken_in) {
        $hdr = @{ Authorization = "Bearer $DefenderToken_in"; Accept = "application/json" }
        $uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=lastIpAddress eq '$ip_in'"
        $resp = Get-JsonSafe -uri $uri -hdr $hdr
        if ($resp -and $resp.value) { $cnt = $resp.value.Count } else { $cnt = 0 }
        if ($cnt -gt 0) { $res.mde = @{ count = $cnt; first = $resp.value[0] } }
    }

    if ($EnableIntune_in -and -not $DryRun_in -and $GraphToken_in) {
        $hdr = @{ Authorization = "Bearer $GraphToken_in"; Accept = "application/json" }
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=ipAddress eq '$ip_in'"
        $resp = Get-JsonSafe -uri $uri -hdr $hdr
        if ($resp -and $resp.value) { $icnt = $resp.value.Count } else { $icnt = 0 }
        if ($icnt -gt 0) { $res.intune = @{ count = $icnt; first = $resp.value[0] } }
    }

    return $res
}

$AllResults = @()
foreach ($r in $rangeList) {
    Write-Log ("Processando range: {0}" -f $r) "INFO"
    $chunkEnumerator = Get-IPChunksFromRange -RangeString $r -ChunkSize 1000
    foreach ($chunk in $chunkEnumerator) {
        $workArgs = @([bool]$EnableMDE, [bool]$EnableIntune, [bool]$DryRun, $global:Tokens.GraphToken, $global:Tokens.DefenderToken)
        Write-Log ("Enviando chunk com {0} IPs para processamento paralelo" -f $chunk.Count) "DEBUG"
        $resultsChunk = Invoke-Parallel -IpList $chunk -MaxThreads $Threads -Work $WorkScript -WorkArgs $workArgs
        if ($resultsChunk) { $AllResults += $resultsChunk }
        $Telemetry.processed += $chunk.Count
    }
}

$foundMde = ($AllResults | Where-Object { $_.mde -ne $null }).Count
$foundIntune = ($AllResults | Where-Object { $_.intune -ne $null }).Count
$Telemetry.mdeFound = $foundMde; $Telemetry.intuneFound = $foundIntune; $Telemetry.endTime = (Get-Date).ToString('o')

$latArray = $AllResults | Where-Object { $_.latencyMs -and ($_.latencyMs -gt 0) } | Select-Object -ExpandProperty latencyMs
if ($latArray -and $latArray.Count -gt 0) { $Telemetry.avgLatencyMs = [math]::Round(($latArray | Measure-Object -Average).Average,2) } else { $Telemetry.avgLatencyMs = 0 }

Write-Log ("Scan finalizado. MDE matches: {0}; Intune matches: {1}" -f $foundMde, $foundIntune) "INFO"

$ExportList = $Export.Split(',') | ForEach-Object { $_.Trim().ToLower() }
$csvPath = Join-Path $ReportDir "aegisnetops_report_$TimeStamp.csv"
$jsonPath = Join-Path $ReportDir "aegisnetops_report_$TimeStamp.json"
$htmlPath = Join-Path $ReportDir "aegisnetops_report_$TimeStamp.html"

$flat = $AllResults | ForEach-Object {
    [PSCustomObject]@{
        IP = $_.ip
        Ping = $_.ping
        ReverseDNS = $_.rdns
        MDE_Count = if ($_.mde) { $_.mde.count } else { 0 }
        Intune_Count = if ($_.intune) { $_.intune.count } else { 0 }
        LatencyMs = $_.latencyMs
    }
}

if ($ExportList -contains 'csv') { $flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8; Write-Log ("CSV salvo: {0}" -f $csvPath) "INFO" }
if ($ExportList -contains 'json') { $AllResults | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8; Write-Log ("JSON salvo: {0}" -f $jsonPath) "INFO" }
if ($ExportList -contains 'html') {
    $html = $flat | ConvertTo-Html -Property IP,Ping,ReverseDNS,MDE_Count,Intune_Count,LatencyMs -Title "AEGIS-NET OPS Report $TimeStamp" -PreContent "<h1>AEGIS-NET OPS Report</h1><p>Generated: $TimeStamp</p>"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log ("HTML salvo: {0}" -f $htmlPath) "INFO"
}

$TelemetryPath = Join-Path $ReportDir "telemetry_$TimeStamp.json"
$Telemetry | ConvertTo-Json -Depth 5 | Out-File -FilePath $TelemetryPath -Encoding UTF8
Write-Log ("Telemetry salvo: {0}" -f $TelemetryPath) "INFO"

# Send telemetry to SIEM (safe: do not use $using)
if ($SiemEndpoint) {
    try {
        $payload = @{ telemetry = $Telemetry; summary = @{ total = $AllResults.Count; mde = $Telemetry.mdeFound; intune = $Telemetry.intuneFound } } | ConvertTo-Json -Depth 6
        Invoke-WithRetry -Script { Invoke-RestMethod -Method Post -Uri $SiemEndpoint -Body $payload -ContentType "application/json" -TimeoutSec 10 } -MaxAttempts 3
        Write-Log ("Telemetry enviada ao SIEM: {0}" -f $SiemEndpoint) "INFO"
    } catch {
        Write-Log ("Falha enviar telemetry ao SIEM: {0}" -f $_.Exception.Message) "WARN"
    }
}

# Remediation (unchanged behavior)
if ($EnableRemediate) {
    if (-not $ConfirmRemediate) { Write-Log "EnableRemediate ativo mas ConfirmRemediate ausente -> abortando remediação." "ERROR"; throw "Remediação requer confirmação (--ConfirmRemediate)." }
    if ($DryRun) { Write-Log "DryRun ativo; remediação não será executada." "WARN" }
    else {
        Write-Log "Iniciando remediação interativa (simulada)" "WARN"
        $candidates = $AllResults | Where-Object { ($_.mde -ne $null -and $_.mde.count -gt 0) -or ($_.intune -ne $null -and $_.intune.count -gt 0) }
        foreach ($c in $candidates) {
            $mdeCount = if ($c.mde) { $c.mde.count } else { 0 }
            $intuneCount = if ($c.intune) { $c.intune.count } else { 0 }
            Write-Host ("Candidate: {0} - MDE: {1} Intune: {2}" -f $c.ip, $mdeCount, $intuneCount)
            $action = Read-Host "Type 'isolate' to isolate via MDE, 'lock' to remoteLock via Intune, 'skip' to skip"
            if ($action -eq 'isolate' -and $EnableMDE) { Write-Log ("ISOLATE requested for {0} - simulated" -f $c.ip) "INFO" }
            elseif ($action -eq 'lock' -and $EnableIntune) { Write-Log ("REMOTELOCK requested for {0} - simulated" -f $c.ip) "INFO" }
            else { Write-Log ("Operador pulou remediação para {0}" -f $c.ip) "INFO" }
        }
    }
}

Write-Log "Execução concluída" "INFO"
Write-Host ("Execução completa. Relatórios em: {0}`nLogs em: {1}" -f $ReportDir, $LogDir) -ForegroundColor Green
# END
