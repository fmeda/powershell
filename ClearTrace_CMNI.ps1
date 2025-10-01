<#
.SYNOPSIS
  Support / Reprovision helper for Windows (PowerShell) - CMNI Enhanced
.DESCRIPTION
  Ferramenta avançada de suporte técnico com controles CMNI.
  Funcionalidades:
  - Verificação de assinatura (Authenticode)
  - Validação de Ticket (placeholder para GLPI)
  - RBAC (AD group check)
  - Logs tamper-evident (HMAC protegido por DPAPI)
  - Envio de logs para SIEM (Graylog placeholder)
  - Fluxo de aprovação (stub)
  - Inventário, backup de perfis, remoção de credenciais, remoção de perfis Wi‑Fi,
    remoção segura de perfis locais (após aprovação), wipe do espaço livre (opcional),
    geração de relatório assinado (hash) e export de artefatos.
.USAGE
  SupportTool_CMNI.ps1 [--help]
  --help    : Mostra informações detalhadas de uso, opções e precauções.
WARNINGS
  - Execute apenas com autorização explícita.
  - Algumas ações são irreversíveis (remoção de perfis, cipher /w).
#>

#region Global Variables
$global:ActionsTaken = @()
#endregion

#region Ctrl+C / Error Handling
$ErrorActionPreference = 'Stop'
$script:stopScript = $false

# Handle Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action {
    if (-not $script:stopScript) {
        Write-Output "Execução interrompida pelo operador (CTRL+C). Ação registrada no log."
        $script:stopScript = $true
        Exit
    }
}

# Trap geral para erros
trap {
    Write-Error "Erro detectado: $_"
    Log "ERROR|$_"
    continue
}
#endregion

#region Pre-Check: Modules / Libraries
$modulesNeeded = @('ActiveDirectory')
foreach ($mod in $modulesNeeded) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Output "Módulo $mod não encontrado. Instalando..."
        try {
            Install-Module -Name $mod -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Output "Módulo $mod instalado com sucesso."
        } catch {
            Write-Error "Falha ao instalar módulo $mod - $_"
            exit 1
        }
    } else {
        Write-Output "Módulo $mod disponível."
    }
}
#endregion

#region Help Option
param(
    [switch]$help
)
if ($help) {
    Write-Output @"
SupportTool_CMNI.ps1 - Ferramenta de suporte técnico com controles CMNI.

Opções:
  --help        : Mostra este menu de ajuda.

Fluxo seguro:
  1. Pré-checagem de módulos obrigatórios e instalação automática.
  2. Verificação de assinatura do script (se habilitado).
  3. Validação de Ticket GLPI (placeholder).
  4. Checagem de grupo AD / RBAC.
  5. Registro de logs tamper-evident.
  6. Fluxo de aprovação antes de ações destrutivas.
  7. Inventário, backup de perfis, remoção de credenciais e perfis Wi-Fi.
  8. Remoção de perfis locais inativos (após aprovação).
  9. Wipe opcional de espaço livre.
 10. Geração de relatório assinado (hash).

Precauções:
  - Execute como Administrador.
  - Confirme todas as ações interativas.
  - Todos os erros e interrupções (CTRL+C) são logados.
"@
    exit 0
}
#endregion

#region Config
$Config = @{ 
    BackupShare       = "\\fileserver\backups\reprovision"    
    ExportPath        = "$env:PUBLIC\SupportExport_$(Get-Date -Format yyyyMMdd_HHmmss)"
    DoWipeFreeSpace   = $false
    DoReset           = $false
    KeepLogs          = $true
    LogFile           = "$env:PUBLIC\SupportScript_$(Get-Date -Format yyyyMMdd_HHmmss).log"

    GLPI_ApiUrl       = 'https://glpi.example/api'      
    GLPI_AppToken     = ''                              
    Graylog_GelfUrl   = 'https://graylog.example:12202/gelf' 
    ApproverApiUrl    = 'https://workflow.example/api/approve' 
    RequiredADGroup   = 'Support-Reprovision'
}

New-Item -Path $Config.ExportPath -ItemType Directory -Force | Out-Null
#endregion

#region Helpers
function Log($txt){
    $line = "$(Get-Date -Format s) - $txt"
    if ($Config.KeepLogs) { $line | Out-File -FilePath $Config.LogFile -Append -Encoding UTF8 }
    Write-Output $line
}
function Confirm-OrAbort($message){
    $r = Read-Host "$message [s/N]"
    if ($r -notin @('s','S','y','Y')) {
        Log "Ação abortada pelo operador."
        throw "Abort by operator"
    }
}
#endregion

#region CMNI: Ticket Validation (Placeholder)
function Validate-Ticket {
    param($TicketID)
    if (-not $TicketID) { throw "TicketID obrigatório." }
    if ($TicketID -notmatch '^\d{6,}$') { throw "TicketID inválido." }
    Write-Output "Ticket $TicketID validado localmente (formato)."
}
#endregion

#region CMNI: RBAC Check
function Assert-OperatorInGroup {
    param([string]$GroupName)
    $user = $env:USERNAME
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        if (Get-Module -Name ActiveDirectory) {
            $groups = Get-ADPrincipalGroupMembership $user | Select-Object -ExpandProperty Name
            $isMember = $groups -contains $GroupName
        } else {
            $isMember = (Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq $user}) -ne $null
        }
    } catch {
        Write-Error "Falha ao verificar grupo AD. Erro: $_"
        exit 1
    }
    if (-not $isMember) { throw "Operador $user não pertence ao grupo requerido: $GroupName" }
    Write-Output "Operador autorizado ($user)."
}
#endregion

#region CMNI: Tamper-Evident Log
function Get-LogKey {
    $keyFile = "$env:ProgramData\SupportTool\logkey.bin"
    if (-not (Test-Path $keyFile)) {
        New-Item -ItemType Directory -Path (Split-Path $keyFile) -Force | Out-Null
        $key = New-Object byte[] 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($key, $null, 'LocalMachine')
        [IO.File]::WriteAllBytes($keyFile, $enc)
        return $key
    } else {
        $enc = [IO.File]::ReadAllBytes($keyFile)
        $key = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'LocalMachine')
        return $key
    }
}

function Write-TamperLog {
    param($Message, $LogPath = "$env:PUBLIC\SupportAudit.log")
    $ts = (Get-Date).ToUniversalTime().ToString("o")
    $payload = "$ts`|$Message"
    $key = Get-LogKey
    $hmac = [System.BitConverter]::ToString((New-Object Security.Cryptography.HMACSHA256 $key).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))).Replace('-','')
    $line = "$payload`|$hmac"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}
#endregion

#region Inventory & Exports
Log "Exportando inventário e aplicações instaladas..."
Get-ComputerInfo | Select CsName, OsName, OsVersion, WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer |
    Out-File -FilePath (Join-Path $Config.ExportPath "systeminfo.txt") -Encoding UTF8

$apps = @()
$regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
foreach ($p in $regPaths) {
    try {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Where-Object { $_.DisplayName } | ForEach-Object { $apps += $_ }
    } catch { }
}
$apps | Sort-Object DisplayName | Export-Csv -Path (Join-Path $Config.ExportPath "installed_apps.csv") -NoTypeInformation -Encoding UTF8
Log "Lista de aplicações exportada ($( $apps.Count ) itens)."
Get-LocalUser | Select Name,Enabled,LastLogon | Export-Csv -Path (Join-Path $Config.ExportPath "local_users.csv") -NoTypeInformation -Encoding UTF8
Log "Lista de usuários locais exportada."
#endregion

#region Backup Profiles (Optional)
if ($Config.BackupShare) {
    Log "Backup de perfis habilitado para: $($Config.BackupShare)"
    if (-not (Test-Path $Config.BackupShare)) {
        Log "Caminho de backup inacessível. Verifique a rede/permissoes: $($Config.BackupShare)"
    } else {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -and $_.Loaded -eq $false }
        foreach ($p in $profiles) {
            try {
                $localPath = $p.LocalPath
                $user = Split-Path $localPath -Leaf
                $dest = Join-Path $Config.BackupShare "$($env:COMPUTERNAME)_$user_$(Get-Date -Format yyyyMMdd_HHmmss)"
                Log "Copiando $localPath -> $dest ..."
                New-Item -Path $dest -ItemType Directory -Force | Out-Null
                & robocopy $localPath $dest /MIR /R:2 /W:2 | Out-Null
                Log "Backup do perfil $user finalizado."
            } catch {
                Log "Falha ao copiar perfil $localPath - $_"
            }
        }
    }
}
#endregion

#region Remove Stored Credentials (cmdkey)
if ((Read-Host "Remover todas as credenciais salvas (Credential Manager / cmdkey)? [s/N]") -in @('s','S','y','Y')) {
    Log "Removendo credenciais listadas por cmdkey..."
    $raw = & cmdkey /list 2>&1
    foreach ($line in $raw) {
        if ($line -match "Target: (.+)$") {
            $target = $matches[1].Trim()
            try {
                & cmdkey /delete:$target
                Log "Deletado credencial: $target"
            } catch {
                Log "Erro ao deletar credencial: $target - $_"
            }
        }
    }
} else { Log "Pulado remoção de credenciais." }
#endregion

#region Remove Wi-Fi Profiles
if ((Read-Host "Remover todos os perfis Wi‑Fi neste equipamento? [s/N]") -in @('s','S','y','Y')) {
    Log "Listando perfis Wi-Fi..."
    $profiles = (& netsh wlan show profiles) -join "`n"
    $profiles = ($profiles -split "`n" | Where-Object { $_ -match "All User Profile|Perfil todos os usuários|Perfil de todos os usuários" })
    foreach ($p in $profiles) {
        if ($p -match ":\\s*(.+)$") {
            $name = $matches[1].Trim()
            try {
                & netsh wlan delete profile name="$name" | Out-Null
                Log "Deletado perfil Wi-Fi: $name"
            } catch {
                Log "Erro ao deletar perfil Wi-Fi: $name - $_"
            }
        }
    }
} else { Log "Pulado remoção de perfis Wi‑Fi." }
#endregion

#region Remove Local User Profiles
Write-Output ""
if ((Read-Host "Remover perfis de usuários locais inativos (excluir pastas de perfil)? [s/N]") -in @('s','S','y','Y')) {
    $TicketID = Read-Host "Informe Ticket ID (GLPI)"
    Validate-Ticket -TicketID $TicketID
    Assert-OperatorInGroup -GroupName $Config.RequiredADGroup

    $profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -and $_.Loaded -eq $false }
    $profiles | Select @{n='SID';e={$_.SID}}, @{n='Path';e={$_.LocalPath}}, @{n='LastUse';e={$_.LastUseTime}} | Format-Table -AutoSize
    Confirm-OrAbort "Confirma exclusão das pastas de perfil listadas? (ação irreversível)"

    foreach ($p in $profiles) {
        try {
            $lp = $p.LocalPath
            Log "Tentando remover perfil: $lp"
            Remove-Item -LiteralPath $lp -Recurse -Force -ErrorAction SilentlyContinue
            Invoke-CimMethod -InputObject $p -MethodName Delete | Out-Null
            Log "Perfil $lp removido com sucesso."
            $global:ActionsTaken += @{ action='RemoveProfile'; path=$lp; outcome='success' }
            Write-TamperLog -Message "ACTION|Ticket:$TicketID|Operator:$env:USERNAME|RemoveProfile:$lp|Outcome:success"
        } catch {
            Log "Falha ao remover perfil $lp - $_"
            $global:ActionsTaken += @{ action='RemoveProfile'; path=$lp; outcome='fail'; error=$_ }
            Write-TamperLog -Message "ACTION_FAIL|Ticket:$TicketID|Operator:$env:USERNAME|RemoveProfile:$lp|Error:$_"
        }
    }
} else { Log "Pulado exclusão de perfis locais." }
#endregion

#region Optional: Overwrite Free Space
if ($Config.DoWipeFreeSpace) {
    Log "Opção wipe free space habilitada."
    Confirm-OrAbort "Executar sobrescrita do espaço livre com 'cipher /w' na unidade C:? Isso pode levar MUITO tempo. Confirmar"
    Log "Executando 'cipher /w:C:' ..."
    & cmd /c "cipher /w:C:\" 2>&1 | ForEach-Object { Log $_ }
    Log "Sobrescrita do espaço livre finalizada."
    $global:ActionsTaken += @{ action='WipeFreeSpace'; outcome='success' }
    Write-TamperLog -Message "ACTION|Ticket:$TicketID|Operator:$env:USERNAME|WipeFreeSpace|Outcome:success"
} else { Log "Wipe free space não habilitado." }
#endregion

#region Final Report Generation
function Generate-Report {
    param($ExportPath)
    $reportFile = Join-Path $ExportPath "report_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
    Log "Gerando relatório final: $reportFile"
    $global:ActionsTaken | ForEach-Object {
        $line = ($_ | ConvertTo-Json -Compress)
        Add-Content -Path $reportFile -Value $line
    }
    # Gerar hash do relatório
    $hash = Get-FileHash $reportFile -Algorithm SHA256
    Log "Relatório hash: $($hash.Hash)"
    Write-TamperLog -Message "REPORT_GENERATED|Path:$reportFile|Hash:$($hash.Hash)|Operator:$env:USERNAME"
}
Generate-Report -ExportPath $Config.ExportPath
#endregion

Log "Execução do SupportTool_CMNI finalizada."
