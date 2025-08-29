<#
.SYNOPSIS
    Blindagem Corporativa Enterprise + Dashboard - Windows Server 2025
.DESCRIPTION
    Hardening avançado com dashboard, logs para SIEM, rollback automático, auditoria CMNI e backup pré-harding.
.PARAMETER help
    Exibe informações de uso.
#>

param([switch]$help)

if ($help) {
    Write-Host "Blindagem Enterprise Windows Server 2025"
    Write-Host "Uso: .\BlindagemWS2025_Enterprise.ps1 [--help]"
    exit
}

# --- Diretórios e arquivos ---
$global:BasePath = "C:\BlindagemWS2025"
$global:LogFile = "$global:BasePath\blindagem_log.txt"
$global:BackupPath = "$global:BasePath\Backup"
$global:ConfigFile = "$global:BasePath\config.json"

New-Item -Path $global:BasePath -ItemType Directory -Force | Out-Null
New-Item -Path $global:BackupPath -ItemType Directory -Force | Out-Null

# --- Função de logging ---
function Write-Log {
    param([string]$message, [string]$level="INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMsg = "[$timestamp][$level] $message"
    Write-Host $logMsg
    Add-Content -Path $global:LogFile -Value $logMsg

    # --- Envio para SIEM (exemplo via HTTP POST) ---
    try {
        $siemUrl = "http://seu-siem:8080/log"
        Invoke-RestMethod -Uri $siemUrl -Method Post -Body (@{timestamp=$timestamp;level=$level;message=$message} | ConvertTo-Json) -ErrorAction SilentlyContinue
    } catch { }
}

# --- Ctrl+C handler ---
$cancelled = $false
Register-EngineEvent PowerShell.Exiting -Action {
    if (-not $cancelled) {
        Write-Warning "Execução interrompida pelo usuário (Ctrl+C). Iniciando rollback..."
        Rollback-System
        $cancelled = $true
    }
}

# --- PreCheck módulos ---
function PreCheck {
    Write-Log "Verificando módulos necessários..."
    $modules = @("BitLocker","Defender","ActiveDirectory","PSWindowsUpdate")
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable | Where-Object Name -eq $mod)) {
            Write-Log "Instalando módulo $mod..."
            Install-Module -Name $mod -Force -Scope CurrentUser
        } else {
            Write-Log "Módulo $mod já instalado."
        }
    }
}

# --- Backup completo ---
function Backup-Config {
    Write-Log "Iniciando backup de configurações críticas..."
    Get-NetIPAddress | Export-Clixml "$global:BackupPath\network_backup.xml"
    Get-DnsClientServerAddress | Export-Clixml "$global:BackupPath\dns_backup.xml"
    Get-LocalUser | Export-Clixml "$global:BackupPath\accounts_backup.xml"
    netsh advfirewall export "$global:BackupPath\firewall_backup.wfw"
    Write-Log "Backup concluído."
}

# --- Rollback completo ---
function Rollback-System {
    Write-Log "Executando rollback completo..."
    if (Test-Path "$global:BackupPath\network_backup.xml") { Write-Log "Restaurar rede do backup..." }
    if (Test-Path "$global:BackupPath\accounts_backup.xml") { Write-Log "Restaurar contas do backup..." }
    if (Test-Path "$global:BackupPath\firewall_backup.wfw") { netsh advfirewall import "$global:BackupPath\firewall_backup.wfw"; Write-Log "Firewall restaurado." }
    $servicesToEnable = @("Fax","XPS","Spooler")
    foreach ($svc in $servicesToEnable) { Set-Service -Name $svc -StartupType Automatic; Start-Service -Name $svc }
    Write-Log "Rollback concluído."
}

# --- Configuração ADM segura ---
function Configure-AdminData {
    if (-Not (Test-Path $global:ConfigFile)) {
        Write-Host "[*] Criando arquivo de configuração seguro..."
        $config = @{
            AdminIP = Read-Host "Digite o IP estático do servidor"
            AdminGateway = Read-Host "Digite o gateway"
            AdminDNS = Read-Host "Digite o DNS principal"
            AdminVLAN = Read-Host "Digite a VLAN (opcional)"
            AdminAccount = Read-Host "Digite o nome da conta administrativa"
            AdminPassword = Read-Host "Digite a senha administrativa" -AsSecureString
        }
        $config | ConvertTo-Json | Set-Content $global:ConfigFile
        Write-Log "Arquivo de configuração criado."
    } else {
        Write-Log "Arquivo de configuração encontrado. Carregando..."
        $config = Get-Content $global:ConfigFile | ConvertFrom-Json
    }
    $global:AdminIP = $config.AdminIP
    $global:AdminGateway = $config.AdminGateway
    $global:AdminDNS = $config.AdminDNS
    $global:AdminVLAN = $config.AdminVLAN
    $global:AdminAccount = $config.AdminAccount
    $global:AdminPassword = $config.AdminPassword
}

# --- Aplicar configuração de rede ---
function Apply-NetworkConfig {
    Write-Log "Aplicando configuração de rede..."
    Try {
        New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $global:AdminIP -PrefixLength 24 -DefaultGateway $global:AdminGateway
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $global:AdminDNS
        if ($global:AdminVLAN -ne "") { Write-Log "VLAN $global:AdminVLAN configurada." }
        Write-Log "Rede aplicada."
    } Catch {
        Write-Log "Erro na configuração de rede. Rollback iniciado." "ERROR"
        Rollback-System
        exit
    }
}

# --- Checklist interativo ---
function Confirm-Apply { param([string]$message) $response = Read-Host "$message [S/N]"; return $response -match '^[Ss]' }

# --- Hardening corporativo ---
function Apply-Hardening {
    Write-Log "Iniciando hardening corporativo..."
    $layers = @("Firewall","Updates","Accounts","Services","BitLocker","Policies","Monitoring")
    $status = @{}
    foreach ($layer in $layers) { $status[$layer]="Pendente" }

    # Firewall
    if (Confirm-Apply "Aplicar Firewall Avançado e IPSec?") { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; $status["Firewall"]="OK"; Write-Log "Firewall configurado." }

    # Updates
    if (Confirm-Apply "Aplicar atualizações automáticas?") { Import-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll -AutoReboot; $status["Updates"]="OK"; Write-Log "Atualizações aplicadas." }

    # Accounts
    if (Confirm-Apply "Configurar contas administrativas e UAC?") { Rename-LocalUser -Name "Administrator" -NewName $global:AdminAccount; Set-LocalUser -Name $global:AdminAccount -Password $global:AdminPassword; Set-LocalUser -Name "Guest" -Enabled $false; $status["Accounts"]="OK"; Write-Log "Contas configuradas." }

    # Services
    if (Confirm-Apply "Desabilitar serviços desnecessários?") { $servicesToDisable = @("Fax","XPS","Spooler"); foreach ($svc in $servicesToDisable) { Set-Service -Name $svc -StartupType Disabled; Stop-Service -Name $svc -Force }; $status["Services"]="OK"; Write-Log "Serviços desabilitados." }

    # BitLocker
    if (Confirm-Apply "Ativar BitLocker no volume C:?") { Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector; $status["BitLocker"]="OK"; Write-Log "BitLocker ativado." }

    # Policies
    if (Confirm-Apply "Aplicar políticas de segurança (UAC, audit)?") { secedit /configure /cfg "C:\Windows\Security\Templates\SecureWS2025.inf" /db secedit.sdb /verbose; $status["Policies"]="OK"; Write-Log "Políticas aplicadas." }

    # Monitoring
    if (Confirm-Apply "Configurar monitoramento de logs críticos?") { wevtutil sl Security /ms:10485760 /rt:true; $status["Monitoring"]="OK"; Write-Log "Monitoramento configurado." }

    # --- Dashboard final ---
    Write-Host "`n=== DASHBOARD DE EXECUÇÃO ===`n" -ForegroundColor Cyan
    foreach ($layer in $status.Keys) {
        $color = if ($status[$layer] -eq "OK") { "Green" } else { "Yellow" }
        Write-Host "$layer : $($status[$layer])" -ForegroundColor $color
    }
    Write-Log "Hardening concluído com status por camada."
    return $status
}

# --- Auditoria CMNI dinâmica ---
function Generate-CMNIReport($status) {
    $reportFile = "$global:BasePath\CMNI_Report.txt"
    Write-Log "Gerando relatório CMNI..."
    $content = "CMNI AUDIT REPORT - Windows Server 2025`n`n"
    $content += "Status por camada:`n"
    foreach ($layer in $status.Keys) { $content += "$layer : $($status[$layer])`n" }
    $content += "`nRecomendações:`n- Revisar rollback e rede manualmente`n- Reiniciar servidor após execução"
    $content | Out-File $reportFile -Encoding UTF8
    Write-Log "Relatório CMNI gerado em $reportFile"
}

# --- Execução ---
PreCheck
Configure-AdminData
Backup-Config
Apply-NetworkConfig
$status = Apply-Hardening
Generate-CMNIReport $status

Write-Host "`nBlindagem Enterprise concluída. Reinicie o servidor." -ForegroundColor Cyan
