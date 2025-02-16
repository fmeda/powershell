# Nome do script: Hardening-Windows10.ps1
# Autor: [Seu Nome]
# Descrição: Script para implementar hardening de segurança no Windows 10 com boas práticas.

# Função para exibir mensagens com formatação padrão
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$timestamp] - $message"
}

Write-Log "Iniciando o processo de hardening do Windows 10..."

# 1. Configuração de Senhas Fortes
Write-Log "Configurando políticas de senhas fortes..."
secpol.msc

# 2. Controle de Acesso e Privilégios
Write-Log "Desabilitando a conta 'Administrador' embutida..."
Disable-LocalUser -Name "Administrator" -Confirm:$false

Write-Log "Criando uma conta de usuário padrão..."
$Password = ConvertTo-SecureString "SenhaForte123!" -AsPlainText -Force
New-LocalUser -Name "UsuarioPadrao" -Password $Password -FullName "Usuario Padrão" -Description "Conta de usuário padrão"
Add-LocalGroupMember -Group "Users" -Member "UsuarioPadrao"

# 3. Desabilitar Serviços Desnecessários
Write-Log "Desabilitando serviços desnecessários..."
$servicesToDisable = @("Telnet", "FTP")
foreach ($service in $servicesToDisable) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
        Write-Log "Serviço $service desabilitado."
    }
}

# 4. Desabilitar Portas de Rede Não Utilizadas
Write-Log "Fechando portas de rede não necessárias..."
$portsToBlock = @(
    @{Name="Telnet"; Port=23},
    @{Name="FTP"; Port=21}
)
foreach ($port in $portsToBlock) {
    New-NetFirewallRule -DisplayName "Block $($port.Name)" -Direction Inbound -Protocol TCP -LocalPort $port.Port -Action Block
    Write-Log "Porta TCP $($port.Port) bloqueada para $($port.Name)."
}

# 5. Atualizações Automáticas
Write-Log "Configurando Windows Update para atualizações automáticas..."
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# 6. Ativar Windows Defender
Write-Log "Habilitando o Windows Defender Antivirus..."
Set-MpPreference -DisableRealtimeMonitoring $false

# 7. Auditoria e Logs
Write-Log "Ativando a auditoria de segurança..."
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable

# 8. Criptografia com BitLocker
Write-Log "Habilitando o BitLocker para criptografar discos..."
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256

# 9. Desabilitar SMBv1
Write-Log "Desabilitando SMBv1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 10. Habilitar Secure Boot
Write-Log "Verificando e habilitando Secure Boot na BIOS/UEFI... (necessário intervenção manual na BIOS)"
Write-Host "Por favor, habilite o Secure Boot manualmente na BIOS/UEFI."

# 11. Configurar DEP e ASLR
Write-Log "Habilitando DEP e ASLR..."
bcdedit /set {current} nx AlwaysOn
bcdedit /set {current} aslr 1

# 12. Desabilitar RDP
Write-Log "Desabilitando Remote Desktop Protocol (RDP)..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

# 13. Desabilitar AutoPlay
Write-Log "Desabilitando AutoPlay..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# 14. Habilitar BitLocker
Write-Log "Habilitando BitLocker novamente para garantir criptografia do disco C:..."
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256

# 15. Assinaturas Digitais nos Arquivos
Write-Log "Configurando assinatura digital de arquivos críticos..."
$signToolPath = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\SDK\NuGetPackages\Microsoft.SignTool\7.0.0\tools\signtool.exe"
$certPath = "C:\Certificados\certificado.pfx"
$certPassword = ConvertTo-SecureString -String "senha_do_certificado" -AsPlainText -Force

$filesToSign = @(
    "C:\Windows\System32\calc.exe",
    "C:\Windows\System32\notepad.exe"
)

foreach ($file in $filesToSign) {
    if (Test-Path $file) {
        & "$signToolPath" sign /f $certPath /p $certPassword $file
        Write-Log "Arquivo assinado digitalmente: $file"
    }
}

# 25. Criptografia de Arquivos e Chaves do Sistema (EFS)
Write-Log "Habilitando criptografia EFS para arquivos e chaves do sistema..."
$folderPath = "C:\Caminho\Para\Pasta\Criptografada"  # Altere o caminho conforme necessário
$fs = Get-Item -LiteralPath $folderPath
$fs.Attributes = 'Encrypted'

Write-Log "Criptografia EFS aplicada na pasta: $folderPath"

# 26. Verificar Assinaturas Digitais em Arquivos Críticos
Write-Log "Verificando assinaturas digitais nos arquivos críticos..."
foreach ($file in $filesToSign) {
    if (Test-Path $file) {
        $signature = Get-AuthenticodeSignature -FilePath $file
        if ($signature.Status -eq 'Valid') {
            Write-Log "Assinatura válida para o arquivo: $file"
        } else {
            Write-Log "Assinatura inválida ou ausente no arquivo: $file"
        }
    }
}

Write-Log "Processo de hardening do Windows 10 concluído com sucesso!"
