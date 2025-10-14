# ==============================
# 🔒 VALIDAÇÃO DE AMBIENTE (CMMI SAFE INIT)
# ==============================
Write-Host "=== Active Directory Cleanup Helper v3.1 (CMMI-5) ===" -ForegroundColor Cyan
Write-Host "Data: $(Get-Date)" -ForegroundColor Gray

# Verifica se o módulo ActiveDirectory está instalado e disponível
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host ""
    Write-Host "❌ ERRO: O módulo ActiveDirectory não foi encontrado no sistema." -ForegroundColor Red
    Write-Host "🔧 Para instalar, execute o comando apropriado conforme sua versão do Windows:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ▪️ Windows Server:" -ForegroundColor White
    Write-Host "     Add-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ▪️ Windows 10 / 11 (cliente):" -ForegroundColor White
    Write-Host "     Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Green
    Write-Host ""
    Write-Host "Após a instalação, abra novamente o PowerShell como Administrador e execute o script novamente." -ForegroundColor Gray
    exit 1
}

# Importa o módulo AD com tratamento de exceção robusto
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "❌ Falha ao importar o módulo ActiveDirectory. Verifique as permissões e tente novamente." -ForegroundColor Red
    Write-Host "Detalhes do erro: $($_.Exception.Message)" -ForegroundColor DarkGray
    exit 1
}

# Exibe informações do ambiente
$User   = [Environment]::UserName
$Domain = try { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name } catch { "Domínio não detectado" }
Write-Host "Usuário atual: $User | Domínio: $Domain" -ForegroundColor Gray
Write-Host ""
