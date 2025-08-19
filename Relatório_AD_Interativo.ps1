<#
.SYNOPSIS
    Gera um relatório interativo de usuários e seus grupos no Active Directory.

.DESCRIPTION
    Este script guia o usuário passo a passo para gerar um relatório de 
    membros de grupos no Active Directory. Ele verifica a presença do módulo 
    necessário e pode instalá-lo automaticamente, se necessário.

.EXAMPLE
    .\RelatorioAD_Interativo.ps1
    // Inicia o modo interativo para coletar as opções do usuário.
#>

[CmdletBinding()]
param (
    [string]$CsvPath,
    [string]$FilterGroup
)

# -------------------- Parte 1: Verificação e Instalação de Módulos --------------------

Write-Host "Iniciando o script interativo de relatórios do Active Directory..." -ForegroundColor Green
Write-Host "Verificando se o módulo 'ActiveDirectory' está instalado. Isso é fundamental para a operação." -ForegroundColor Cyan

# Verifica se o módulo ActiveDirectory está disponível.
if (-not (Get-Module -ListAvailable -Name "ActiveDirectory")) {
    Write-Host "O módulo Active Directory não foi encontrado." -ForegroundColor Yellow
    $confirmacao = Read-Host "Deseja que eu instale a funcionalidade RSAT-AD-PowerShell agora? (Pode requerer reinicialização) [S/N]"
    if ($confirmacao -eq 'S' -or $confirmacao -eq 's') {
        try {
            Write-Host "Iniciando a instalação do módulo... Por favor, aguarde." -ForegroundColor Yellow
            Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
            Write-Host "Instalação concluída com sucesso! Para evitar problemas, é recomendável reiniciar o servidor." -ForegroundColor Green
            Write-Host "Por favor, reinicie e execute o script novamente para continuar." -ForegroundColor Green
        } catch {
            Write-Host "Ocorreu um erro durante a instalação. Certifique-se de que está executando o PowerShell como Administrador e que tem acesso à internet." -ForegroundColor Red
            Write-Host "Detalhes do erro: $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    } else {
        Write-Host "Instalação cancelada. O script não pode continuar sem o módulo." -ForegroundColor Red
        return
    }
}

Import-Module ActiveDirectory

# -------------------- Parte 2: Coleta de Opções do Usuário --------------------

Write-Host "`nO módulo está pronto! Vamos começar a gerar o seu relatório." -ForegroundColor Green
Write-Host "Você pode gerar um relatório completo ou focado em um grupo específico."

# Se o parâmetro CsvPath não foi fornecido, pergunta ao usuário.
if ([string]::IsNullOrEmpty($CsvPath)) {
    $salvarCSV = Read-Host "Deseja salvar o relatório em um arquivo CSV? [S/N]"
    if ($salvarCSV -eq 'S' -or $salvarCSV -eq 's') {
        $CsvPath = Read-Host "Por favor, digite o caminho completo do arquivo para salvar (ex: C:\Relatorios\meu_relatorio.csv)"
    }
}

# Se o parâmetro FilterGroup não foi fornecido, pergunta ao usuário.
if ([string]::IsNullOrEmpty($FilterGroup)) {
    $filtrarGrupo = Read-Host "Deseja filtrar o relatório por um grupo específico? [S/N]"
    if ($filtrarGrupo -eq 'S' -or $filtrarGrupo -eq 's') {
        $FilterGroup = Read-Host "Por favor, digite o nome exato do grupo que você deseja filtrar (ex: 'Domain Admins')"
    }
}

# -------------------- Parte 3: Execução da Lógica de Relatório --------------------

try {
    Write-Host "Obtendo a lista de usuários e grupos do Active Directory. Isso pode levar alguns instantes..." -ForegroundColor Green
    
    $gruposHashTable = @{}
    Get-ADGroup -Filter * | ForEach-Object { $gruposHashTable[$_.DistinguishedName] = $_.Name }
    
    if (-not [string]::IsNullOrEmpty($FilterGroup)) {
        $usuarios = Get-ADGroupMember -Identity $FilterGroup -Recursive | Get-ADUser -Properties Name, SamAccountName, MemberOf -ErrorAction Stop
        if ($null -eq $usuarios) {
            Write-Host "Nenhum usuário encontrado no grupo '$FilterGroup'. Verifique o nome do grupo e tente novamente." -ForegroundColor Yellow
            return
        }
    } else {
        $usuarios = Get-ADUser -Filter * -Properties Name, SamAccountName, MemberOf -ErrorAction Stop
    }

} catch {
    Write-Host "Ocorreu um erro ao buscar os dados do Active Directory. Por favor, verifique suas permissões." -ForegroundColor Red
    Write-Host "Detalhes do erro: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$relatorio = @()
Write-Host "Processando a associação de grupos de cada usuário..."

$gruposPrioridade = "Domain Admins", "Enterprise Admins", "Schema Admins"

foreach ($usuario in $usuarios) {
    $gruposDoUsuarioDN = $usuario.MemberOf
    $gruposDoUsuario = $gruposDoUsuarioDN | ForEach-Object {
        $nomeDoGrupo = $gruposHashTable[$_]
        if ($null -ne $nomeDoGrupo) { $nomeDoGrupo } else { "Grupo Removido" }
    }
    
    $highPriorityGroups = ($gruposDoUsuario | Where-Object { $_ -in $gruposPrioridade }) -join ", "
    
    $objetoUsuario = [PSCustomObject]@{
        Usuario = $usuario.Name
        SamAccountName = $usuario.SamAccountName
        Grupos = ($gruposDoUsuario -join ", ")
        PrivilegiosDeAltoNivel = if (-not [string]::IsNullOrEmpty($highPriorityGroups)) { $highPriorityGroups } else { "Nenhum" }
    }
    
    $relatorio += $objetoUsuario
}

# -------------------- Parte 4: Exibição ou Salvamento do Relatório --------------------

if (-not [string]::IsNullOrEmpty($CsvPath)) {
    try {
        Write-Host "Salvando o relatório em '$CsvPath'..." -ForegroundColor Green
        $relatorio | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Relatório salvo com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Ocorreu um erro ao salvar o arquivo. Verifique se o caminho e o nome do arquivo estão corretos." -ForegroundColor Red
        Write-Host "Detalhes do erro: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "`n--- Mapeamento de Usuários e Grupos Concluído ---" -ForegroundColor Green
    $relatorio | Format-Table -AutoSize
}

Write-Host "`nOperação finalizada. Obrigada por usar o script!" -ForegroundColor Green