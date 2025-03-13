# Função para verificar se o script está sendo executado com privilégios elevados
function Verificar-PrivilégiosElevados {
    if (-not [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -match "S-1-5-32-544") {
        Write-Host "Este script precisa ser executado como Administrador!" -ForegroundColor Red
        exit
    }
}

# Função para criar um novo usuário
function Criar-Usuario {
    param(
        [string]$usuario,
        [string]$senha
    )
    Write-Host "Criando o usuário $usuario..." -ForegroundColor Yellow
    net user $usuario $senha /add
    if ($?) {
        Write-Host "Usuário $usuario criado com sucesso!" -ForegroundColor Green
    } else {
        Write-Host "Falha ao criar o usuário $usuario." -ForegroundColor Red
    }
}

# Função para desativar um usuário
function Desativar-Usuario {
    param(
        [string]$usuario
    )
    Write-Host "Desativando o usuário $usuario..." -ForegroundColor Yellow
    net user $usuario /active:no
    if ($?) {
        Write-Host "Usuário $usuario desativado com sucesso!" -ForegroundColor Green
    } else {
        Write-Host "Falha ao desativar o usuário $usuario." -ForegroundColor Red
    }
}

# Função para deletar um usuário
function Deletar-Usuario {
    param(
        [string]$usuario
    )
    Write-Host "Tem certeza que deseja deletar o usuário $usuario? (S/N)"
    $confirmacao = Read-Host "Confirmar"
    if ($confirmacao -eq 'S') {
        Write-Host "Deletando o usuário $usuario..." -ForegroundColor Yellow
        net user $usuario /delete
        if ($?) {
            Write-Host "Usuário $usuario deletado com sucesso!" -ForegroundColor Green
        } else {
            Write-Host "Falha ao deletar o usuário $usuario." -ForegroundColor Red
        }
    } else {
        Write-Host "Operação cancelada." -ForegroundColor Yellow
    }
}

# Função para exibir os logs de segurança
function Exibir-LogsSeguranca {
    Write-Host "Exibindo os logs de segurança..." -ForegroundColor Yellow
    try {
        Get-EventLog -LogName Security -Newest 10
    } catch {
        Write-Host "Erro ao tentar acessar os logs de segurança. Detalhes: $_" -ForegroundColor Red
    }
}

# Função para listar processos em execução
function Listar-Processos {
    Write-Host "Exibindo processos em execução:" -ForegroundColor Green
    tasklist | Format-Table -Property ImageName, PID, SessionName, Session# -AutoSize
}

# Função para testar conectividade
function Testar-Conectividade {
    param(
        [string]$host
    )
    Write-Host "Testando conectividade com $host..." -ForegroundColor Yellow
    ping $host
}

# Função para exibir os serviços em execução
function Listar-Servicos {
    Write-Host "Exibindo os serviços em execução:" -ForegroundColor Green
    Get-Service | Format-Table -Property Name, Status, DisplayName -AutoSize
}

# Função para verificar o status do Firewall
function Verificar-Firewall {
    Write-Host "Exibindo status do firewall..." -ForegroundColor Yellow
    powershell Get-NetFirewallProfile
}

# Função principal para exibir o menu interativo e processar a escolha do usuário
function Exibir-Menu {
    Write-Host "Escolha uma opção:" -ForegroundColor Cyan
    Write-Host "1: Criar usuário"
    Write-Host "2: Desativar usuário"
    Write-Host "3: Deletar usuário"
    Write-Host "4: Exibir logs de segurança"
    Write-Host "5: Listar processos em execução"
    Write-Host "6: Testar conectividade"
    Write-Host "7: Listar serviços em execução"
    Write-Host "8: Verificar status do firewall"

    $opcao = Read-Host "Digite a opção desejada"

    switch ($opcao) {
        "1" {
            $usuario = Read-Host "Digite o nome do usuário"
            $senha = Read-Host "Digite a senha do usuário" -AsSecureString
            Criar-Usuario -usuario $usuario -senha $senha
        }
        "2" {
            $usuario = Read-Host "Digite o nome do usuário a ser desativado"
            Desativar-Usuario -usuario $usuario
        }
        "3" {
            $usuario = Read-Host "Digite o nome do usuário a ser deletado"
            Deletar-Usuario -usuario $usuario
        }
        "4" {
            Exibir-LogsSeguranca
        }
        "5" {
            Listar-Processos
        }
        "6" {
            $host = Read-Host "Digite o endereço IP ou nome do host para testar conectividade"
            Testar-Conectividade -host $host
        }
        "7" {
            Listar-Servicos
        }
        "8" {
            Verificar-Firewall
        }
        default {
            Write-Host "Opção inválida!" -ForegroundColor Red
        }
    }
}

# Função principal de execução
function Executar-Script {
    Verificar-PrivilégiosElevados
    Exibir-Menu
}

# Executando o script
Executar-Script
