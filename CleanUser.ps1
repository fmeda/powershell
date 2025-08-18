# Este script deve ser executado com privilégios de Administrador.

# Defina o nome de usuário que você deseja excluir.
# Substitua "NomeDoUsuario" pelo nome de usuário real.
$nomeDoUsuario = "NomeDoUsuario"

# Ponto 1: Excluir o perfil do usuário do registro do sistema.
Write-Host "Excluindo o perfil do usuário do registro..."
$sid = (Get-WmiObject Win32_UserAccount -Filter "Name='$nomeDoUsuario'").SID
if ($sid) {
    $perfilCaminho = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (Test-Path $perfilCaminho) {
        Remove-Item -Path $perfilCaminho -Recurse -Force
        Write-Host "Perfil removido do registro."
    } else {
        Write-Host "Perfil do usuário não encontrado no registro."
    }
} else {
    Write-Host "Usuário não encontrado."
}

# Ponto 2: Excluir a pasta de perfil do usuário.
Write-Host "Excluindo a pasta de perfil do usuário..."
$caminhoPerfil = "C:\Users\$nomeDoUsuario"
if (Test-Path $caminhoPerfil) {
    Remove-Item -Path $caminhoPerfil -Recurse -Force
    Write-Host "Pasta de perfil excluída."
} else {
    Write-Host "Pasta de perfil não encontrada."
}

# Ponto 3: Limpar entradas residuais do usuário no registro.
Write-Host "Limpando entradas residuais do usuário..."
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

foreach ($path in $regPaths) {
    Get-Item -Path $path | ForEach-Object {
        Get-ItemProperty $_.PSPath | ForEach-Object {
            if ($_.PSObject.Properties.Value -match $nomeDoUsuario) {
                Write-Host "Excluindo entrada do registro em: $($_.PSParentPath)"
                Remove-ItemProperty -Path $_.PSParentPath -Name $_.Name -Force
            }
        }
    }
}

# Ponto 4: Limpar o cache de miniaturas e arquivos temporários.
Write-Host "Limpando arquivos de cache e temporários do sistema..."
$cacheCaminho = "C:\Users\$nomeDoUsuario\AppData\Local\Microsoft\Windows\Explorer"
if (Test-Path $cacheCaminho) {
    Remove-Item -Path "$cacheCaminho\thumbcache_*.db" -Force
}

$tempCaminho = "C:\Users\$nomeDoUsuario\AppData\Local\Temp"
if (Test-Path $tempCaminho) {
    Remove-Item -Path "$tempCaminho\*" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Limpeza de arquivos concluída."

Write-Host "Remoção definitiva do usuário e seus dados concluída com sucesso."