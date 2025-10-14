#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco ACL Automator - v2.0
Autor: Fabiano Aparecido
Descrição:
  Automatiza a criação de regras ACL em equipamentos Cisco IOS/IOS-XE,
  com interface CLI moderna, validação de parâmetros, exportação e feedback visual.
"""

import os
import time
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

# ==========================================================
# 🔧 CONFIGURAÇÕES
# ==========================================================
VERSION = "2.0"
EXPORT_PATH = "./output_acls/"
os.makedirs(EXPORT_PATH, exist_ok=True)

# ==========================================================
# 🎨 FUNÇÕES DE INTERFACE
# ==========================================================
def banner():
    print(Fore.CYAN + Style.BRIGHT + "\n🧩 CISCO ACL AUTOMATOR v2.0")
    print(Fore.YELLOW + "Automação inteligente de ACLs Cisco\n")

def feedback(msg, tipo="info"):
    cores = {
        "info": Fore.CYAN,
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "erro": Fore.RED
    }
    print(cores.get(tipo, Fore.WHITE) + f"[{tipo.upper()}] {msg}")

def progresso():
    for _ in range(3):
        print(Fore.BLUE + "Gerando ACL...", end="\r")
        time.sleep(0.4)
        print(" " * 30, end="\r")
        time.sleep(0.4)

# ==========================================================
# 🔍 FUNÇÕES DE VALIDAÇÃO
# ==========================================================
def validar_ip(ip):
    partes = ip.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit() or not 0 <= int(parte) <= 255:
            return False
    return True

def validar_protocolo(proto):
    return proto.lower() in ["tcp", "udp", "icmp", "ip", "any"]

def normalizar_nome(nome):
    return nome.strip().replace(" ", "_").lower()

# ==========================================================
# 🧠 GERAÇÃO DE ACL CISCO
# ==========================================================
def gerar_acl(dados):
    acl = [
        f"ip access-list extended {dados['nome_acl']}",
        f" permit {dados['protocolo']} {dados['origem']} {dados['mascara_origem']} {dados['destino']} {dados['mascara_destino']} eq {dados['porta']}" if dados['porta'] else
        f" permit {dados['protocolo']} {dados['origem']} {dados['mascara_origem']} {dados['destino']} {dados['mascara_destino']}",
        f" remark {dados['descricao']}"
    ]
    return "\n".join(acl)

# ==========================================================
# 📤 EXPORTAÇÃO
# ==========================================================
def exportar_acl(acl_texto, nome_arquivo):
    caminho = os.path.join(EXPORT_PATH, f"{nome_arquivo}.txt")
    with open(caminho, "w") as f:
        f.write(acl_texto)
    feedback(f"ACL exportada com sucesso para: {caminho}", "ok")

# ==========================================================
# 💬 INTERFACE INTERATIVA COM TRATAMENTO DE INTERRUPÇÃO
# ==========================================================
def coletar_dados():
    feedback("Iniciando coleta de parâmetros...\n", "info")
    try:
        nome_acl = normalizar_nome(input("Nome da ACL: "))
        if not nome_acl:
            feedback("Nome da ACL não pode ser vazio. Encerrando operação.", "warn")
            return None

        origem = input("Endereço de origem (ex: 192.168.10.0): ")
        while not validar_ip(origem):
            feedback("IP inválido! Digite novamente.", "erro")
            origem = input("Endereço de origem: ")

        mascara_origem = input("Máscara da origem (ex: 0.0.0.255): ")

        destino = input("Endereço de destino (ex: 10.0.0.5): ")
        while not validar_ip(destino):
            feedback("IP inválido! Digite novamente.", "erro")
            destino = input("Endereço de destino: ")

        mascara_destino = input("Máscara do destino (ex: 0.0.0.255): ")
        protocolo = input("Protocolo [tcp/udp/icmp/ip/any]: ").lower()
        while not validar_protocolo(protocolo):
            feedback("Protocolo inválido!", "erro")
            protocolo = input("Protocolo [tcp/udp/icmp/ip/any]: ").lower()

        porta = input("Porta (opcional, ex: 80): ")
        descricao = input("Descrição da regra: ")

        return {
            "nome_acl": nome_acl,
            "origem": origem,
            "mascara_origem": mascara_origem,
            "destino": destino,
            "mascara_destino": mascara_destino,
            "protocolo": protocolo,
            "porta": porta,
            "descricao": descricao
        }

    except KeyboardInterrupt:
        feedback("\nOperação cancelada pelo usuário. Nenhuma ACL foi gerada.", "warn")
        return None

# ==========================================================
# 🚀 EXECUÇÃO PRINCIPAL COM TRATAMENTO
# ==========================================================
def main():
    banner()
    feedback("Bem-vindo ao criador automático de ACLs Cisco!", "info")
    
    dados = coletar_dados()
    if dados is None:
        feedback("Encerrando execução de forma segura.", "info")
        return

    progresso()
    acl_texto = gerar_acl(dados)

    print("\n" + Fore.MAGENTA + "🧱 ACL Gerada:")
    print(tabulate([[line] for line in acl_texto.splitlines()], tablefmt="grid"))

    exportar_acl(acl_texto, f"{dados['nome_acl']}")
    feedback("Processo concluído com sucesso!", "ok")

if __name__ == "__main__":
    main()
