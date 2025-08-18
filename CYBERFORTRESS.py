#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure Cyber Program - 2025

Descrição: Ferramenta de automação para hardening, coleta forense e varredura de rede.
           Projetado para ambientes de produção.
"""
import os
import sys
import subprocess
import hashlib
import logging
import argparse
import secrets
from colorama import Fore, Style, init

try:
    from cryptography.fernet import Fernet
    from dotenv import load_dotenv
except ImportError as e:
    print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} As dependências essenciais 'cryptography' e 'python-dotenv' não foram encontradas.")
    print(f"Por favor, instale-as manualmente: {Fore.YELLOW}pip install cryptography python-dotenv{Style.RESET_ALL}")
    sys.exit(1)

# Carrega variáveis de ambiente a partir do arquivo .env
load_dotenv()

# -----------------------------------
# Configurações de Ambiente (do .env)
# -----------------------------------
LOG_FILE = os.getenv('LOG_FILE', '/var/log/secure_program.log')
CREDENTIAL_FILE = os.getenv('CREDENTIAL_FILE', '/etc/secure_program/.vault.enc')
KEY_FILE = os.getenv('KEY_FILE', '/etc/secure_program/keyfile.bin')
HASH_FILE = os.getenv('HASH_FILE', '/etc/secure_program/script_hash.sha256')
SCRIPTS_DIR = os.getenv('SCRIPTS_DIR', './scripts')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

# -----------------------------------
# Configuração de Logging
# -----------------------------------
init(autoreset=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# -----------------------------------
# Funções de Segurança e Utilidade
# -----------------------------------
def _is_root():
    """Verifica se o usuário atual é root."""
    return os.geteuid() == 0

def _get_script_path():
    """Retorna o caminho completo para o script em execução."""
    return os.path.abspath(sys.argv[0])

def check_environment():
    """Verifica permissões, dependências e a integridade do ambiente."""
    if not _is_root():
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Este script deve ser executado com privilégios de superusuário (root).")
        logging.critical("Execução abortada. Privilégios de root ausentes.")
        sys.exit(1)

    required_dirs = [SCRIPTS_DIR, '/etc/secure_program']
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Diretório '{directory}' verificado/criado.")

    logging.info("Verificação de ambiente concluída com sucesso.")

def generate_and_encrypt_credentials():
    """Cria e protege credenciais se não existirem."""
    if not os.path.exists(CREDENTIAL_FILE) or not os.path.exists(KEY_FILE):
        logging.warning("Credenciais e chave de criptografia não encontradas. Gerando novas.")
        try:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            
            fernet = Fernet(key)
            # Use segredos seguros e aleatórios em vez de um padrão fixo
            creds = secrets.token_bytes(32)
            with open(CREDENTIAL_FILE, "wb") as f:
                f.write(fernet.encrypt(creds))
            
            logging.info("Credenciais geradas e protegidas com sucesso.")
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Credenciais seguras criadas.")
        except IOError as e:
            logging.error(f"Falha ao criar credenciais. Verifique permissões de escrita: {e}")
            print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Falha ao criar credenciais. Verifique permissões.")
            sys.exit(1)

def verify_script_integrity():
    """Verifica a integridade do script usando um hash SHA256."""
    script_path = _get_script_path()
    try:
        with open(script_path, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        if not os.path.exists(HASH_FILE):
            with open(HASH_FILE, "w") as f:
                f.write(current_hash)
            logging.info("Hash inicial do script registrado.")
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Hash de integridade inicial registrado.")
        else:
            with open(HASH_FILE, "r") as f:
                saved_hash = f.read().strip()
            if saved_hash != current_hash:
                logging.critical("Alerta de Segurança: Alteração de código não autorizada detectada!")
                print(f"{Fore.RED}[CRÍTICO]{Style.RESET_ALL} Alerta de Segurança: O script foi modificado. Saia imediatamente!")
                sys.exit(1)
            logging.info("Integridade do script verificada com sucesso.")
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Integridade do script verificada.")
    except (IOError, OSError) as e:
        logging.error(f"Falha na verificação de integridade: {e}")
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Falha na verificação de integridade.")
        sys.exit(1)

def execute_task(task, task_path):
    """Executa o script externo para a tarefa selecionada."""
    full_path = os.path.join(SCRIPTS_DIR, task_path)
    
    if not os.path.exists(full_path):
        logging.error(f"Script '{full_path}' para a tarefa '{task}' não encontrado.")
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Script '{os.path.basename(full_path)}' não encontrado em '{SCRIPTS_DIR}'.")
        return

    try:
        logging.info(f"Iniciando a tarefa '{task}' com o script '{full_path}'.")
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Executando a tarefa: '{task}'.")
        
        if full_path.endswith('.sh'):
            subprocess.run([full_path], check=True)
        elif full_path.endswith('.py'):
            subprocess.run([sys.executable, full_path], check=True)
            
        logging.info(f"Tarefa '{task}' concluída com sucesso.")
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Tarefa '{task}' finalizada com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"A tarefa '{task}' falhou com código de saída {e.returncode}. Erro: {e}")
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} A tarefa '{task}' falhou. Verifique o log para detalhes.")
    except Exception as e:
        logging.error(f"Ocorreu um erro inesperado durante a execução da tarefa '{task}': {e}")
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Ocorreu um erro inesperado. Verifique o log para mais informações.")

# -----------------------------------
# Lógica Principal do Programa
# -----------------------------------
def main():
    """Função principal que orquestra o fluxo de execução."""
    parser = argparse.ArgumentParser(
        description="Secure Cyber Program 2025 - Ferramenta de segurança em produção."
    )
    parser.add_argument("--task",
                        choices=["hardening", "forensic", "network"],
                        help="A tarefa de segurança a ser executada.")
    parser.add_argument("--range",
                        help="Range de IP para varredura de rede (ex: 192.168.1.0/24).")

    args = parser.parse_args()

    # Se nenhum argumento for fornecido, exibe a ajuda.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Executa pré-verificações críticas
    check_environment()
    verify_script_integrity()
    generate_and_encrypt_credentials()

    # Mapeia as tarefas para os caminhos dos scripts externos
    TASKS = {
        "hardening": "SecureMilitaryHardening.sh",
        "forensic": "forensic_collector.py",
        "network": "network_scanner.py"
    }

    task_to_run = args.task
    if task_to_run in TASKS:
        execute_task(task_to_run, TASKS[task_to_run])
    else:
        print(f"{Fore.YELLOW}[AVISO]{Style.RESET_ALL} Nenhuma tarefa válida selecionada. Use --help para ver as opções.")
        logging.warning("Nenhuma tarefa válida selecionada.")

    logging.info("Programa finalizado.")
    print(f"{Fore.BLUE}=== Execução do Secure Cyber Program concluída ==={Style.RESET_ALL}")


if __name__ == "__main__":
    main()