#!/usr/bin/env python3
# Cyber Security SOC Framework – Production Ready
# Autor: CyberMaturix
# Versão: 7.0 – Credenciais seguras, retry, TLS, dashboard avançado

import os, sys, signal, subprocess, getpass, json, hashlib, smtplib, asyncio, time, ipaddress, uuid
import paramiko, pandas as pd
from jinja2 import Template
from rich.console import Console
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

console = Console()
CRED_VAULT = "/tmp/.vault_cybercli"
JSON_LOG = "/tmp/cybercli_prod_logs.json"

# ---------------- Signal Handler ----------------
def cleanup_and_exit(sig=None, frame=None):
    if os.path.exists(CRED_VAULT): os.remove(CRED_VAULT)
    console.print("[yellow]🧹 Credenciais removidas do vault[/yellow]")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)

# ---------------- Vault seguro ----------------
def save_credentials(user, password):
    content = f"{user}:{password}"
    with open(CRED_VAULT, "w") as f: f.write(content)
    os.chmod(CRED_VAULT, 0o600)

def load_credentials():
    if os.path.exists(CRED_VAULT):
        user, password = open(CRED_VAULT).read().strip().split(":")
        return user, password
    return None, None

# ---------------- Execução Local/Remota ----------------
def run_local(cmd):
    try: return subprocess.check_output(cmd, shell=True, text=True)
    except Exception as e: return f"Erro local: {e}"

def run_remote(host, cmd, retries=2):
    user, password = load_credentials()
    if not user or not password:
        return f"Erro: credenciais ausentes para {host}"
    attempt = 0
    while attempt <= retries:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=user, password=password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out, err = stdout.read().decode(), stderr.read().decode()
            ssh.close()
            if out or err: return out if out else err
        except Exception as e:
            attempt += 1
            time.sleep(2)
            if attempt > retries:
                return f"Erro remoto {host}: {e}"
    return f"Erro remoto {host}: retries esgotados"

# ---------------- Funções Utilitárias ----------------
def expand_hosts(hosts_input):
    hosts = []
    for h in hosts_input.split(","):
        h = h.strip()
        try:
            if "/" in h:
                net = ipaddress.ip_network(h, strict=False)
                hosts.extend([str(ip) for ip in net.hosts()])
            else:
                hosts.append(h)
        except Exception:
            console.print(f"[red]Host inválido ou CIDR: {h}[/red]")
    return hosts

def save_log(entry):
    logs = []
    if os.path.exists(JSON_LOG):
        with open(JSON_LOG, "r") as f: logs = json.load(f)
    logs.append(entry)
    with open(JSON_LOG, "w") as f: json.dump(logs, f, indent=2)

def hash_output(output):
    return hashlib.sha256(output.encode()).hexdigest()

def send_alert(host, task, output):
    try:
        sender = "alert@domain.com"
        receiver = "security@domain.com"
        msg = MIMEMultipart()
        msg['From'], msg['To'], msg['Subject'] = sender, receiver, f"[ALERTA CRÍTICO] {host}"
        body = f"Tarefa: {task}\nHost: {host}\nOutput:\n{output}"
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP('smtp.domain.com', 587)
        server.starttls()
        server.login("alert@domain.com", "senha_segura")
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        console.print(f"[red]⚠️ Alerta enviado para {receiver}[/red]")
    except Exception as e:
        console.print(f"[red]Erro ao enviar alerta: {e}[/red]")

# ---------------- Tarefas SOC ----------------
TASKS = {
    "Monitoramento": {
        "Integridade": {"cmd":"sudo aide --check", "critical":True},
        "Tentativas login": {"cmd":"grep 'Failed password' /var/log/auth.log", "critical":True},
        "Portas": {"cmd":"ss -tulnp", "critical":False}
    },
    "Auditoria": {
        "Falhas auth": {"cmd":"grep 'Failed password' /var/log/auth.log", "critical":True},
        "Escalonamento root": {"cmd":"grep 'sudo' /var/log/auth.log", "critical":True}
    }
}

# ---------------- Execução Assíncrona ----------------
async def execute_task_async(host, task_name, task_info):
    cmd, critical = task_info["cmd"], task_info["critical"]
    console.print(f"[yellow]▶ Executando {task_name} em {host}[/yellow]")
    output = run_local(cmd) if host=="local" else run_remote(host, cmd)
    log_entry = {
        "id_exec": str(uuid.uuid4()),
        "timestamp": time.time(),
        "host": host,
        "task": task_name,
        "critical": critical,
        "hash": hash_output(output),
        "output": output
    }
    save_log(log_entry)
    if critical and ("Erro" in output or "Failed" in output):
        send_alert(host, task_name, output)
    return log_entry

async def run_tasks(hosts, tasks):
    await asyncio.gather(*[execute_task_async(host, name, info) for host in hosts for name, info in tasks.items()])

# ---------------- Dashboard Profissional ----------------
def generate_dashboard():
    if not os.path.exists(JSON_LOG): return
    with open(JSON_LOG) as f: results = json.load(f)
    df = pd.DataFrame(results)
    template = Template("""
    <html>
    <head><title>Dashboard SOC Production</title></head>
    <body>
    <h1>Relatório SOC – Production Ready</h1>
    <table border="1">
        <tr><th>Host</th><th>Tarefa</th><th>Critical</th><th>Hash</th><th>Output</th></tr>
        {% for row in results %}
        <tr style="color:{% if row['critical'] and 'Erro' in row['output'] %}red{% else %}black{% endif %}">
            <td>{{row['host']}}</td>
            <td>{{row['task']}}</td>
            <td>{{row['critical']}}</td>
            <td>{{row['hash']}}</td>
            <td><pre>{{row['output']}}</pre></td>
        </tr>
        {% endfor %}
    </table>
    </body>
    </html>
    """)
    html_output = template.render(results=results)
    with open("/tmp/dashboard_soc_prod.html", "w") as f: f.write(html_output)
    console.print("[green]✅ Dashboard SOC gerado em /tmp/dashboard_soc_prod.html[/green]")

# ---------------- Menu ----------------
async def menu_async():
    hosts_input = input("Digite hosts ou ranges CIDR separados por vírgula ou 'local': ")
    hosts = expand_hosts(hosts_input)
    console.print("Hosts expandidos:", hosts)
    console.print("Tarefas disponíveis:", list(TASKS.keys()))
    task_choice = input("Escolha a tarefa principal: ")
    if task_choice not in TASKS:
        console.print("[red]Opção inválida[/red]")
        return
    await run_tasks(hosts, TASKS[task_choice])
    generate_dashboard()

# ---------------- Main ----------------
if __name__=="__main__":
    console.print("[bold cyan]Cyber Security SOC Framework v7.0 – Production Ready[/bold cyan]")
    if input("Deseja configurar credenciais? (s/n): ").lower()=="s":
        user=input("Usuário SSH: "); password=getpass.getpass("Senha SSH: ")
        save_credentials(user,password)
    asyncio.run(menu_async())
    cleanup_and_exit()
