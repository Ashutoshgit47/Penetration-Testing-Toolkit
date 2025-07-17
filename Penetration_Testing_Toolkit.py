import os
import time
import socket
from datetime import datetime
import concurrent.futures
import subprocess
import json

try:
    import whois  # python-whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from termcolor import colored
except ImportError:
    def colored(x, *_a, **_kw):
        return x

# SSH (optional)
try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False

import ftplib

# ---------------- Settings ----------------
THREADS_PORTSCAN = 100
THREADS_SUBDOMAIN = 100
BRUTE_TRIES_PARALLEL = 5
LOG_FILE = "pentest_log.txt"

# Common wordlists
COMMON_SUBS = (
    "www", "mail", "ftp", "dev", "test", "api", "blog", "shop", "staging",
    "beta", "portal", "admin", "vpn", "demo", "cdn"
)
COMMON_VULN_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS"}

# ---------- Helpers ----------

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def safe_input(prompt: str, default: str = "") -> str:
    try:
        return input(prompt)
    except (OSError, EOFError):
        print(prompt + default)
        return default

# ---------- UI ----------

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(colored("""
╔═══════════════════ PENTESTING TOOLKIT ═══════════════════╗
    """, "cyan"))


def menu():
    print(colored("[1] Quick WHOIS Lookup", "yellow"))
    print(colored("[2] Quick Subdomain Finder", "yellow"))
    print(colored("[3] Quick Port Scanner", "yellow"))
    print(colored("[4] Quick Vulnerability Check", "yellow"))
    print(colored("[5] Quick Password Brute (FTP/SSH)", "yellow"))
    print(colored("[0] Exit", "red"))

# ---------- 1. WHOIS ----------

def quick_whois(domain: str):
    print(colored(f"\n[~] WHOIS: {domain}", "cyan"))
    if not WHOIS_OK:
        print(colored("Install python-whois for full info (pip install python-whois)", "red"))
        return
    try:
        data = whois.whois(domain)
        print(json.dumps(data, indent=2, default=str))
        log(f"WHOIS {domain}: {data}")
    except Exception as e:
        print(colored(f"[!] WHOIS error: {e}", "red"))

# ---------- 2. Subdomain Finder ----------

def _probe_sub(domain: str, sub: str, out: list):
    try:
        host = f"{sub}.{domain}"
        socket.gethostbyname(host)
        print(colored(f"[+] {host}", "green"), flush=True)
        out.append(host)
        log(f"Subdomain found: {host}")
    except socket.gaierror:
        pass


def quick_subfinder(domain: str):
    print(colored(f"\n[~] Subdomain brute on {domain}", "cyan"))
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS_SUBDOMAIN) as ex:
        for sub in COMMON_SUBS:
            ex.submit(_probe_sub, domain, sub, found)
    if not found:
        print(colored("[!] No common subdomains resolved", "yellow"))

# ---------- 3. Port Scanner ----------

def _check_port(ip: str, p: int, open_list: list):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex((ip, p)) == 0:
                open_list.append(p)
                print(colored(f"[+] {p}/TCP open", "green"), flush=True)
    except Exception:
        pass


def quick_ports(target: str):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(colored("Invalid host", "red")); return
    ports = range(1, 1025)
    print(colored(f"\n[~] Fast scan (1-1024) on {ip}", "cyan"))
    open_p = []
    start = datetime.now()
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS_PORTSCAN) as ex:
        for p in ports:
            ex.submit(_check_port, ip, p, open_p)
    dur = datetime.now() - start
    print(colored(f"Finished in {dur}. Open: {open_p}", "cyan"))

# ---------- 4. Vulnerability Check ----------

def quick_vuln(target: str):
    print(colored(f"\n[~] Quick Vuln Check {target}", "cyan"))
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(colored("Invalid host", "red")); return
    hits = []
    for port, svc in COMMON_VULN_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((ip, port)) == 0:
                hits.append((port, svc))
                print(colored(f"Possible exposure: {svc} on {port}", "red"))
    if not hits:
        print(colored("No quick issues found", "green"))

# ---------- 5. Brute (FTP/SSH) ----------

def quick_brute(target: str):
    svc = safe_input("Service ftp/ssh: ")
    user = safe_input("Username: ")
    wl = safe_input("Wordlist path: ")
    try:
        pwds = [p.strip() for p in open(wl, encoding="utf-8", errors="ignore") if p.strip()]
    except FileNotFoundError:
        print(colored("Wordlist missing", "red")); return

    func = None
    if svc == "ftp":
        def func(pwd):
            try:
                with ftplib.FTP(target, timeout=3) as ftp:
                    ftp.login(user=user, passwd=pwd)
                    return pwd
            except Exception:
                return None
    elif svc == "ssh" and PARAMIKO_OK:
        def func(pwd):
            try:
                ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=user, password=pwd, timeout=4)
                ssh.close(); return pwd
            except Exception:
                return None
    else:
        print(colored("Unsupported svc or paramiko missing", "red")); return

    with concurrent.futures.ThreadPoolExecutor(max_workers=BRUTE_TRIES_PARALLEL) as ex:
        futures = {ex.submit(func, pwd): pwd for pwd in pwds}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            pwd = futures[fut]
            if result:
                print(colored(f"[+] {user}:{pwd}", "green")); return
            else:
                print(colored(f"[-] {user}:{pwd}", "red"), flush=True)
    print(colored("No creds found", "yellow"))

# ---------- MAIN ----------
if __name__ == "__main__":
    while True:
        banner()
        menu()
        choice = safe_input("\nEnter option: ").strip()
        if choice == "0":
            print("Goodbye!")
            break
        target = safe_input("Target domain/IP: ") if choice in {"1", "2", "3", "4", "5"} else ""
        if choice == "1":
            quick_whois(target)
        elif choice == "2":
            quick_subfinder(target)
        elif choice == "3":
            quick_ports(target)
        elif choice == "4":
            quick_vuln(target)
        elif choice == "5":
            quick_brute(target)
        else:
            print(colored("Invalid option", "red"))
        safe_input("\nPress ENTER to continue...")