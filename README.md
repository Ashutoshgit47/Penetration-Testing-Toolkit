# Penetration-Testing-Toolkit

A powerful multi-threaded **cybersecurity toolkit** for recon, scanning, and brute-forcing operations. Built in Python for penetration testing education and demonstrations.

> ⚠️ **Educational Use Only**  
> Unauthorized scanning is illegal. Use only on systems you own or are authorized to test.

---

## 🧰 Features

- 🔎 WHOIS Lookup with `python-whois`
- 🌐 Subdomain Brute-Force (multi-threaded)
- 🚪 Fast Port Scanner (1–1024)
- ⚠️ Vulnerability Check for common services
- 🔐 Password Brute Forcer (FTP/SSH) – Threaded
- 📊 Text-based Reports & Export Files
- 🔁 Clear modular layout with penetration testing phases

---


## 💻 Requirements

- Python 3.7+
- Optional (but recommended):

```bash
pip install termcolor
pip install python-whois
pip install paramiko  # optional, for SSH brute
```
---
## 🧑‍💻 How to Run

Save the script to pentest_toolkit.py

Run in terminal:

```bas
https://github.com/Ashutoshgit47/Penetration-Testing-Toolkit.git
python pentest_toolkit.py
```
Follow the interactive menu to scan a domain or IP.

---
## 📂 Example Usage

## 🔍 WHOIS
```bash

[~] WHOIS: example.com
{
  "domain_name": "EXAMPLE.COM",
  "registrar": "ICANN",
  ...
}
```
---
## 🌐 Subdomain Finder

```bash
[+] www.example.com
[+] dev.example.com
```
---

## 🔓 Port Scan

```bash

[+] 21/TCP open
[+] 80/TCP open
```
---

## 🚨 Vulnerability Check
```bash

Possible exposure: FTP on 21
Possible exposure: HTTP on 80
```
---

## 🔐 FTP/SSH  Brute

```bash

[+] admin:123456
```
---

## 📝 Notes

All actions are logged to pentest_log.txt

Make sure the target is in your scope and you have permission to test!

SSH brute-forcing requires paramiko, and too many attempts may get you blocked.

---

## ⚠️ Disclaimer

This tool is for educational and authorized penetration testing only.
Do not use it against systems without explicit permission.

## 📜 License

MIT License

---

## 🤝 Credits
Built with by Ashutosh Gautam 
