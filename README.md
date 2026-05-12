# Network Scanner & Threat Mapper

Automated network scanner that detects open ports, identifies 
service versions, and maps findings to known CVEs.

## What it does
- Scans target IP using nmap
- Detects open ports and running service versions
- Flags dangerous services — SSH, RDP, FTP, Telnet, databases
- Looks up CVEs via three sources with automatic fallback:
  1. Shodan InternetDB — best for public IPs
  2. NIST NVD API — live CVE database
  3. Manual guidance — links to research yourself

## Real finding from home lab
Target: Ubuntu 22.04 running OpenSSH 8.9p1
Result: Falls within CVE-2024-6387 (regreSSHion) — CRITICAL RCE

## How to run
pip install python
nmap must be installed on your system

python3 network_scanner.py

## Built with
- Python 3
- nmap
- Shodan InternetDB API
- NIST NVD API
- Kali Linux home lab