import subprocess
import json
import urllib.request
import os
from datetime import datetime

def scan_target(ip):
    print(f"\n=== Network Scanner & Threat Mapper ===")
    print(f"Target: {ip}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    print("Running port scan...")
    result = subprocess.run(
        ['nmap', '-sV', '--open', ip],
        capture_output=True,
        text=True
    )
    return result.stdout

def parse_results(raw_output):
    findings = []
    lines = raw_output.split('\n')
    for line in lines:
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            port = parts[0].split('/')[0]
            service = parts[2] if len(parts) > 2 else 'unknown'
            version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
            findings.append({
                'port': port,
                'service': service,
                'version': version
            })
    return findings

def check_dangerous(findings):
    dangerous_ports = {
        '22': 'SSH — brute force risk if weak password',
        '23': 'Telnet — unencrypted, highly dangerous',
        '21': 'FTP — unencrypted file transfer',
        '3389': 'RDP — remote desktop, brute force risk',
        '3306': 'MySQL — database exposed',
        '5432': 'PostgreSQL — database exposed',
        '80': 'HTTP — unencrypted web traffic',
        '8080': 'HTTP Alt — possible admin panel',
    }
    alerts = []
    for finding in findings:
        if finding['port'] in dangerous_ports:
            alerts.append({
                'port': finding['port'],
                'service': finding['service'],
                'version': finding['version'],
                'risk': dangerous_ports[finding['port']]
            })
    return alerts

def check_shodan(ip):
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        vulns = data.get('vulns', [])
        cpes = data.get('cpes', [])
        if vulns:
            print(f"  [Shodan] Found {len(vulns)} known CVEs for this IP")
            if cpes:
                print(f"  Detected software: {', '.join(cpes)}")
            for v in vulns:
                print(f"  [{v}] → https://cvedb.shodan.io/cve/{v}")
            return True
    except:
        pass
    return False

def check_nist(service, version):
    try:
        query = f"{service} {version}".replace(' ', '%20')
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        cves = data.get('vulnerabilities', [])
        cutoff_year = datetime.now().year - 3
        recent = []
        for item in cves:
            cve = item.get('cve', {})
            published = cve.get('published', '')
            year = published[:4] if published else '0'
            if int(year) >= cutoff_year:
                recent.append(item)
        if recent:
            print(f"  [NIST] Found {len(recent)} recent CVEs")
            for item in recent:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                desc = cve.get('descriptions', [{}])[0].get('value', '')[:100]
                print(f"  [{cve_id}] {desc}")
            return True
    except:
        pass
    return False

def manual_lookup_guide(alerts):
    print("\n  CVE lookup unavailable via API.")
    print("  Search manually using the details below:\n")
    for a in alerts:
        version_num = a['version'].split()[0]
        print(f"  Service: {a['service']} {version_num}")
        print(f"  NIST search: https://nvd.nist.gov/vuln/search")
        print(f"  Shodan CVE:  https://cvedb.shodan.io")
        print(f"  Search tip:  {a['service']} {version_num}\n")

def cve_menu(target, alerts):
    print("\n=== CVE Lookup ===\n")
    print("  Trying Shodan InternetDB...")
    found = check_shodan(target)

    if not found:
        print("  Shodan returned nothing (private IP or not indexed).")
        print("  Trying NIST live API...\n")
        for a in alerts:
            version_num = a['version'].split()[0]
            found = check_nist(a['service'], version_num)
            if found:
                break

    if not found:
        print("  NIST API unavailable or rate limited.\n")
        print("  Choose an option:")
        print("  [1] Show manual lookup guide — where to search yourself")
        print("  [2] Download CVE database info — what it is and how to get it\n")

        choice = input("  Enter choice (1 or 2): ").strip()

        if choice == '1':
            manual_lookup_guide(alerts)

        elif choice == '2':
            print("\n  === About Local CVE Database ===\n")
            print("  NIST no longer provides bulk JSON feed downloads (retired 2024).")
            print("  The new method is the NIST 2.0 API which we already tried above.")
            print("\n  For a full offline database, professional tools like")
            print("  OpenVAS and Nessus maintain their own synced databases.")
            print("\n  For manual research use these free sources:")
            print("  NIST NVD    → https://nvd.nist.gov/vuln/search")
            print("  Shodan CVE  → https://cvedb.shodan.io")
            print("  Exploit-DB  → https://www.exploit-db.com")
            print("  MITRE CVE   → https://cve.mitre.org")
            print("\n  Search tip: Enter service name + version number")
            print("  Example: OpenSSH 8.9p1\n")
            manual_lookup_guide(alerts)
        else:
            print("  Invalid choice. Run again to retry.")

# Main
target = input("Enter target IP: ")
raw = scan_target(target)

print("=== Open Ports Found ===\n")
findings = parse_results(raw)

if not findings:
    print("  No open ports found.")
else:
    for f in findings:
        print(f"  Port {f['port']} → {f['service']} {f['version']}")

print("\n=== Threat Assessment ===\n")
alerts = check_dangerous(findings)

if not alerts:
    print("  No high risk services detected.")
else:
    for a in alerts:
        print(f"  [RISK] Port {a['port']} — {a['service']}")
        print(f"         Version: {a['version']}")
        print(f"         Risk: {a['risk']}")

if alerts:
    cve_menu(target, alerts)

print(f"\nTotal open ports: {len(findings)}")
print(f"High risk services: {len(alerts)}")
print("\nScan complete.")