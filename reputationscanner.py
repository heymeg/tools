#!/usr/bin/env python3

#Assessment features and Risk Score can be tweaked. 
#Set your own rules :(((((
import argparse, socket, subprocess, requests, datetime, ssl, re
from colorama import Fore, init

init(autoreset=True)
GOOD = Fore.GREEN + "[✔] "
BAD  = Fore.RED   + "[✖] "
WARN = Fore.YELLOW+ "[!] "
INFO = Fore.CYAN  + "[+] "

score = 0
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}

def add_score(points, reason):
    global score
    score += points
    print(WARN + reason)

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def detect_scheme(domain):
    try:
        requests.get(f"https://{domain}", headers=headers, timeout=5)
        return "https"
    except:
        return "http"


def dnsbl_check(ip):
    try:
        rev = ".".join(ip.split(".")[::-1])
        socket.gethostbyname(f"{rev}.zen.spamhaus.org")
        return True
    except:
        return False


#TLS Inspection 
def inspect_certificate(domain):
    global score
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])
        expiry = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)

        print(INFO + f"TLS Issuer  : {issuer.get('organizationName','Unknown')}")
        print(INFO + f"TLS Expires : {expiry.date()}")

        if expiry < datetime.datetime.now(datetime.timezone.utc):
            print(BAD + "Certificate expired")
            add_score(4, "Expired TLS certificate")

        if issuer.get("organizationName") is None:
            add_score(3, "Self-signed TLS certificate")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        add_score(1, f"TLS inspection failed: connection error ({e})")
    except ssl.SSLError as e:
        add_score(1, f"TLS inspection failed: SSL error ({e})")
    except Exception as e:
        add_score(1, f"TLS inspection failed: {type(e).__name__}: {e}")


#Domain Age
def get_domain_age(domain):
    try:
        out = subprocess.check_output(
            ["whois", domain],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10
        )
        match = re.search(r"Creation Date:\s*(.+)", out, re.I)
        if match:
            created = match.group(1).split("T")[0]
            created = datetime.datetime.fromisoformat(created)
            return (datetime.datetime.now() - created).days 
    except:
        return None


def scan_domain(domain):
    global score

    scheme = detect_scheme(domain)
    url = f"{scheme}://{domain}"

    print(INFO + f"Target     : {domain}")
    print(INFO + f"Scheme     : {scheme.upper()}")

    ip = resolve_ip(domain)
    if not ip:
        print(BAD + "DNS resolution failed")
        add_score(3, "Unresolvable domain")
        verdict()
        return

    print(INFO + f"IP Address : {ip}")

    try:
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        print(INFO + f"HTTP Code  : {r.status_code}")

        if r.history:
            add_score(1, "Redirect detected")
    except:
        add_score(2, "HTTP connection failed")

    if scheme == "https":
        print(GOOD + "HTTPS enabled")
        inspect_certificate(domain)
    else:
        add_score(2, "Unencrypted HTTP")

    if dnsbl_check(ip):
        print(BAD + "IP listed in Spamhaus DNSBL")
        add_score(4, "DNSBL listing")
    else:
        print(GOOD + "DNSBL clean")

    age = get_domain_age(domain)
    if age is not None:
        print(INFO + f"Domain Age : {age} days ({age/365:.1f}years)")
        if age < 1:
            add_score(2, "New domain")
    else:
        add_score(1, "Unknown domain age")
    verdict()

def verdict():
    print("\n" + INFO + f"Risk Score: {score}")
    if score >= 7:
        print(BAD + "VERDICT: HIGH RISK")
    elif score >= 4:
        print(WARN + "VERDICT: SUSPICIOUS")
    else:
        print(GOOD + "VERDICT: LOW RISK")


def main():
    parser = argparse.ArgumentParser(description="DOMAIN REPUTATION SCANNER")
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    scan_domain(args.domain)

if __name__ == "__main__":
    main()

