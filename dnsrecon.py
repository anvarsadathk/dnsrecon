#!/usr/bin/env python3
"""
dnsrecon - DNS enumeration and zone-transfer checker.

Enumerates common record types, discovers nameservers, attempts an AXFR
zone transfer against each (a classic misconfiguration), and can brute
a small subdomain list via DNS resolution.

Uses dnspython if available (full features incl. AXFR); otherwise falls
back to stdlib resolution for basic records.

Author: Anvar Sadath K.  |  License: MIT
Only query infrastructure you own or are authorized to assess.
"""
import argparse
import socket
import sys

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "SRV", "CAA"]
DEFAULT_SUBS = ["www", "mail", "ftp", "dev", "staging", "test", "api", "admin",
                "vpn", "ns1", "ns2", "smtp", "webmail", "portal", "gitlab",
                "jenkins", "internal", "intranet", "autodiscover", "cpanel"]


def enum_records(domain):
    results = {}
    resolver = dns.resolver.Resolver()
    for rt in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rt, lifetime=5)
            results[rt] = [a.to_text() for a in answers]
        except Exception:
            pass
    return results


def try_axfr(domain, nameservers):
    vuln = []
    for ns in nameservers:
        ns_host = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_host)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=8))
            names = [f"{n}.{domain}" for n in zone.nodes.keys()]
            vuln.append((ns_host, names))
        except Exception:
            pass
    return vuln


def brute_subs(domain, subs):
    found = []
    for s in subs:
        host = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append((host, ip))
        except Exception:
            pass
    return found


def stdlib_basic(domain):
    print("[*] dnspython not installed — basic stdlib mode (A records only).",
          file=sys.stderr)
    try:
        name, aliases, ips = socket.gethostbyname_ex(domain)
        print(f"A/CNAME: {name} {aliases} {ips}")
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="DNS enumeration + zone-transfer check.")
    p.add_argument("domain")
    p.add_argument("--axfr", action="store_true", help="attempt zone transfer on each NS")
    p.add_argument("--brute", action="store_true", help="resolve a built-in subdomain list")
    p.add_argument("-w", "--wordlist", help="subdomain wordlist for --brute")
    p.add_argument("-o", "--output", help="write a summary to file")
    args = p.parse_args()

    domain = args.domain.strip(". ").lower()
    out_lines = [f"# dnsrecon: {domain}"]

    if not HAVE_DNS:
        stdlib_basic(domain)
        print("[i] install dnspython for records/AXFR:  pip install dnspython",
              file=sys.stderr)
        return

    print(f"[*] Enumerating records for {domain} ...", file=sys.stderr)
    records = enum_records(domain)
    for rt, vals in records.items():
        for v in vals:
            line = f"{rt}\t{v}"
            print(line); out_lines.append(line)

    nameservers = [v.split()[0] for v in records.get("NS", [])]

    if args.axfr and nameservers:
        print(f"[*] Attempting AXFR against {len(nameservers)} nameserver(s) ...",
              file=sys.stderr)
        vuln = try_axfr(domain, nameservers)
        if vuln:
            for ns, names in vuln:
                head = f"[CRITICAL] AXFR allowed on {ns} — {len(names)} records leaked"
                print(head); out_lines.append(head)
                for n in names[:200]:
                    print(f"  {n}"); out_lines.append(f"  {n}")
        else:
            print("[+] No nameserver allowed zone transfer.", file=sys.stderr)

    if args.brute:
        subs = DEFAULT_SUBS
        if args.wordlist:
            with open(args.wordlist, errors="ignore") as f:
                subs = [x.strip() for x in f if x.strip() and not x.startswith("#")]
        print(f"[*] Resolving {len(subs)} candidate subdomains ...", file=sys.stderr)
        for host, ip in brute_subs(domain, subs):
            line = f"SUB\t{host}\t{ip}"
            print(line); out_lines.append(line)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(out_lines) + "\n")
        print(f"[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
