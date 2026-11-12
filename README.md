# dnsrecon

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/recon-dns-orange)

DNS **enumeration + zone-transfer checker**. Pulls the common record types, discovers nameservers, attempts an **AXFR zone transfer** against each (a classic, high-impact misconfiguration that dumps the entire zone), and can resolve a built-in subdomain list.

## Features
- Enumerates A, AAAA, NS, MX, TXT, SOA, CNAME, SRV, CAA
- `--axfr` zone-transfer attempt on every nameserver (flags CRITICAL on success)
- `--brute` subdomain resolution (built-in list or `-w` wordlist)
- Graceful stdlib fallback when `dnspython` isn't installed

## Install
```bash
git clone https://github.com/anvarsadathk/dnsrecon.git
cd dnsrecon
pip install -r requirements.txt   # recommended (dnspython)
python3 dnsrecon.py --help
```

## Usage
```bash
# Record enumeration
python3 dnsrecon.py example.com

# Everything: records + zone transfer + subdomain brute
python3 dnsrecon.py example.com --axfr --brute -o dns.txt

# Custom subdomain wordlist
python3 dnsrecon.py example.com --brute -w subs.txt
```

## ⚠️ Responsible use
Record enumeration is passive, but zone-transfer attempts and brute resolution should only target infrastructure you own or are explicitly authorized to assess. A successful AXFR is a reportable finding — disclose it, don't abuse it.

## License
MIT © Anvar Sadath K.
