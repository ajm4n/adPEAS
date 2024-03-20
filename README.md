# Quick Start
```bash
usage: adPEAS [-h] -u USERNAME [-p PASSWORD] -d DOMAIN -i DC_IP

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for log in.
  -p PASSWORD, --password PASSWORD
                        Password for log in. Will prompt if not specified.
  -d DOMAIN, --domain DOMAIN
                        Domain of the DC.
  -i DC_IP, --dc-ip DC_IP
                        Domain Controller IP or hostname.
```

# Installation
Install `adPEAS` and its dependencies

```bash
pipx install --include-deps git+https://github.com/ajm4n/adPEAS
```

# Features
adPEAS v1.1.0
- Pipx compatibility
- Support flags instead of prompting for input

adPEAS v1.0.0
- Supports Certipy, BloodHound, findDelegation, and Kerberoasting.

Will add more features as I get to work on them, lol.
