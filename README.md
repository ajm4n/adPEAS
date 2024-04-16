# Quick Start
```bash
usage: adPEAS [-h] [--version] -u USERNAME [-p PASSWORD] -d DOMAIN -i DC_IP

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -u USERNAME, --username USERNAME
                        Username for log in.
  -p PASSWORD, --password PASSWORD
                        Password for log in. Will prompt if not specified.
  -d DOMAIN, --domain DOMAIN
                        Domain of the DC.
  -i DC_IP, --dc-ip DC_IP
                        Domain Controller IP or hostname.
  -s scope.txt, --scope scope.txt
                        Supply a scope.txt file.
  -ns, --no-bloodhound
                        Run adPEAS without running Bloodhound.
  -nc, --no-certipy
                        Run adPEAS without running Certipy. 
```

# Installation
Install `adPEAS` and its dependencies

```bash
pipx install --include-deps git+https://github.com/ajm4n/adPEAS
```

# Example Usage

```
adPEAS -u ajman -p 'DomainAdmin123!' -d snaplabs.local -i 10.0.0.86
```

![image](https://github.com/ajm4n/adPEAS/assets/60402150/cb8970ff-0308-4750-8cfe-e4d00b31b553)

![image](https://github.com/ajm4n/adPEAS/assets/60402150/60a324c4-2b85-4164-8b4f-2ea225a1c53c)

![image](https://github.com/ajm4n/adPEAS/assets/60402150/4bd4b3c5-3b73-4041-96f7-3e909a8ceb44)

