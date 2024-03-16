from ldap3 import Server, Connection, SUBTREE

def find_kerberoastable_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip, port=389)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication='NTLM', auto_bind=True)

        # Search for objects with SPNs set
        search_base = 'DC=' + ',DC='.join(domain.split('.'))
        search_filter = '(servicePrincipalName=*)'
        attributes = ['sAMAccountName', 'servicePrincipalName']
        conn.search(search_base, search_filter, SUBTREE, attributes=attributes)

        # Parse search result
        kerberoastable_objects = []
        for entry in conn.entries:
            sAMAccountName = entry['sAMAccountName'].value
            servicePrincipalNames = entry['servicePrincipalName'].values
            kerberoastable_objects.append((sAMAccountName, servicePrincipalNames))

        conn.unbind()
        return kerberoastable_objects

    except Exception as e:
        print(f"Error while searching for kerberoastable objects: {e}")
        return []

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"


kerberoastable_objects = find_kerberoastable_objects(username, password, domain, dc_ip)
if kerberoastable_objects:
    print("Kerberoastable objects found:")
    for obj, spns in kerberoastable_objects:
        print(f"Object: {obj}, SPNs: {', '.join(spns)}")
else:
    print("No kerberoastable objects found.")