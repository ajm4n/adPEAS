from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

def find_kerberoastable_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip)
        conn = Connection(server, user=f"{domain}\\{username}", password=password)
        conn.bind()

        # Search for objects with SPNs set
        conn.search(search_base='DC=' + ',DC='.join(domain.split('.')),
                     search_filter='(servicePrincipalName=*)',
                     search_scope=SUBTREE,
                     attributes=['sAMAccountName', 'servicePrincipalName'])

        kerberoastable_objects = [(entry['sAMAccountName'].value, entry['servicePrincipalName'].values) for entry in conn.entries]

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