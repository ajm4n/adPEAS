from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

def find_kerberoastable_users(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip)
        conn = Connection(server, user=f"{domain}\\{username}", password=password)
        conn.bind()

        # Search for kerberoastable users (users with SPNs set)
        conn.search(search_base='DC=' + ',DC='.join(domain.split('.')),
                     search_filter='(&(objectCategory=user)(objectClass=user)(servicePrincipalName=*))',
                     search_scope=SUBTREE,
                     attributes=['sAMAccountName'])

        kerberoastable_users = [entry['sAMAccountName'].value for entry in conn.entries]

        conn.unbind()

        return kerberoastable_users

    except Exception as e:
        print(f"Error while searching for kerberoastable users: {e}")
        return []

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"

kerberoastable_users = find_kerberoastable_users(username, password, domain, dc_ip)
if kerberoastable_users:
    print("Kerberoastable users found:")
    for user in kerberoastable_users:
        print(user)
else:
    print("No kerberoastable users found.")