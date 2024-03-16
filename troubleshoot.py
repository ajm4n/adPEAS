from impacket.ldap import ldap, ldapasn1

def find_kerberoastable_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controller via LDAP
        ldap_conn = ldap.LDAPConnection(dc_ip, username=f"{domain}\\{username}", password=password)
        ldap_conn.connect()

        # Search for objects with SPNs set
        search_base = 'DC=' + ',DC='.join(domain.split('.'))
        search_filter = '(servicePrincipalName=*)'
        attributes = ['sAMAccountName', 'servicePrincipalName']
        search_request = ldapasn1.SearchRequest(baseObject=ldapasn1.LDAPDN(search_base),
                                                scope=ldapasn1.SearchRequest.SUB,
                                                derefAliases=ldapasn1.SearchRequest.NEVER_DEREF_ALIASES,
                                                sizeLimit=0,
                                                timeLimit=0,
                                                typesOnly=ldapasn1.LDAPBool(False),
                                                filter=ldapasn1.LDAPFilter(filterstr=search_filter),
                                                attributes=attributes)
        search_result = ldap_conn.search(search_request)

        # Parse search result
        kerberoastable_objects = []
        for entry in search_result:
            if isinstance(entry, ldapasn1.SearchResultEntry):
                sAMAccountName = entry['attributes']['sAMAccountName'][0]
                servicePrincipalNames = entry['attributes']['servicePrincipalName']
                kerberoastable_objects.append((sAMAccountName, servicePrincipalNames))

        ldap_conn.disconnect()
        return kerberoastable_objects

    except Exception as e:
        print(f"Error while searching for kerberoastable objects: {e}")
        return []

# Example usage:
# Replace "username", "password", "domain", and "dc_ip" with your actual credentials and domain controller's IP address
username = "ajman"
password = "DomainAdmin123!"
domain = "snaplabs.local"
dc_ip = "10.10.0.86"


kerberoastable_objects = find_kerberoastable_objects(username, password, domain, dc_ip)
if kerberoastable_objects:
    print("Kerberoastable objects found:")
    for obj, spns in kerberoastable_objects:
        print(f"Object: {obj}, SPNs: {', '.join(spns)}")
else:
    print("No kerberoastable objects found.")