#include <iostream>

#include "tfldap.h"


TFLdap::TFLdap()
{
    cred.bv_val = ldap_pass;
    cred.bv_len = sizeof(ldap_pass)-1;
}

TFLdap::~TFLdap() {
    // Unbind from LDAP
    ldap_unbind_ext_s(ld, NULL, NULL);
}

int TFLdap::bind() {
    ldap_initialize(&ld, ldap_url);
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    int res = ldap_sasl_bind_s(ld, ldap_dn, LDAP_SASL_AUTOMATIC, &cred, NULL, NULL, &server_creds);
    if ( res != LDAP_SUCCESS) {
        std::cerr << "Error occured: " << res << std::endl << ldap_err2string(res) << std::endl;
    } else {
        std::cout << "Ldap connection established" << std::endl;
    }

    return res;
}

int TFLdap::search(char *ldapfilter) {
    int res = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE, ldapfilter,
                            NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &ldap_result);
    if ( res != LDAP_SUCCESS) {
        std::cerr << "Error occured: " << res << std::endl << ldap_err2string(res) << std::endl;
    } else {
        for (entry = ldap_first_entry(ld, ldap_result); entry != NULL; entry = ldap_next_entry(ld, entry)) {
            for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
                values = ldap_get_values_len(ld, entry, attr);
                // Multiple values definition
                for (int i = 0; i < ldap_count_values_len(values); i++)
                    std::cout << attr  << ": " << values[i]->bv_val << std::endl;
                ldap_value_free_len(values);
            }
            std::cout << std::endl;
        }
        // Free LDAP vars
        if ( ber != NULL )
            ber_free(ber, 0);
        ldap_memfree(attr);
        ldap_msgfree(ldap_result);
    }

    return 0;
}
