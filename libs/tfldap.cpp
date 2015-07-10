#include "tfldap.h"


std::string ptree_dn_encode(std::string s) {
    int pos = 0;
    while( ( pos = s.find(".") ) != std::string::npos )
        s.replace(pos, 1, ldap_dn_dot_replacer);

    return s;
}

std::string ptree_dn_decode(std::string s) {
    int pos = 0;
    while( ( pos = s.find("***") ) != std::string::npos )
        s.replace(pos, sizeof(ldap_dn_dot_replacer)/sizeof(char), ".");

    return s;
}

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
        exit(-1);
    } else {
        std::cout << "Ldap connection established" << std::endl;
    }

    return res;
}

boost::property_tree::ptree TFLdap::search(std::string ldapfilter) {
    return TFLdap::search(ldapfilter, NULL);
}

boost::property_tree::ptree TFLdap::search(std::string ldapfilter, char **attrs) {
    boost::property_tree::ptree res;
    LDAPMessage *ldap_result;
    BerElement *ber;

    int r = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE,
                              ldapfilter.c_str(), attrs, 0, NULL, NULL,
                              LDAP_NO_LIMIT, LDAP_NO_LIMIT, &ldap_result);
    if ( r != LDAP_SUCCESS) {
        std::cerr << "[TFLdap::search] error occured: " << r << std::endl << ldap_err2string(r) << std::endl;
    } else {

        // Get ldap entry
        for (LDAPMessage *entry = ldap_first_entry(ld, ldap_result); entry != NULL; entry = ldap_next_entry(ld, entry)) {
            // Put full DN
            std::string fdn = ptree_dn_encode(ldap_get_dn(ld, entry));
            res.add(fdn, "Full DN");

            // Get attributes
            for (char *attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
                // Get values
                berval **values = ldap_get_values_len(ld, entry, attr);
                for (int i = 0; i < ldap_count_values_len(values); i++)
                    res.add(fdn + std::string(".") + std::string(attr), values[i]->bv_val);
                ldap_value_free_len(values);
            }
            if ( ber != NULL )
                ber_free(ber, 0);

            // If entry does not have any provided attrs
            if ( res.get_child(fdn).size() == 0 )
                res.pop_back();
        }
        ldap_msgfree(ldap_result);
    }

    return res;
}

