#include <iostream>

#include "tfldap.h"
#include <cstdio>

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

TFLdap::ldap_object TFLdap::search(std::string ldapfilter) {
    return TFLdap::search(ldapfilter, NULL);
}

TFLdap::ldap_object TFLdap::search(std::string ldapfilter, char **attrs) {

    int res = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE, ldapfilter.c_str(),
                                attrs, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &ldap_result);
    if ( res != LDAP_SUCCESS) {
        std::cerr << "Error occured: " << res << std::endl << ldap_err2string(res) << std::endl;
    } else {
        entry = ldap_first_entry(ld, ldap_result);
        tfldap_entry_count = ldap_count_entries(ld, ldap_result);
        tfldap_object.object.clear();

        // Put first value into object
        attr = ldap_first_attribute(ld, entry, &ber);
        values = ldap_get_values_len(ld, entry, attr);

        // Put full DN
        tfldap_object.iter = tfldap_object.object.insert(ldap_pair("TFLdapFullDN", ldap_get_dn(ld, entry)));

        // Put first attr
        tfldap_object.object.insert(tfldap_object.iter, ldap_pair(attr, values[0]->bv_val));
        for (int i = 1; i < ldap_count_values_len(values); i++)
            tfldap_object.object.insert(tfldap_object.iter, ldap_pair(attr, values[i]->bv_val));

        for (attr = ldap_next_attribute(ld, entry, ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
            values = ldap_get_values_len(ld, entry, attr);

            // Multiple values definition
            for (int i = 0; i < ldap_count_values_len(values); i++)
                tfldap_object.object.insert(tfldap_object.iter, ldap_pair(attr, values[i]->bv_val));
            ldap_value_free_len(values);
        }
    }

    return tfldap_object;
}

TFLdap::ldap_object TFLdap::search_next() {
    if ( ber != NULL) {
        tfldap_object.object.clear();
        entry = ldap_next_entry(ld, entry);

        if (entry == NULL) {
            // Free LDAP vars
            if ( ber != NULL )
                ber_free(ber, 0);
            ldap_memfree(attr);
            ldap_msgfree(ldap_result);
        } else {

            // Put first value into object
            attr = ldap_first_attribute(ld, entry, &ber);
            values = ldap_get_values_len(ld, entry, attr);
            tfldap_object.iter = tfldap_object.object.insert(ldap_pair(attr, values[0]->bv_val));
            for (int i = 1; i < ldap_count_values_len(values); i++)
                tfldap_object.object.insert(tfldap_object.iter, ldap_pair(attr, values[i]->bv_val));

            for (attr = ldap_next_attribute(ld, entry, ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
                values = ldap_get_values_len(ld, entry, attr);

                // Multiple values definition
                for (int i = 0; i < ldap_count_values_len(values); i++)
                    tfldap_object.object.insert(tfldap_object.iter, ldap_pair(attr, values[i]->bv_val));
                ldap_value_free_len(values);
            }
        }
    }

    return tfldap_object;
}

int TFLdap::ldap_mod(std::string ldapfilter, int mod_op, char *attr, char *values[]) {

    if ( mod_op == LDAP_MOD_INCREMENT) {
        // Get current values
        char *attrs[] = {attr, NULL};
        ldap_object tfldap_res = search(ldapfilter, attrs);
        if (tfldap_entry_count != 1) {
            std::cerr << "Error in ldap_mod(): DN " << mod_op << " is not unique" << std::endl;
            return -1;
        }

        char **ivalues;
        ivalues = new char *[tfldap_res.object.size()];
        int i = 0;

        // Create new values array
        std::multimap <std::string, std::string>::iterator iter;
        for (iter = tfldap_res.object.begin();
             iter != tfldap_res.object.end(); iter++) {
            if ((*iter).first == attr ) {
                sprintf(ivalues[i], "%s", (*iter).second.c_str());
                std::cout << ivalues[i] << std::endl;
                i++;
            }
        }
    }

    int res;
    LDAPMod mod;
    mod.mod_op = mod_op;
    mod.mod_type = attr;
    mod.mod_values = values;

    LDAPMod *mods[2];
    mods[0] = &mod;
    mods[1] = NULL;

    switch (mod_op) {
    case LDAP_MOD_ADD:
        res = ldap_add_ext_s(ld, ldapfilter.c_str(), mods, NULL, NULL);
        // Try next method if attr's value is not exists
        if ( res == LDAP_SUCCESS )
            break;
    case LDAP_MOD_REPLACE:
        mods[0]->mod_op = LDAP_MOD_REPLACE;
        res = ldap_modify_ext_s(ld, ldapfilter.c_str(), mods, NULL, NULL);
        break;
    default:
        std::cerr << "Used unsupported modify method in ldap_mod(): " << mod_op << std::endl;
        return -1;
    }

    if ( res != LDAP_SUCCESS )

        std::cerr << "Error occured on ldap_mod(): " << res << std::endl << ldap_err2string(res) << std::endl;

    return res;
}
