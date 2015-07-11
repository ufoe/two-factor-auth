#include "tfldap.h"

string ptree_dn_encode(string s) {
    int pos = 0;
    while( ( pos = s.find(".") ) != string::npos )
        s.replace(pos, 1, ldap_dn_dot_replacer);

    return s;
}

string ptree_dn_decode(string s) {
    int pos = 0;
    while( ( pos = s.find(ldap_dn_dot_replacer) ) != string::npos )
        s.replace(pos, sizeof(ldap_dn_dot_replacer)/sizeof(char) -1, ".");

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
        cerr << "Error occured: " << res << endl << ldap_err2string(res) << endl;
        exit(-1);
    } else {
        cout << "Ldap connection established" << endl;
    }

    return res;
}

ptree TFLdap::search(string ldapfilter) {
    return TFLdap::search(ldapfilter, NULL);
}

ptree TFLdap::search(string ldapfilter, char **attrs) {
    ptree res;
    LDAPMessage *ldap_result;
    BerElement *ber;

    int r = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE,
                              ldapfilter.c_str(), attrs, 0, NULL, NULL,
                              LDAP_NO_LIMIT, LDAP_NO_LIMIT, &ldap_result);
    if ( r != LDAP_SUCCESS) {
        cerr << "[TFLdap::search] error occured: " << r << endl << ldap_err2string(r) << endl;
    } else {

        // Get ldap entry
        for (LDAPMessage *entry = ldap_first_entry(ld, ldap_result); entry != NULL; entry = ldap_next_entry(ld, entry)) {
            // Put full DN
            string fdn = ptree_dn_encode(ldap_get_dn(ld, entry));
            res.add(fdn, "Full DN");

            // Get attributes
            for (char *attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
                // Get values
                berval **values = ldap_get_values_len(ld, entry, attr);
                for (int i = 0; i < ldap_count_values_len(values); i++)
                    res.add(fdn + string(".") + string(attr), values[i]->bv_val);
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

int TFLdap::_modify_add(string fdn, int mod_op, char *attr, char **values) {
    return 0;
}

int TFLdap::_modify_increment(string fdn, int mod_op, char *attr, char **values) {
    return 0;
}

int TFLdap::_modify_replace(string fdn, int mod_op, char *attr, char **values) {
    return 0;
}

int TFLdap::modify(string fdn, int mod_op, char *attr, char **values) {
    int res;
    switch (mod_op) {
    case LDAP_MOD_ADD:
        return _modify_add(fdn, mod_op, attr, values);
    case LDAP_MOD_INCREMENT:
        return _modify_increment(fdn, mod_op, attr, values);
    case LDAP_MOD_REPLACE:
        return _modify_replace(fdn, mod_op, attr, values);
    case LDAP_MOD_INC_OR_ADD:
        res = modify(fdn, LDAP_MOD_INCREMENT, attr, values);
        if ( res != LDAP_SUCCESS )
            res = modify(fdn, LDAP_MOD_ADD, attr, values);
        return res;
    case LDAP_MOD_ADD_OR_REPLACE:
        res = modify(fdn, LDAP_MOD_ADD, attr, values);
        if ( res != LDAP_SUCCESS )
            res = modify(fdn, LDAP_MOD_REPLACE, attr, values);
        return res;
    case LDAP_MOD_INC_OR_ADD_OR_REPLACE:
        res = modify(fdn, LDAP_MOD_INCREMENT, attr, values);
        if ( res != LDAP_SUCCESS )
            res = modify(fdn, LDAP_MOD_ADD, attr, values);
        if ( res != LDAP_SUCCESS )
            res = modify(fdn, LDAP_MOD_REPLACE, attr, values);
        return res;
    default:
        cerr << "Used unsupported modify method in TFLdap::modify(): " << mod_op << endl;
        return -1;
    }
}
