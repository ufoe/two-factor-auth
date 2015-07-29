#include "tfldap.h"

string ptree_dn_encode(string s) {
    int pos = 0;
    while( ( pos = s.find(".") ) != -1 )
        s.replace(pos, 1, ldap_dn_dot_replacer);

    return s;
}

string ptree_dn_decode(string s) {
    int pos = 0;
    while( ( pos = s.find(ldap_dn_dot_replacer) ) != -1 )
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
        cerr << "[TFLdap::bind] Error occured: " << res << endl << ldap_err2string(res) << endl;
        exit(-1);
    }

    return res;
}

ptree TFLdap::search(string ldapfilter) {
    return search(ldapfilter, NULL);
}

ptree TFLdap::search(string ldapfilter, char **attrs) {
    ptree res;
    LDAPMessage *ldap_result;
    BerElement *ber;

    int r = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE,
                              ldapfilter.c_str(), attrs, 0, NULL, NULL,
                              LDAP_NO_LIMIT, LDAP_NO_LIMIT, &ldap_result);
    if ( r != LDAP_SUCCESS) {
        cerr << "[TFLdap::search] error occured: (" << r << ") " << ldap_err2string(r) << endl;
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

int TFLdap::is_dn_uniq(string searchdn) {
    ptree res;

    res = search(searchdn);
    switch (res.size()) {
    case 0:
        return TFLDAP_FILTER_RES_NOT_FOUND;
    case 1:
        return TFLDAP_FILTER_RES_IS_UNIQ;
    default:
        return TFLDAP_FILTER_RES_IS_NOT_UNIQ;
    }
}

int TFLdap::_modify_add(string fdn, char *attr, char **values) {
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_ADD;
    mod.mod_type = attr;
    mod.mod_values = values;

    LDAPMod *mods[2];
    mods[0] = &mod;
    mods[1] = NULL;

    int res = ldap_add_ext_s(ld, fdn.c_str(), mods, NULL, NULL);
    if ( res != LDAP_SUCCESS )
        cerr << "[TFLdap::_modify_add] error occured: (" << res << ") " << ldap_err2string(res) << endl;
    return res;
}

int TFLdap::_modify_increment(string fdn, char *attr, char **values) {
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_INCREMENT;
    mod.mod_type = attr;
    mod.mod_values = values;

    LDAPMod *mods[2];
    mods[0] = &mod;
    mods[1] = NULL;

    int res = ldap_modify_ext_s(ld, fdn.c_str(), mods, NULL, NULL);
    if ( res == LDAP_SUCCESS )
        return res;

    // Gather current values
    string dn = fdn.substr(0, fdn.find(','));
    vector<string> res_attrs;
    char *attrs[2] = {attr, NULL};
    ptree sres = search(dn, attrs);
    BOOST_FOREACH(const ptree::value_type &e, sres)
            if (( e.second.get<string>("") == "Full DN") & ( fdn == ptree_dn_decode(e.first))) {
            BOOST_FOREACH(const ptree::value_type &v, sres.get_child(e.first))
            if ( v.first == attr )
            res_attrs.insert(res_attrs.end(), v.second.get<string>(""));
            }

    // Append new values
    for ( unsigned int i = 0; i < sizeof(values)/sizeof(*values); i++)
        res_attrs.insert(res_attrs.end(), values[i]);

    // Make new array of values
    char **res_values = new char*[res_attrs.size() + 1];
    for ( unsigned int i = 0; i < res_attrs.size(); i++)
        res_values[i] = const_cast<char*>(res_attrs[i].c_str());
    res_values[res_attrs.size()] = NULL;

    // Execute modify ;)
    return _modify_replace(fdn, attr, res_values);
}

int TFLdap::_modify_replace(string fdn, char *attr, char **values) {
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = attr;
    mod.mod_values = values;

    LDAPMod *mods[2];
    mods[0] = &mod;
    mods[1] = NULL;

    int res = ldap_modify_ext_s(ld, fdn.c_str(), mods, NULL, NULL);
    if ( res != LDAP_SUCCESS )
        cerr << "[TFLdap::_modify_replace] error occured: (" << res << ") " << ldap_err2string(res) << endl;
    return res;
}

int TFLdap::modify(string fdn, int mod_op, char *attr, char **values) {
    int res;
    switch (mod_op) {
    case LDAP_MOD_ADD:
        return _modify_add(fdn, attr, values);
    case LDAP_MOD_INCREMENT:
        return _modify_increment(fdn, attr, values);
    case LDAP_MOD_REPLACE:
        return _modify_replace(fdn, attr, values);
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
    // Use it with attention!
    //    If even 1 value from argument is already presented in an object -
    //    ALL attribute values will be REPLACED with a new array
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

int TFLdap::remove_value(string dn, char *attr, char *value) {
    ptree sres = search(dn);
    string fdn;

    vector<string> res_attrs;
    BOOST_FOREACH(const ptree::value_type &e, sres) {
        if ( e.second.get<string>("") == "Full DN")
            fdn = ptree_dn_decode(e.first);
        BOOST_FOREACH(const ptree::value_type &v, sres.get_child(e.first))
                if (( v.first == attr ) & (v.second.get<string>("") != value))
                res_attrs.insert(res_attrs.end(), v.second.get<string>(""));
    }

    char **res_values = new char*[res_attrs.size() + 1];
    for ( unsigned int i = 0; i < res_attrs.size(); i++)
        res_values[i] = const_cast<char*>(res_attrs[i].c_str());
    res_values[res_attrs.size()] = NULL;

    return modify(fdn, LDAP_MOD_REPLACE, attr, res_values);
}

string TFLdap::get_value(string dn, char *attr) {
    ptree sres = search(dn);
    string res;

    BOOST_FOREACH(const ptree::value_type &e, sres)
        BOOST_FOREACH(const ptree::value_type &v, sres.get_child(e.first))
                if ( v.first == attr )
                    res = v.second.get<string>("");

    return res;
}

vector<string> TFLdap::get_values(string dn, char *attr) {
    ptree sres = search(dn);
    vector<string> res;

    BOOST_FOREACH(const ptree::value_type &e, sres)
        BOOST_FOREACH(const ptree::value_type &v, sres.get_child(e.first))
                if ( v.first == attr )
                    res.insert(res.end(), v.second.get<string>(""));

    return res;
}
