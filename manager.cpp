#include "libs/tfldap.h"
#include <getopt.h>

void show_help() {
    cout << "Help message" << endl;
}

int main(int argc, char **argv)
{
    int c;
    bool is_adding = false, is_deleting = false;
    char *attrs_twofactor[] = {"twoFactorToken", "twoFactorIPs",
                               "twoFactorGlobal", "twoFactorGlobalAllowed",
                               "twoFactorSuccess", "twoFactorFail", NULL};
    char *attrs_twofactor_default_vals[][2] = {{"", NULL},
                                              {"", NULL},
                                              {"0", NULL},
                                              {"FALSE", NULL},
                                              {"0", NULL},
                                              {"0", NULL},
                                              {NULL, NULL}};

    string dn = "";

    // Turn off getopt errors
    opterr = 0;

    while ( (c = getopt(argc, argv, "adu:")) != -1 ) {
        switch (c) {
        case 'u':
            dn = optarg;
            continue;
        case 'a':
            is_adding = true;
            continue;
        case 'd':
            is_deleting = true;
            continue;
        default:
            show_help();
            return 0;
        }
    }

    // Manage two-factor class
    if ((is_adding) | (is_deleting)) {
        if (is_adding == is_deleting) {
            cerr << "Sorry, but you can not ADD and DELETE two-factow attributes at the same time" << endl;
            // 1 - 1 == :P
            return -1;
        }
        if (dn.size() == 0) {
            cerr << "You must define search filter (-u) to manage attributes for specific account" << endl;
            return -1;
        }

        TFLdap ldap;
        char *attrs_null[] = {NULL};
        char *attrs_object[] = {"twoFactorData", NULL};


        string fdn = "";
        ptree ldap_res;

        ldap.bind();

        // Check for unique account
        switch (ldap.is_dn_uniq(dn)) {
        case TFLDAP_FILTER_RES_NOT_FOUND:
            cout << "Ldap filter \"" << dn << "\" returns empty results" << endl;
            return 0;
        case TFLDAP_FILTER_RES_IS_NOT_UNIQ:
            cout << "Ldap filter \"" << dn << "\" returns more than 1 result. ";
            cout << "Suggested accounts:" << endl;

            ldap_res = ldap.search(dn, attrs_null);
            BOOST_FOREACH(const ptree::value_type &e, ldap_res)
                    if (e.second.get<string>("") == "Full DN")
                    cout << "- " << ptree_dn_decode(e.first) << endl;
            return 0;
        case TFLDAP_FILTER_RES_IS_UNIQ:
            ldap_res = ldap.search(dn, attrs_null);
            BOOST_FOREACH(const ptree::value_type &e, ldap_res)
                    if (e.second.get<string>("") == "Full DN")
                    fdn = ptree_dn_decode(e.first);
        }

        // Writing data
        if (is_adding) {
            cout << "Adding two-factor object to account: " << fdn << endl;
            cout << "  (All two-factor values will set to default)" << endl;
            cout << "Please, confirm (yes): ";

            string answer;
            cin >> answer;
            if (answer != "yes")
                return 0;

            cout << "- Object \"twoFactorData\"..." << endl;
            ldap.modify(fdn, LDAP_MOD_INCREMENT, "objectClass", attrs_object);

            for (int i = 0; i < sizeof(attrs_twofactor)/sizeof(*attrs_twofactor)-1; i++) {
                cout << "- Attribute \"" << attrs_twofactor[i] << "\"..." << endl;
                ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[i], attrs_twofactor_default_vals[i]);
            }

        } else {
            cout << "Deleting two-factor object from account: " << fdn << endl;
            cout << "Please, confirm (yes): ";

            string answer;
            cin >> answer;
            if (answer != "yes")
                return 0;

            // Removing two-factor attributes
            for (int i = 0; i < sizeof(attrs_twofactor)/sizeof(*attrs_twofactor)-1; i++) {
                cout << "- Attribute \"" << attrs_twofactor[i] << "\"..." << endl;
                ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[i], attrs_null);
            }

            // Removing object
            ptree sres = ldap.search(dn, attrs_null);
            vector<string> res_attrs;
            BOOST_FOREACH(const ptree::value_type &e, sres)
                    BOOST_FOREACH(const ptree::value_type &v, sres.get_child(e.first))
                    if (( v.first == "objectClass" ) & (v.second.get<string>("") != attrs_object[0]))
                    res_attrs.insert(res_attrs.end(), v.second.get<string>(""));

            char **res_values = new char*[res_attrs.size() + 1];
            for (int i = 0; i < res_attrs.size(); i++)
                res_values[i] = const_cast<char*>(res_attrs[i].c_str());
            res_values[res_attrs.size()] = NULL;

            cout << "- Object class \"" << attrs_object[0] << "\"..." << endl;
            ldap.modify(fdn, LDAP_MOD_REPLACE, "objectClass", res_values);
        }
    }

    return 0;
}
