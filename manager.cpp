#include <getopt.h>
#include "libs/tfldap.h"
#include "libs/totp.h"


void show_help();
int check_uniq_account(TFLdap *ldap, string dn, string *fdn);


int main(int argc, char **argv)
{
    int c;
    bool is_adding = false;
    bool is_deleting = false;
    bool todo_token = false;
    char *attrs_null[] = {NULL};
    char *attrs_object[] = {"twoFactorData", NULL};
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

    while ( (c = getopt(argc, argv, "adu:t")) != -1 ) {
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
        case 't':
            todo_token = true;
            continue;
        default:
            show_help();
            return 0;
        }
    }

    TFLdap ldap;
    string fdn = "";

    ldap.bind();

    /*
     * Managing two-factor class
     */
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

        // Check for unique account
        if ( check_uniq_account(&ldap, dn, &fdn) != 1 )
            return 0;

        // Writing data
        if (is_adding) {
            cout << "Adding two-factor objectClass to account: " << fdn << endl;

            cout << "- Object class \"" << attrs_object[0] << "\"..." << endl;
            if (ldap.modify(fdn, LDAP_MOD_INCREMENT, "objectClass", attrs_object) == 20)
                // (20) Type or value exists
                cout << "Account already have two-factor attributes" << endl;
            else
                for (uint i = 0; i < sizeof(attrs_twofactor)/sizeof(*attrs_twofactor)-1; i++) {
                    cout << "- Attribute \"" << attrs_twofactor[i] << "\"..." << endl;
                    ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[i], attrs_twofactor_default_vals[i]);
                }
        } else {
            cout << "Deleting two-factor objectClass from account: " << fdn << endl;
            cout << "Please, confirm (yes): ";

            string answer;
            cin >> answer;
            if (answer != "yes")
                return 0;

            // Removing two-factor attributes
            for (uint i = 0; i < sizeof(attrs_twofactor)/sizeof(*attrs_twofactor)-1; i++) {
                cout << "- Attribute \"" << attrs_twofactor[i] << "\"..." << endl;
                ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[i], attrs_null);
            }

            // Removing object
            cout << "- Object class \"" << attrs_object[0] << "\"..." << endl;
            ldap.remove_value(dn, "objectClass", attrs_object[0]);
        }
    }

    if ((todo_token) & (is_deleting == false)) {
        // Check for unique account
        if ( check_uniq_account(&ldap, dn, &fdn) != 1 )
            return 0;

        // Check two-factor class exist
        vector<string> chck = ldap.get_values(dn, "objectClass");
        bool fail = true;
        for (vector<string>::iterator it = chck.begin() ; it != chck.end(); ++it)
            if (*it == attrs_object[0])
                fail = false;
        if (fail) {
            cout << "Object haven't two-factor class yet" << endl;
            return 0;
        }

        char *values[2] = {NULL, NULL};
        cout << "Enter new token (leave empty to generate random): ";
        string token = "";
        getline(cin, token);

        if (token.size() == 0) {
            cout << "- Generating random token..." << endl;
            uint8_t *seed = totp::get_random_seed();
            ostringstream token;
            for (uint i = 0; i < SEED_LEN; i++)
                token << (char)seed[i];
            values[0] = const_cast<char*>(token.str().c_str());
        } else {
            values[0] = const_cast<char*>(token.c_str());
        }
        cout << "- Replacing current token..." << endl;
        ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[0], values);
    }

    return 0;
}

void show_help() {
    cout << "Help message" << endl;
}

int check_uniq_account(TFLdap *ldap, string dn, string *fdn) {
    ptree ldap_res;

    if (dn.size() == 0) {
        cout << "Please, specify ldap filter (-u)" << endl;
        return -1;
    }

    switch (ldap->is_dn_uniq(dn)) {
    case TFLDAP_FILTER_RES_NOT_FOUND:
        cout << "Ldap filter \"" << dn << "\" returns empty results" << endl;
        return 0;
    case TFLDAP_FILTER_RES_IS_NOT_UNIQ:
        cout << "Ldap filter \"" << dn << "\" returns more than 1 result. ";
        cout << "Suggested accounts:" << endl;

        ldap_res = ldap->search(dn);
        BOOST_FOREACH(const ptree::value_type &e, ldap_res)
                if (e.second.get<string>("") == "Full DN")
                cout << "- " << ptree_dn_decode(e.first) << endl;
        return 0;
    case TFLDAP_FILTER_RES_IS_UNIQ:
        ldap_res = ldap->search(dn);
        BOOST_FOREACH(const ptree::value_type &e, ldap_res)
                if (e.second.get<string>("") == "Full DN")
                *fdn = ptree_dn_decode(e.first);
        return 1;
    }

    return -1;
}
