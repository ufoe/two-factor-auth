#include <getopt.h>
#include <ctime>
#include <cstdio>
#include "libs/tfldap.h"
#include "libs/tftotp.h"

#include <boost/array.hpp>
void show_help(char *name);
int check_uniq_account(TFLdap *ldap, string dn, string *fdn);


int main(int argc, char **argv)
{

    int c;
    string ban = "";
    bool with_args = false;
    bool is_adding = false;
    bool is_deleting = false;
    bool todo_token = false;
    bool todo_qr = false;
    char *attrs_null[] = {NULL};
    char *attrs_object[] = {"twoFactorData", NULL};
    char *attrs_twofactor[] = {"twoFactorToken", "twoFactorIPs",
                               "twoFactorGlobal", "twoFactorGlobalAllowed",
                               "twoFactorSuccess", "twoFactorFail", NULL};
    char *attrs_twofactor_default_vals[][2] = {{"", NULL},
                                              {"", NULL},
                                              {"-1", NULL},
                                              {"FALSE", NULL},
                                              {"0", NULL},
                                              {"0", NULL},
                                              {NULL, NULL}};

    string dn = "";

    // Turn off getopt errors
    opterr = 0;

    while ( (c = getopt(argc, argv, "ab:df:tq")) != -1 ) {
        with_args = true;
        switch (c) {
        case 'a':
            is_adding = true;
            continue;
        case 'b':
            ban.append(optarg);
            if ( ban != "-" )
                for ( unsigned int i = 0 ; i < ban.size() ; i++ )
                    if ( !isdigit(ban[i]) ) {
                        cerr << "Argument -b requires a number or \"-\" (" << ban << " NaN)" << endl;
                        exit(-1);
                    }
            continue;
        case 'd':
            is_deleting = true;
            continue;
        case 'f':
            dn = optarg;
            continue;
        case 't':
            todo_token = true;
            continue;
        case 'q':
            todo_qr = true;
            continue;
        case '?':
            if ((optopt == 'f') | (optopt == 'b'))
                cerr << "Option -" << (char)optopt << " requires an argument" << endl;
            else if (isprint (optopt))
                cerr << "Unknown option \"-" << (char)optopt << "\"" << endl;
            show_help(argv[0]);
        }
    }

    if (with_args == false)
        show_help(argv[0]);

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
            cerr << "Ldap filter (-u) is not defined" << endl;
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
                cerr << "Account already have two-factor attributes" << endl;
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
            cerr << "Object haven't two-factor class yet" << endl;
            return 0;
        }

        char *values[2] = {NULL, NULL};
        cout << "- Generating random token..." << endl;
        string token = ""; //(const char*)TOTP::get_random_seed32();

        values[0] = const_cast<char*>(token.c_str());
        cout << "- Replacing current token..." << endl;
        cout << "[DEBUG] token: " << token << endl;
        ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[0], values);
    }

    if ( ban.size() > 0 ) {
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
            cerr << "Object haven't two-factor class yet" << endl;
            return 0;
        }

        char *values[] = {"-1", NULL};
        if ( ban != "0" ) {
            ostringstream ban_t;
            if ( ban == "-" ) {
                cout << "- Removing ban..." << endl;
                ban_t << 0;
            } else {
                cout << "- Applying temporary ban..." << endl;
                ban_t << 0 - ( atoi(ban.c_str()) + time(0) );
            }
            values[0] = const_cast<char*>(ban_t.str().c_str());
        } else
            cout << "- Applying permanent ban..." << endl;

        ldap.modify(fdn, LDAP_MOD_REPLACE, attrs_twofactor[2], values);
    }

    if (todo_qr) {
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
            cerr << "Object haven't two-factor class yet" << endl;
            return 0;
        }

//        string asdasd = "I hate base32";
//        cout << "Source string: " << asdasd << endl;

//        int len = Base32::GetEncode32Length(asdasd.size()) ;
//        unsigned char *encoded = new unsigned char [ len ];
//        Base32::Encode32((unsigned char*)asdasd.c_str(), asdasd.size(),  encoded);
//        cout << "Encoded string: " << encoded << endl;

//        Base32::Map32(encoded, len, alpha);
//        cout << "Mapped encoded string: " << encoded << endl;

//        Base32::Unmap32(encoded, len, alpha);
//        cout << "Unmapped encoded string: " << encoded << endl;

//        unsigned char *decoded = new unsigned char [ Base32::GetDecode32Length(len) ];
//        Base32::Decode32(encoded, len,  decoded);
//        cout << "Decoded string: " << decoded << endl;


        cout << "Account: " << fdn << endl;
        cout << "Token: " << ldap.get_value(dn, attrs_twofactor[0]) << endl;
        TFTOTP totp(ldap.get_value(dn, attrs_twofactor[0]));
        cout << "TOTP code32: " << totp.generateCode() << endl;
    }

    return 0;
}

void show_help(char *name) {
    cout << "Usage: " << name << " [OPTION...]" << endl;
    cout << endl;
    cout << "  -a                     add two factor objectClass and attributes to object" << endl;
    cout << "  -b -|INTEGER           \"-\" used to remove ban, \"0\" for permanent ban," << endl;
    cout << "                         positive number used as period for temporary ban" << endl;
    cout << "  -d                     delete two factor objectClass and attributes from object" << endl;
    cout << "  -f STRING              ldap filter (man ldapsearch)" << endl;
    cout << "  -t                     generate or regenerate TOTP token for object" << endl;
    cout << endl;
    cout << "Report bugs to https://github.com/tylkas/two-factor-auth/issues" << endl;

    exit(0);
}

int check_uniq_account(TFLdap *ldap, string dn, string *fdn) {
    ptree ldap_res;

    if (dn.size() == 0) {
        cerr << "Please, specify ldap filter (-f)" << endl;
        return -1;
    }

    switch (ldap->is_dn_uniq(dn)) {
    case TFLDAP_FILTER_RES_NOT_FOUND:
        cerr << "Ldap filter \"" << dn << "\" returns empty results" << endl;
        return 0;
    case TFLDAP_FILTER_RES_IS_NOT_UNIQ:
        cerr << "Ldap filter \"" << dn << "\" returns more than 1 result. ";
        cerr << "Suggested accounts:" << endl;

        ldap_res = ldap->search(dn);
        BOOST_FOREACH(const ptree::value_type &e, ldap_res)
                if (e.second.get<string>("") == "Full DN")
                cerr << "- " << ptree_dn_decode(e.first) << endl;
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
