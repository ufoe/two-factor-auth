#ifndef TFLDAP_H
#define TFLDAP_H

#include <ldap.h>
#include <string>
#include <map>
#include <iostream>
#include <vector>
#include <boost/property_tree/ptree.hpp>
#include <boost/foreach.hpp>

#include "config.h"

using namespace std;
using namespace boost::property_tree;

#define LDAP_MOD_INC_OR_ADD             (0x0201)
#define LDAP_MOD_ADD_OR_REPLACE         (0x0202)
#define LDAP_MOD_INC_OR_ADD_OR_REPLACE  (0x0203)

#define TFLDAP_FILTER_RES_IS_UNIQ       0
#define TFLDAP_FILTER_RES_IS_NOT_UNIQ   1
#define TFLDAP_FILTER_RES_NOT_FOUND     -1


string ptree_dn_encode(string);
string ptree_dn_decode(string);

class TFLdap {
    LDAP *ld;
    berval cred, *server_creds;
    int version = LDAP_VERSION3;

public:
    TFLdap();
    ~TFLdap();

    int bind();
    ptree search(string ldapfilter);
    ptree search(string ldapfilter, char **attrs);
    int modify(string fdn, int mod_op, char *attr, char **values);
    string get_value(string dn, char *attr);
    vector<string> get_values(string dn, char *attr);
    int remove_value(string dn, char *attr, char *value);
    int is_dn_uniq(string searchdn);

private:
    int _modify_add(string fdn, char *attr, char **values);
    int _modify_increment(string fdn, char *attr, char **values);
    int _modify_replace(string fdn, char *attr, char **values);
};

#endif // TFLDAP_H
