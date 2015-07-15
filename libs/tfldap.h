#ifndef TFLDAP_H
#define TFLDAP_H

#define LDAP_MOD_INC_OR_ADD             (0x0201)
#define LDAP_MOD_ADD_OR_REPLACE         (0x0202)
#define LDAP_MOD_INC_OR_ADD_OR_REPLACE  (0x0203)

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

private:
    int _modify_add(string fdn, char *attr, char **values);
    int _modify_increment(string fdn, char *attr, char **values);
    int _modify_replace(string fdn, char *attr, char **values);
};

#endif // TFLDAP_H
