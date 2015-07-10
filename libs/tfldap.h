#ifndef TFLDAP_H
#define TFLDAP_H

#include <ldap.h>
#include <string>
#include <map>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/foreach.hpp>

#include "config.h"

std::string ptree_dn_encode(std::string);
std::string ptree_dn_decode(std::string);

class TFLdap {
    LDAP *ld;
    berval cred, *server_creds;
    int version = LDAP_VERSION3;

public:
    struct ldap_object {
        std::multimap <std::string, std::string> object;
        std::multimap <std::string, std::string>::iterator iter;
    };

    TFLdap();
    ~TFLdap();

    int bind();
    boost::property_tree::ptree search(std::string);
    boost::property_tree::ptree search(std::string, char**);

private:
    ldap_object tfldap_object;
};

#endif // TFLDAP_H
