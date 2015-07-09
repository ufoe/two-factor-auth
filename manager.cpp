#include <iostream>
#include <ldap.h>

#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    TFLdap::ldap_object tfldap_res;

    std::cout << "== First query ==" << std::endl;

    tfldap_res = ldap.search("objectClass=posixGroup");
    for (int i = 0; i < ldap.tfldap_entry_count; i++) {
        std::multimap <std::string, std::string>::iterator iter;
        for (iter = tfldap_res.object.begin();
             iter != tfldap_res.object.end(); iter++) {
            std::cout << (*iter).first << ": " << (*iter).second << '\n';
        }
        std::cout << std::endl;
        tfldap_res = ldap.search_next();
    }

    std::cout << "== Second query ==" << std::endl;

    tfldap_res = ldap.search("cn=manager");
    for (int i = 0; i < ldap.tfldap_entry_count; i++) {
        std::multimap <std::string, std::string>::iterator iter;
        for (iter = tfldap_res.object.begin();
             iter != tfldap_res.object.end(); iter++) {
            std::cout << (*iter).first << ": " << (*iter).second << '\n';
        }
        std::cout << std::endl;
        tfldap_res = ldap.search_next();
    }


}
