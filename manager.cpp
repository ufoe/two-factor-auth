#include <iostream>
#include <ldap.h>

#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    TFLdap::ldap_object tfldap_res;


    char *attrs[] = {NULL};
//    std::cout << "== First query ==" << std::endl;
//    char *attrs[] = {"mail", "audio", NULL};
//    tfldap_res = ldap.search("cn=manager", attrs);
//    for (int i = 0; i < ldap.tfldap_entry_count; i++) {
//        std::multimap <std::string, std::string>::iterator iter;
//        for (iter = tfldap_res.object.begin();
//             iter != tfldap_res.object.end(); iter++) {
//            std::cout << (*iter).first << ": " << (*iter).second << '\n';
//        }
//        std::cout << std::endl;
//        tfldap_res = ldap.search_next();
//    }

    std::string dn = (*ldap.search("cn=manager", attrs).object.begin()).second;
    std::cout << "DN to modify: " << dn << std::endl;

    char *values[] = {"soundb", NULL};
    ldap.ldap_mod(dn, LDAP_MOD_INCREMENT, "audio", values);

    std::cout << "== Second query ==" << std::endl;

    tfldap_res = ldap.search(dn, attrs);
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
