#ifndef TFLDAP_H
#define TFLDAP_H

#include <ldap.h>
#include <string>
#include <map>

#include "config.h"

#define ldap_pair(key, value) std::pair<std::string, std::string>(key, value)


class TFLdap {
    LDAP *ld;
    LDAPMessage *ldap_result, *entry;
    BerElement *ber;
    berval cred, *server_creds, **values;
    char *attr;
    int version = LDAP_VERSION3;

public:
    struct ldap_object {
        std::multimap <std::string, std::string> object;
        std::multimap <std::string, std::string>::iterator iter;
    };

    TFLdap();
    ~TFLdap();

    int bind();
    int tfldap_entry_count;

    ldap_object search(std::string);
    ldap_object search(std::string, char**);
    ldap_object search_next();
    int ldap_mod(std::string, int, char*, char *values[]);

private:
    ldap_object tfldap_object;
};

#endif // TFLDAP_H
