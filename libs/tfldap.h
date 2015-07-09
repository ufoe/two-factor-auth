#ifndef TFLDAP_H
#define TFLDAP_H

#include <ldap.h>
#include "config.h"

class TFLdap
{
    LDAP *ld;
    LDAPMessage *ldap_result, *entry;
    BerElement *ber;
    berval cred, *server_creds, **values;
    char *attr;
    int version = LDAP_VERSION3;

    public:
        TFLdap();
        ~TFLdap();
        int bind();
        int search(char *);

//    private:

};

#endif // TFLDAP_H
