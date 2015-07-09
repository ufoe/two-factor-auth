#include <iostream>
#include <ldap.h>

#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    ldap.search("cn=manager");
}
