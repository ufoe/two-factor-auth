#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    char *attrs[] = {NULL};
    //char *attrs[] = {"userPassword", NULL};
    string dn = "cn=martin*";
    //string dn = "objectClass=posixAccount";
    ptree ldap_res = ldap.search(dn, attrs);

    BOOST_FOREACH(const ptree::value_type &e, ldap_res)
    {
        if (e.second.get<string>("") == "Full DN")
            cout << "=== " << ptree_dn_decode(e.first) << " ===" << endl;
        BOOST_FOREACH(const ptree::value_type &v, ldap_res.get_child(e.first))
        {
            cout << v.first << ": " << v.second.get<string>("") << endl;
        }
        cout << endl;
    }
}
