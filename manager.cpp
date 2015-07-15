#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    char *attrs[] = {"cn", "mail", NULL};
    //char *attrs[] = {"userPassword", NULL};
    string dn = "cn=martin*";
    string fdn = "";
    //string dn = "objectClass=posixAccount";

    ptree ldap_res = ldap.search(dn, attrs);
    BOOST_FOREACH(const ptree::value_type &e, ldap_res)
    {
        if (e.second.get<string>("") == "Full DN") {
            fdn = ptree_dn_decode(e.first);
            cout << "=== " << fdn << " ===" << endl;
        }
        BOOST_FOREACH(const ptree::value_type &v, ldap_res.get_child(e.first))
            cout << v.first << ": " << v.second.get<string>("") << endl;
        cout << endl;
    }

    char *values[] = {"a_email@example.com", NULL};
    ldap.modify(fdn, LDAP_MOD_INCREMENT, "mail", values);

    ldap_res = ldap.search(dn, attrs);
    BOOST_FOREACH(const ptree::value_type &e, ldap_res)
    {
        if (e.second.get<string>("") == "Full DN") {
            fdn = ptree_dn_decode(e.first);
            cout << "=== " << fdn << " ===" << endl;
        }
        BOOST_FOREACH(const ptree::value_type &v, ldap_res.get_child(e.first))
            cout << v.first << ": " << v.second.get<string>("") << endl;
        cout << endl;
    }

}
