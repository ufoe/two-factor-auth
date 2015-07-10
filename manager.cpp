#include "libs/tfldap.h"

int main()
{
    TFLdap ldap;
    ldap.bind();

    char *attrs[] = {NULL};
    //char *attrs[] = {"userPassword", NULL};
    //std::string dn = "objectClass=*";
    std::string dn = "cn=*";
    boost::property_tree::ptree ldap_res = ldap.search(dn, attrs);

    BOOST_FOREACH(const boost::property_tree::ptree::value_type &e, ldap_res)
    {
        if (e.second.get<std::string>("") == "Full DN")
            std::cout << "=== " << ptree_dn_decode(e.first) << " ===" << std::endl;
        BOOST_FOREACH(const boost::property_tree::ptree::value_type &v, ldap_res.get_child(e.first))
        {
            std::cout << v.first << ": " << v.second.get<std::string>("") << std::endl;
        }
        std::cout << std::endl;
    }
}
