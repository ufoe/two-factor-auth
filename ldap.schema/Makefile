tmp_dir = /tmp/ldif
schema = two-factor_openldap
pretty = twoFactor

all:
	mkdir $(tmp_dir)
	echo "include $(schema).schema" > $(tmp_dir)/$(schema).conf
	slaptest -f $(tmp_dir)/$(schema).conf -F $(tmp_dir)
	find $(tmp_dir) -name *$(schema).ldif -exec cp {} $(tmp_dir)/$(schema).ldif \;
	sed -r "/^(\#|structural|entry[C|U]|creat[e|o]|modif[i|y])/d" -i $(tmp_dir)/$(schema).ldif
	sed "s/{.}$(schema)/$(pretty)/" -i $(tmp_dir)/$(schema).ldif
	sed "s/cn=$(pretty)/cn=$(pretty),cn=schema,cn=config/" -i $(tmp_dir)/$(schema).ldif
	@printf "\nNow you are able to import LDIF. Example:"
	@printf "\n\n    ldapadd -WD cn=admin,cn=config -f $(tmp_dir)/$(schema).ldif"
	@printf "\n\nIf you will get error like \"Invalid credentials (49)\" - check admin account/password.\n\n"

clean:
	[ \! -d $(tmp_dir) ] || rm -rf $(tmp_dir)
