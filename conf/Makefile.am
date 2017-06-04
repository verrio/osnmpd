SUFFIXES = .in

.in:
	@sed \
		-e 's|@SNMP_VERSION[@]|$(agent_version)|g' \
		-e 's|@SNMP_CONF[@]|$(confdir)|g' \
		-e 's|@SNMP_PLUGIN[@]|$(plugindir)|g' \
		-e 's|@SNMP_RUN[@]|$(rundir)|g' \
		-e 's|@SNMP_BIN[@]|$(bindir)|g' \
		-e 's|@SNMP_CACHE[@]|$(cachedir)|g' \
		< $< > $@

EXTRA_DIST = \
	snmpd.conf.in \
	snmpd.in

CLEANFILES = \
	snmpd.conf \
	snmpd

conf_DATA = ./snmpd.conf
init_ddir = $(sysconfdir)/init.d
init_d_SCRIPTS = ./snmpd

