osnmp_mibs_dir = $(datadir)/snmp/mibs
osnmp_mibs__DATA = $(top_srcdir)/doc/mib/*

SUFFIXES = .in

.in:
	@sed \
		-e 's|@SNMP_VERSION[@]|$(VERSION)|g' \
		-e 's|@SNMP_CONF[@]|$(confdir)|g' \
		-e 's|@SNMP_PLUGIN[@]|$(plugindir)|g' \
		-e 's|@SNMP_RUN[@]|$(rundir)|g' \
		-e 's|@SNMP_BIN[@]|$(bindir)|g' \
		-e 's|@SNMP_CACHE[@]|$(cachedir)|g' \
		< $< > $@

man8_MANS = snmpd.8

EXTRA_DIST = \
	mib/* \
	snmpd.8.in

CLEANFILES = \
	snmpd.8

