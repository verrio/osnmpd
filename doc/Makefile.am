osnmp_mib_dir = $(datadir)/snmp/mib
osnmp_mib__DATA = ./mib/*

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

man8_MANS = ./osnmpd.8

EXTRA_DIST = \
	./mib/* \
	./osnmpd.8.in

CLEANFILES = \
	./osnmpd.8

