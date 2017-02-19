SUBDIRS = snmp-core snmp-mib snmp-agent

bin_PROGRAMS = osnmpd

osnmpd_SOURCES =
osnmpd_LDADD = \
        $(top_builddir)/src/snmp-agent/libsnmp-agent.a \
        $(top_builddir)/src/snmp-mib/libsnmp-mib.a \
        $(top_builddir)/src/snmp-core/libsnmp.a \
        -lrt -ldl \
        $(OPENSSL_LIB)
osnmpd_LDFLAGS = \
        -Wl,-export-dynamic \
        -Wl,--whole-archive,$(top_builddir)/src/snmp-agent/libsnmp-agent.a,--no-whole-archive \
        -Wl,--whole-archive,$(top_builddir)/src/snmp-mib/libsnmp-mib.a,--no-whole-archive \
        -Wl,--whole-archive,$(top_builddir)/src/snmp-core/libsnmp.a,--no-whole-archive

