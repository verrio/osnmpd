SUBDIRS = agent system sensors power ip java-subagent

noinst_LIBRARIES = libsnmp-mib.a

libsnmp_mib_a_SOURCES = \
	single-level-module.c single-level-module.h \
	single-table-module.c single-table-module.h \
	mib-utils.h mib-utils.c

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-agent

install-exec-hook:
	find $(plugindir) -type f -name \*.la -delete
