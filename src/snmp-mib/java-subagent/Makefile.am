if ENABLE_MIB_JAVA_SUBAGENT

plugin_LTLIBRARIES = libsnmp-mib-java-sub-agent.la

libsnmp_mib_java_sub_agent_la_SOURCES = \
	activator.c java-subagent.h java-subagent.c
libsnmp_mib_java_sub_agent_la_CFLAGS= \
	-fPIC
libsnmp_mib_java_sub_agent_la_LDFLAGS = \
        -no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-agent \
        -I$(top_srcdir)/src/snmp-mib

endif
