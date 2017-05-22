if ENABLE_MIB_AGENT

plugin_LTLIBRARIES = libsnmp-mib-agent.la

libsnmp_mib_agent_la_SOURCES = \
	activator.c framework-module.h framework-module.c \
	mpd-stats-module.h mpd-stats-module.c \
	usm-stats-module.h usm-stats-module.c \
	usm-users-module.h usm-users-module.c \
	usm-dh-module.h usm-dh-module.c \
	snmpv2-module.h snmpv2-module.c \
	snmp-stats-module.h snmp-stats-module.c \
	notification-module.h notification-module.c \
	target-module.h target-module.c \
	snmp-agent-descriptor.h snmp-agent-descriptor.c \
	ucd-version-module.h ucd-version-module.c \
	vacm-access-module.h vacm-access-module.c \
	vacm-context-module.h vacm-context-module.c \
	vacm-security-group-module.h vacm-security-group-module.c \
	vacm-views-module.h vacm-views-module.c
libsnmp_mib_agent_la_CFLAGS= \
	-fPIC -fvisibility=hidden
libsnmp_mib_agent_la_LDFLAGS = \
	-no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/snmp-core \
	-I$(top_srcdir)/src/snmp-agent \
	-I$(top_srcdir)/src/snmp-mib

endif
