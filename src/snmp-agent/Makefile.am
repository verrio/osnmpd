noinst_LIBRARIES = libsnmp-agent.a

libsnmp_agent_a_SOURCES = \
	agent-cache.c agent-cache.h agent-config.c agent-config.h agent-ctl.c \
	agent-ctl.h agent-incoming.c agent-incoming.h agent-notification-builder.c \
	agent-notification-builder.h agent-notification.c agent-notification.h \
	mib-tree.c mib-tree.h snmpd.c snmpd.h

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-mib

