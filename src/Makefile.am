SUBDIRS = snmp-mib

bin_PROGRAMS = snmpd

snmpd_SOURCES = \
	snmp-core/snmp-core.h snmp-core/snmp-types.c \
	snmp-core/snmp-types.h snmp-core/snmp-crypto.c \
	snmp-core/snmp-crypto.h snmp-core/snmp-pdu.c \
	snmp-core/snmp-pdu.h snmp-core/snmp-date-time.h \
	snmp-core/snmp-date-time.c snmp-core/tinyber.c \
	snmp-core/tinyber.h snmp-core/utils.c snmp-core/utils.h \
	snmp-agent/agent-cache.c snmp-agent/agent-cache.h \
	snmp-agent/agent-config.c snmp-agent/agent-config.h \
	snmp-agent/agent-ctl.c snmp-agent/agent-ctl.h \
	snmp-agent/agent-incoming.c snmp-agent/agent-incoming.h \
	snmp-agent/agent-notification-builder.c \
	snmp-agent/agent-notification-builder.h \
	snmp-agent/agent-notification-log.c snmp-agent/agent-notification-log.h \
	snmp-agent/agent-notification.c snmp-agent/agent-notification.h \
	snmp-agent/mib-tree.c snmp-agent/mib-tree.h \
	snmp-agent/snmpd.c snmp-agent/snmpd.h \
	snmp-mib/single-level-module.c snmp-mib/single-level-module.h \
	snmp-mib/single-table-module.c snmp-mib/single-table-module.h \
	snmp-mib/mib-utils.h snmp-mib/mib-utils.c
snmpd_CFLAGS= \
        -fPIC -fvisibility=hidden
snmpd_LDADD = \
	-lrt -lz -lcrypto
#ifdef LINUX
snmpd_LDADD += -ldl
#endif
snmpd_LDFLAGS = \
	-fvisibility=hidden \
	-Wl,-export-dynamic \
	-Wl,--gc-sections

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/snmp-core \
	-I$(top_srcdir)/src/snmp-agent \
	-I$(top_srcdir)/src/snmp-mib

install-exec-hook:
	find $(DESTDIR)$(plugindir) -type f -name \*.la -delete
