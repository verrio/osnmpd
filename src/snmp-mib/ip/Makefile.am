if ENABLE_MIB_IP

plugin_LTLIBRARIES = libsnmp-mib-ip.la

libsnmp_mib_ip_la_SOURCES = \
	activator.c ip-cache.h ip-cache.c \
	ip-traps.h ip-traps.c ip-module.h ip-module.c \
	icmp-module.h icmp-module.c tcp-module.h tcp-module.c \
	udp-module.h udp-module.c sctp-module.h sctp-assoc-local-module.c \
	sctp-assoc-module.c sctp-assoc-remote-module.c \
	sctp-hostname-module.c sctp-local-port-module.c \
	sctp-params-module.c sctp-remote-ip-module.c \
	sctp-remote-port-module.c sctp-remote-prim-ip-module.c \
	sctp-stats-module.c ip-address-cache.h ip-address-cache.c \
	ip-traffic-stats.h ip-traffic-stats.c \
	if-module.h if-module.c ifx-module.h ifx-module.c \
	if-inverted-module.h if-inverted-module.c \
	if-cache.h if-cache.c socket-cache.h socket-cache.c
libsnmp_mib_ip_la_CFLAGS= \
	-fPIC -fvisibility=hidden
libsnmp_mib_ip_la_LDFLAGS = \
	-no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/snmp-core \
	-I$(top_srcdir)/src/snmp-agent \
	-I$(top_srcdir)/src/snmp-mib

endif
