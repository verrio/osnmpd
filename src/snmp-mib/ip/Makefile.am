if ENABLE_MIB_IP

plugin_LTLIBRARIES = libsnmp-mib-ip.la

libsnmp_mib_ip_la_SOURCES = \
	activator.c ip-cache.h ip-cache.c \
	ip-module.h ip-module.c \
	icmp-module.h icmp-module.c \
	tcp-module.h tcp-module.c \
	udp-module.h udp-module.c \
	ip-address-cache.h ip-address-cache.c \
	ip-traffic-stats.h ip-traffic-stats.c \
	if-module.h if-module.c \
	ifx-module.h ifx-module.c \
	if-inverted-module.h if-inverted-module.c \
	if-cache.h if-cache.c \
	socket-cache.h socket-cache.c
libsnmp_mib_ip_la_CFLAGS= \
	-fPIC
libsnmp_mib_ip_la_LDFLAGS = \
        -no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-agent \
        -I$(top_srcdir)/src/snmp-mib

endif
