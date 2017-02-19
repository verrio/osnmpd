if ENABLE_MIB_IP

plugin_LTLIBRARIES = libsnmp-mib-ip.la

libsnmp_mib_ip_la_SOURCES = \
	activator.c ip-cache.h ip-cache.c \
	icmp-module.h icmp-module.c
libsnmp_mib_ip_la_CFLAGS= \
	-fPIC
libsnmp_mib_ip_la_LDFLAGS = \
        -no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-agent \
        -I$(top_srcdir)/src/snmp-mib

endif
