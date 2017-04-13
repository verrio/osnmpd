if ENABLE_MIB_POWER

plugin_LTLIBRARIES = libsnmp-mib-power.la

libsnmp_mib_power_la_SOURCES = \
	activator.c battery-module.h battery-module.c \
	ups-module.h ups-ident-module.c ups-battery-module.c ups-input-module.c \
	ups-output-module.c ups-bypass-module.c ups-alarm-module.c \
	ups-test-module.c ups-control-module.c ups-config-module.c \
	power-cache.h power-cache.c
libsnmp_mib_power_la_CFLAGS= \
	-fPIC
libsnmp_mib_power_la_LDFLAGS = \
    -no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
    -I$(top_srcdir)/src/snmp-core \
    -I$(top_srcdir)/src/snmp-agent \
    -I$(top_srcdir)/src/snmp-mib

endif
