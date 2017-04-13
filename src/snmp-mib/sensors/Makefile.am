if ENABLE_MIB_SENSORS

plugin_LTLIBRARIES = libsnmp-mib-sensors.la

libsnmp_mib_sensors_la_SOURCES = \
	activator.c entity-sensors-module.h entity-sensors-module.c \
	sensor-cache.h sensor-cache.c
libsnmp_mib_sensors_la_CFLAGS= \
	-fPIC
libsnmp_mib_sensors_la_LDFLAGS = \
    -no-undefined -avoid-version -shared -fPIC -lsensors

AM_CPPFLAGS = \
    -I$(top_srcdir)/src/snmp-core \
    -I$(top_srcdir)/src/snmp-agent \
    -I$(top_srcdir)/src/snmp-mib

endif
