if ENABLE_MIB_SYSTEM

plugin_LTLIBRARIES = libsnmp-mib-system.la

libsnmp_mib_system_la_SOURCES = \
	activator.c system-module.h system-module.c \
	hr-system-module.h hr-system-module.c \
	hr-device-module.h hr-device-module.c \
	hr-storage-module.h hr-storage-module.c \
	hr-sw-run-module.h hr-sw-run-module.c \
	hr-sw-perf-module.h hr-sw-perf-module.c \
	hr-sw-installed-module.h hr-sw-installed-module.c \
	ucd-module.h ucd-memory-module.c ucd-load-module.c ucd-vmstat-module.c \
	application-module.h application-module.c \
	cpu-cache.h cpu-cache.c \
	device-cache.h device-cache.c \
	proc-cache.h proc-cache.c \
	mem-cache.h mem-cache.c \
	storage-cache.h storage-cache.c
libsnmp_mib_system_la_CFLAGS= \
	-fPIC
libsnmp_mib_system_la_LDFLAGS = \
    -no-undefined -avoid-version -shared -fPIC

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core \
        -I$(top_srcdir)/src/snmp-agent \
        -I$(top_srcdir)/src/snmp-mib

endif
