noinst_PROGRAMS = pdu-tests event-tests

pdu_tests_SOURCES = pdu-tests.c \
        ../snmp-core/snmp-core.h ../snmp-core/snmp-types.c \
        ../snmp-core/snmp-types.h ../snmp-core/snmp-crypto.c \
        ../snmp-core/snmp-crypto.h ../snmp-core/snmp-pdu.c \
        ../snmp-core/snmp-pdu.h ../snmp-core/snmp-date-time.h \
        ../snmp-core/snmp-date-time.c ../snmp-core/tinyber.c \
        ../snmp-core/tinyber.h ../snmp-core/utils.c ../snmp-core/utils.h

pdu_tests_LDADD = $(OPENSSL_LIB)
	
event_tests_SOURCES = event-tests.c \
	../snmp-agent/agent-notification-builder.h ../snmp-core/tinyber.c \
        ../snmp-core/tinyber.h ../snmp-core/utils.c ../snmp-core/utils.h

event_tests_LDADD = -lrt
	
AM_CPPFLAGS = -I$(top_srcdir)/src/snmp-core
