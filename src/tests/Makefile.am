noinst_PROGRAMS = pdu-tests

pdu_tests_SOURCES = pdu-tests.c

pdu_tests_LDADD = \
	$(top_builddir)/src/snmp-core/libsnmp.a \
	$(OPENSSL_LIB)

AM_CPPFLAGS = \
        -I$(top_srcdir)/src/snmp-core

