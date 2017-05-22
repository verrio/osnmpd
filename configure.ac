#
# This file is part of the osnmpd project (https://github.com/verrio/osnmpd).
# Copyright (C) 2016 Olivier Verriest
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

m4_define([osnmpd_major_version], [1])
m4_define([osnmpd_minor_version], [0])
m4_define([osnmpd_micro_version], [0])
m4_define([osnmpd_version], [osnmpd_major_version.osnmpd_minor_version.osnmpd_micro_version])
AC_SUBST(VERSION)
AC_REVISION([m4_esyscmd_s([git describe --long --always])])

AC_INIT(osnmpd, [osnmpd_version])
AC_CONFIG_SRCDIR([src/snmp-agent/snmpd.c])
AC_LANG([C])

AC_CONFIG_MACRO_DIR([m4/config])
AC_CONFIG_HEADER([src/config.h])
AC_CANONICAL_HOST

GIT_TAG=$(git rev-parse HEAD 2> /dev/null || echo out-of-tree)
AC_DEFINE_UNQUOTED([GIT_TAG], ["$GIT_TAG"], [git commit tag])
GIT_DATE=$(git show -s --format=%cD HEAD 2> /dev/null || echo unknown)
AC_DEFINE_UNQUOTED([GIT_DATE], ["$GIT_DATE"], [git commit date])

m4_pattern_allow([AM_PROG_AR])
if test -z "$CFLAGS"; then
	CFLAGS="-Os -fomit-frame-pointer -Wall -Wunreachable-code -Wpointer-arith -Werror"
fi
AM_PROG_AR
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_TYPE_SIZE_T

AC_LIB_PREFIX
LT_INIT
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_MSG_CHECKING([whether to build for Microsoft Windows target])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <windows.h>]],
		[[#ifndef WIN32
		  # error WIN32 undefined
		  #endif
		]])],
	[
		AC_MSG_RESULT([yes])
		windows=true
		openssl_lib=eay32
	],
	[
		AC_MSG_RESULT([no])
		openssl_lib=crypto
	]
)
AC_SUBST(OPENSSL_LIB, [-l${openssl_lib}])
AC_CHECK_LIB([config],[config_read_file],[],[AC_MSG_ERROR([libconfig library not found])],[])

AC_MSG_CHECKING([whether serial number is to be used])
AC_ARG_ENABLE(serial-number,
	[  --enable-serial-number  Use serial number instead of interface MAC],
	[enable_serial_number=$enableval],
	[enable_serial_number="no"])
AC_MSG_RESULT(${enable_serial_number})
if test "${enable_serial_number}" = "yes"; then
	AC_DEFINE([SERIAL_NUMBER_SUPPORT], [], [Enable support for serial number])
fi

AC_MSG_CHECKING([whether smartcard support is to be compiled in])
AC_ARG_ENABLE(smartcard,
	[  --enable-smartcard      Enable smartcard engine support],
	[enable_smartcard=$enableval],
	[enable_smartcard="no"])
AC_MSG_RESULT($enable_smartcard)
if test "${enable_smartcard}" = "yes"; then
	AC_DEFINE([WITH_SMARTCARD_SUPPORT], [], [Enable smartcard engine support])
fi

AC_MSG_CHECKING(which admin user to be used)
AC_ARG_WITH(admin-user-name,
	[AS_HELP_STRING([--with-admin-user-name],[Alternative administrator user name])],
	ADMIN_USER_NAME=$withval,
	ADMIN_USER_NAME="admin")
AC_MSG_RESULT(${ADMIN_USER_NAME})
AC_DEFINE_UNQUOTED(ADMIN_USER_NAME, "${ADMIN_USER_NAME}", [Administrator user name])

AC_MSG_CHECKING(the maximum PDU size to be used by the agent)
AC_ARG_WITH(max-pdu-size,
	[AS_HELP_STRING([--with-max-pdu-size],[Alternative maximum transport level PDU size])],
	MAX_PDU_SIZE=$withval,
	MAX_PDU_SIZE=1280)
AC_MSG_RESULT(${MAX_PDU_SIZE})
AC_DEFINE_UNQUOTED(MAX_PDU_SIZE, ${MAX_PDU_SIZE}, [Max PDU size])

AC_MSG_CHECKING(which enterprise number to use)
AC_ARG_WITH(enterprise-number,
	[AS_HELP_STRING([--with-enterprise-number],[Alternative enterprise number])],
	ENTERPRISE_NUMBER=$withval,
	ENTERPRISE_NUMBER=4)
AC_MSG_RESULT(${ENTERPRISE_NUMBER})
AC_DEFINE_UNQUOTED(ENTERPRISE_NUMBER, ${ENTERPRISE_NUMBER}, [Enterprise number])

AC_MSG_CHECKING(which enterprise OID to use)
AC_ARG_WITH(enterprise-oid,
	[  --with-enterprise-oid   Alternative enterprise OID],
	ENTERPRISE_MIB=$withval,
	ENTERPRISE_MIB="1.3.6.1.3.255")
AC_MSG_RESULT(${ENTERPRISE_MIB})
AC_DEFINE_UNQUOTED(ENTERPRISE_MIB, [`echo ${ENTERPRISE_MIB} | tr '.' ','`], [Enterprise MIB subtree])

AC_MSG_CHECKING([whether the agent MIB is to be compiled in])
AC_ARG_WITH(mib-agent,
	[  --with-mib-agent        Include agent MIB module],
	enable_mib_agent=$withval,
	enable_mib_agent=yes)
AC_MSG_RESULT(${enable_mib_agent})
AM_CONDITIONAL([ENABLE_MIB_AGENT], [test "${enable_mib_agent}" = "yes"])

AC_MSG_CHECKING([whether the system MIB is to be compiled in])
AC_ARG_WITH(mib-system,
	[  --with-mib-system       Include system MIB module],
	enable_mib_system=$withval,
	enable_mib_system=yes)
AC_MSG_RESULT(${enable_mib_system})
AM_CONDITIONAL([ENABLE_MIB_SYSTEM], [test "${enable_mib_system}" = "yes"])

AC_MSG_CHECKING([whether the power MIB is to be compiled in])
AC_ARG_WITH(mib-sensors,
	[  --with-mib-power        Include power MIB module],
	enable_mib_power=$withval,
	enable_mib_power=yes)
AC_MSG_RESULT(${enable_mib_power})
AM_CONDITIONAL([ENABLE_MIB_POWER], [test "${enable_mib_power}" = "yes"])

AC_MSG_CHECKING([whether the IP MIB is to be compiled in])
AC_ARG_WITH(mib-ip,
	[  --with-mib-ip           Include IP MIB module],
	enable_mib_ip=$withval,
	enable_mib_ip=yes)
AC_MSG_RESULT(${enable_mib_ip})
AM_CONDITIONAL([ENABLE_MIB_IP], [test "${enable_mib_ip}" = "yes"])

AC_MSG_CHECKING([whether the sensors MIB is to be compiled in])
AC_ARG_WITH(mib-sensors,
	[  --with-mib-sensors      Include sensors MIB module],
	enable_mib_sensors=$withval,
	enable_mib_sensors=yes)
AC_MSG_RESULT(${enable_mib_sensors})
AM_CONDITIONAL([ENABLE_MIB_SENSORS], [test "${enable_mib_sensors}" = "yes"])

if test "${enable_mib_sensors}" = "yes"; then
	AC_CHECK_HEADER([sensors/sensors.h], [], [
		AC_MSG_ERROR([required lm-sensors header not found])
	])
fi

AC_MSG_CHECKING([whether the Java subagent MIB is to be compiled in])
AC_ARG_WITH(java-subagent-oid,
	[AS_HELP_STRING([--with-java-subagent-oid],[Java sub agent OID])],
	[
		enable_mib_java_subagent="yes"
		JAVA_SUB_AGENT_MIB=$withval
	],
	[
		enable_mib_java_subagent="no"
		JAVA_SUB_AGENT_MIB=""
	])
AC_MSG_RESULT(${enable_mib_java_subagent})
AM_CONDITIONAL([ENABLE_MIB_JAVA_SUBAGENT], [test "${enable_mib_java_subagent}" = "yes"])
AC_DEFINE_UNQUOTED(JAVA_SUB_AGENT_MIB,
	[`echo ${JAVA_SUB_AGENT_MIB} | tr '.' ','`], [Java subagent MIB subtree])


AS_AC_EXPAND(PLUGIN_DIR,${libdir}/snmp/plugins)
AC_DEFINE_UNQUOTED(PLUGIN_DIR, "$PLUGIN_DIR", [location of the MIB plugins])
AC_MSG_NOTICE([Using $PLUGIN_DIR as the plugin install location])
plugindir="\$(libdir)/snmp/plugins"
AC_SUBST(plugindir)

AS_AC_EXPAND(CONF_DIR,${sysconfdir}/snmp)
AC_DEFINE_UNQUOTED(CONF_DIR, "$CONF_DIR", [location of the SNMP agent conf files])
confdir="\$(sysconfdir)/snmp"
AC_SUBST(confdir)

AS_AC_EXPAND(RUN_DIR,${localstatedir}/run/snmp)
AC_DEFINE_UNQUOTED(RUN_DIR, "$RUN_DIR", [location of the SNMP agent runtime files])
rundir="\${localstatedir}/run/snmp"
AC_SUBST(rundir)

AS_AC_EXPAND(CACHE_DIR,${localstatedir}/lib/snmp)
AC_DEFINE_UNQUOTED(CACHE_DIR, "$CACHE_DIR", [location of the SNMP agent cache])
cachedir="\${localstatedir}/lib/snmp"
AC_SUBST(cachedir)

AC_DEFINE_UNQUOTED([AGENT_CONF_OPTIONS], ["$ac_configure_args"],
	[configure options specified])

AC_CONFIG_FILES([
	Makefile
	conf/Makefile
	doc/Makefile
	src/Makefile
	src/snmp-core/Makefile
	src/snmp-agent/Makefile
	src/snmp-mib/Makefile
	src/snmp-mib/agent/Makefile
	src/snmp-mib/system/Makefile
	src/snmp-mib/power/Makefile
	src/snmp-mib/sensors/Makefile
	src/snmp-mib/ip/Makefile
	src/snmp-mib/java-subagent/Makefile
	src/tests/Makefile
])
AC_OUTPUT

cat << EOF

  osnmpd has been configured with the following options:
  ----------------------------------------------------------

  install prefix .................. : ${prefix}
  C preprocessor .................. : ${CPP}
  C preprocessor flags ............ : ${CPPFLAGS}
  C compiler ...................... : ${CC}
  C compiler flags ................ : ${CFLAGS} ${VISIBILITY_CFLAGS}
  linker .......................... : ${LD}
  linker flags .................... : ${LDFLAGS}
  extra libraries ................. : ${LIBS}  
  
  enterprise OID .................. : ${ENTERPRISE_MIB}
  enterprise number ............... : ${ENTERPRISE_NUMBER}
  administrator ................... : ${ADMIN_USER_NAME}
  max PDU size .................... : ${MAX_PDU_SIZE}
  smartcard support ............... : ${enable_smartcard}
  serial number support ........... : ${enable_serial_number}
  
  include SNMP agent module ....... : ${enable_mib_agent}
  include system module ........... : ${enable_mib_system}
  include power module ............ : ${enable_mib_power}
  include IP module ............... : ${enable_mib_ip}
  include sensors module .......... : ${enable_mib_sensors}
  include Java subagent module .... : ${enable_mib_java_subagent}

EOF

