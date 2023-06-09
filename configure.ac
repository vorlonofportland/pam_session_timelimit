#
# Copyright (c) 2023 Steve Langasek <vorlon@dodds.net>
#
# pam_session_timelimit is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# pam_session_timelimit is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.63)

AC_INIT([pam_session_timelimit], [0.1],
        [https://github.com/vorlonofportland/pam_session_timelimit/issues])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([foreign])

LT_INIT([disable-static])
AC_ENABLE_STATIC([no])
AC_ENABLE_SHARED([yes])

AC_SYS_LARGEFILE
if [[ "$ac_cv_sys_file_offset_bits" = yes ]]; then
    AC_DEFINE([_TIME_BITS], [64],
              [Number of bits in a timestamp, on hosts where this is settable.])
fi

AC_ARG_WITH(
        [pam-dir],
        AS_HELP_STRING([--with-pam-dir],
                       [Directory where to install the module (defaults to ${libdir}/security]),
        [pamdir=$withval], [pamdir="${libdir}/security"])

AC_SUBST(pamdir)

AC_ARG_WITH(
	[config-dir],
	AS_HELP_STRING([--with-config-dir],
	               [Directory to use for the config file (defaults to ${sysconfdirdir}/security)]),
	[configdir=$withval], [configdir="${sysconfdir}/security"])

AC_SUBST(configdir)

AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([XMLLINT], [xmllint],[/bin/true])

AC_DEFINE_UNQUOTED(CONFIGDIR, "$configdir",
                   [Define to the directory used for the config file])
AC_DEFINE_UNQUOTED(LOCALSTATEDIR, "$localstatedir",
                   [Define to the directory used for the config file])

AC_CONFIG_FILES([Makefile tests/Makefile doc/Makefile])

AC_OUTPUT
