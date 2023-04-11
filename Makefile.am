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

SUBDIRS = . tests doc

ACLOCAL_AMFLAGS = -I m4

AM_LDFLAGS = -no-undefined -avoid-version -module

dist_config_DATA = time_limits.conf

pamdir = @pamdir@

pam_LTLIBRARIES = pam_session_timelimit.la

pam_session_timelimit_la_SOURCES = pam_session_timelimit.c \
                                   time-util.c \
                                   time-util.h
pam_session_timelimit_la_LIBADD = -lpam
