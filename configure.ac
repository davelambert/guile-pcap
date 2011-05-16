dnl Copyright (C) 2003 David J. Lambert

dnl Process this file with autoconf to produce a configure script.

AC_INIT(guile-pcap.c)
AC_PREREQ(2.53)
AM_INIT_AUTOMAKE(guile-pcap,0.1.0,no-define)
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)


AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_C_CONST

if test "${USE_MAINTAINER_MODE}" = "yes" ; then
    AC_CHECK_PROG(GUILE_FILTER_DOC_SNARFAGE,guile_filter_doc_snarfage,guile_filter_doc_snarfage)
    if test "${GUILE_FILTER_DOC_SNARFAGE}" = no; then
	AC_MSG_ERROR(Unable to find guile_filter_doc_snarfage);
    fi

    AC_CHECK_PROG(GUILE_SNARF_DOCS,guile-snarf-docs,guile-snarf-docs)
    if test "${GUILE_SNARF_DOCS}" = no; then
	AC_MSG_ERROR(Unable to find guile-snarf-docs);
    fi

    CFLAGS="-Wall -g";
    enable_shared='no';
    enable_static='yes';
fi

AM_CONDITIONAL(MAINTAINER_MODE, test "${USE_MAINTAINER_MODE}" = "yes")

AC_CHECK_PROG(GUILE_CONFIG,guile-config,guile-config)
if test "$GUILE_CONFIG" = no; then
	AC_MSG_ERROR(Unable to find guile-config, required for compilation);
fi
GUILE_DIR=`guile-config info pkgdatadir`
AC_SUBST(GUILE_DIR)
GUILE_LINK=`guile-config link`
AC_SUBST(GUILE_LINK)
GUILE_COMPILE=`guile-config compile`
AC_SUBST(GUILE_COMPILE)

AC_CHECK_PROG(GUILE_SNARF,guile-snarf,guile-snarf,no)
if test "$GUILE_SNARF" = no; then
	AC_MSG_ERROR([Unable to find guile-snarf, required for compilation]);
fi


AC_CHECK_LIB(pcap, pcap_open_live,
    [LIBS="$LIBS -lpcap"],
    [AC_MSG_ERROR([Cannot find libpcap, required for compilation])])

AC_CHECK_LIB(guile-srfi-srfi-4-v-1, scm_make_u8vector,,
    [AC_MSG_ERROR([Cannot find guile-srfi-srfi-4-v-1, required for compilation])])


AC_OUTPUT(Makefile)

### Local variables:
### mode: sh
### End:
