AC_INIT([uwpqc_auth], [1.0.0])
AM_INIT_AUTOMAKE([foreign])
AM_PROG_AR
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_DISABLE_STATIC
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

AC_PATH_NS_ALLINONE
AC_ARG_WITH_NSMIRACLE
AC_CHECK_NSMIRACLE([have_nsmiracle=yes], [have_nsmiracle=no])
if test x$have_nsmiracle != xyes; then
  AC_MSG_ERROR([Could not find NS-Miracle])
fi

AC_ARG_WITH_DESERT
AC_ARG_WITH_DESERT_BUILD
AC_CHECK_DESERT([have_desert=yes], [have_desert=no])
if test x$have_desert != xyes; then
  AC_MSG_ERROR([Could not find DESERT])
fi

AC_ARG_WITH([oqs],
  [AS_HELP_STRING([--with-oqs=PREFIX], [liboqs installation prefix])],
  [oqs_prefix="$withval"], [oqs_prefix="/usr/local"])

saved_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS -I$oqs_prefix/include"
AC_CHECK_HEADERS([oqs/oqs.h openssl/kdf.h], [],
  [AC_MSG_ERROR([required liboqs or OpenSSL headers are unavailable])])
CPPFLAGS="$saved_CPPFLAGS"

AC_SUBST([OQS_CPPFLAGS], [-I$oqs_prefix/include])
AC_SUBST([OQS_LDFLAGS], [-L$oqs_prefix/lib])

saved_CPPFLAGS="$CPPFLAGS"
saved_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS -I$oqs_prefix/include"
LIBS="$LIBS -L$oqs_prefix/lib -loqs -lcrypto"
AC_LINK_IFELSE([
  AC_LANG_PROGRAM([[#include <oqs/oqs.h>]],
    [[OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hrss701);
      OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
      OQS_KEM_free(kem); OQS_SIG_free(sig);]])], [],
  [AC_MSG_ERROR([NTRU-HRSS-701 and Falcon-512 liboqs support is required])])
CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"

AC_CONFIG_FILES([Makefile m4/Makefile])
AC_OUTPUT