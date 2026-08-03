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

AC_ARG_WITH([ns-bin],
  [AS_HELP_STRING([--with-ns-bin=PATH], [DESERT ns executable for ABI detection])],
  [ns_bin="$withval"], [ns_bin=""])
if test -z "$ns_bin" && test -x "$oqs_prefix/bin/ns"; then
  ns_bin="$oqs_prefix/bin/ns"
fi
if test -z "$ns_bin"; then
  AC_MSG_ERROR([could not locate the DESERT ns runtime; use --with-ns-bin=PATH])
fi
if test ! -x "$ns_bin"; then
  AC_MSG_ERROR([DESERT ns runtime is not executable: $ns_bin])
fi

AC_MSG_CHECKING([DESERT ns scheduler UID width])
cat > conftest-uwpqc-auth-abi.tcl <<'EOF'
puts @<:@ns-hasint64@:>@
EOF
ns_lib_dir=`dirname "$ns_bin"`/../lib
ns_has_int64=`LD_LIBRARY_PATH="$ns_lib_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$ns_bin" conftest-uwpqc-auth-abi.tcl 2>/dev/null | sed -n '1p'`
rm -f conftest-uwpqc-auth-abi.tcl
case "$ns_has_int64" in
  0|1) AC_MSG_RESULT([$ns_has_int64]) ;;
  *) AC_MSG_ERROR([could not query ns-hasint64 from $ns_bin]) ;;
esac
AC_SUBST([UWPQC_AUTH_NS_HAS_INT64], [$ns_has_int64])

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
    [[OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
      OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
      OQS_KEM_free(kem); OQS_SIG_free(sig);]])], [],
  [AC_MSG_ERROR([NTRU-HPS-2048-509 and Falcon-512 liboqs support is required])])
CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"

AC_CONFIG_FILES([Makefile m4/Makefile uwpqc-auth-build-config.h])
AC_OUTPUT