AM_CXXFLAGS = -Wall -Wextra -Werror -std=c++17

lib_LTLIBRARIES = libuwpqc_auth.la

libuwpqc_auth_la_SOURCES = \
    initlib.cpp \
    uwpqc-auth-defaults.tcl \
    uwpqc-auth-crypto.cpp \
    uwpqc-auth-module.cpp

libuwpqc_auth_la_CPPFLAGS = @NS_CPPFLAGS@ @NSMIRACLE_CPPFLAGS@ @DESERT_CPPFLAGS@ @OQS_CPPFLAGS@
libuwpqc_auth_la_LDFLAGS = @NS_LDFLAGS@ @NSMIRACLE_LDFLAGS@ @DESERT_LDFLAGS@ @DESERT_LDFLAGS_BUILD@ @OQS_LDFLAGS@
libuwpqc_auth_la_LIBADD = @NS_LIBADD@ @NSMIRACLE_LIBADD@ @DESERT_LIBADD@ -luwip -luwudp -loqs -lcrypto

nodist_libuwpqc_auth_la_SOURCES = InitTcl.cc
BUILT_SOURCES = InitTcl.cc uwpqc-auth-build-config.h
CLEANFILES = InitTcl.cc uwpqc-auth-build-config.h
TCL_FILES = uwpqc-auth-defaults.tcl

InitTcl.cc: Makefile $(TCL_FILES)
	cat $(srcdir)/$(TCL_FILES) | @TCL2CPP@ UwpqcauthInitTclCode > InitTcl.cc

EXTRA_DIST = $(TCL_FILES) uwpqc-auth-build-config.h.in samples/test_uwpqc_ntru_falcon_handshake.tcl