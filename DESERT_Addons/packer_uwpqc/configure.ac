#
# Copyright (c) 2024 Regents of the SIGNET lab, University of Padova.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University of Padova (SIGNET lab) nor the 
#    names of its contributors may be used to endorse or promote products 
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

AC_INIT(packeruwpqc, 1.0.0)
AM_INIT_AUTOMAKE
AM_PROG_AR

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_PROG_MAKE_SET

AC_DISABLE_STATIC
 
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

AC_PATH_NS_ALLINONE

AC_ARG_WITH_NSMIRACLE

AC_CHECK_NSMIRACLE([have_nsmiracle=yes],[have_nsmiracle=no])
if test x$have_nsmiracle != xyes ; then
  AC_MSG_ERROR([Could not find nsmiracle, is --with-nsmiracle set correctly?])
fi  

AC_ARG_WITH_DESERT
AC_ARG_WITH_DESERT_BUILD

AC_CHECK_DESERT([have_desert=yes],[have_desert=no])
if test x$have_desert != xyes ; then
  AC_MSG_ERROR([Could not find desert, is --with-desert set correctly?])
fi  


# Check for liboqs library (optional but recommended for PQC support)
AC_ARG_WITH([oqs],
  AS_HELP_STRING([--with-oqs=PATH], [path to liboqs installation]),
  [OQS_PATH=$withval; OQS_CPPFLAGS="-I${withval}/include"; OQS_LDFLAGS="-L${withval}/lib"; OQS_LIBADD="-loqs"],
  [OQS_PATH=""; OQS_CPPFLAGS=""; OQS_LDFLAGS=""; OQS_LIBADD="-loqs"]
)

# Try to find liboqs library
AC_CHECK_LIB([oqs], [OQS_KEM_new],
  [have_oqs=yes; AC_DEFINE(HAVE_LIBOQS, 1, [Define if liboqs library is available])],
  [have_oqs=no],
  [$OQS_LDFLAGS]
)

# Substitute variables for Makefile
AC_SUBST(OQS_CPPFLAGS)
AC_SUBST(OQS_LDFLAGS)
AC_SUBST(OQS_LIBADD)

AC_DEFINE(CPP_NAMESPACE,std)

AC_CONFIG_FILES([
		m4/Makefile
		Makefile
      ])

AC_OUTPUT

if test x$have_oqs = xyes ; then
  AC_MSG_NOTICE([Building with liboqs PQC support enabled])
else
  AC_MSG_WARN([liboqs not found - PQC features will be disabled. Install liboqs and use --with-oqs to enable.])
fi
