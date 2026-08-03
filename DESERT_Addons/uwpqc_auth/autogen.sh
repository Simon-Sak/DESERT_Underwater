#!/bin/sh
set -eu
aclocal -I m4 --force
libtoolize --force
automake --foreign --add-missing
autoconf