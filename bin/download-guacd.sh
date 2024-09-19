#!/bin/sh -e
#
# Copyright (C) 2015 Glyptodon LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

##
## @fn download-guacd.sh
##
## Downloads and builds the given version of guacamole-server, automatically
## creating any required symbolic links for the proper loading of FreeRDP
## plugins.
##
## @param VERSION
##     The version of guacamole-server to download, such as "0.9.6".
##

VERSION="$1"
BUILD_DIR="/tmp"

##
## Locates the directory in which the FreeRDP libraries (.so files) are
## located, printing the result to STDOUT.
##
#where_is_freerdp() {
#    dirname `rpm -ql freerdp-devel | grep 'libfreerdp.*\.so' | head -n1`
#}

#
# Download latest guacamole-server
#

curl -L "http://sourceforge.net/projects/guacamole/files/current/source/guacamole-server-$VERSION.tar.gz" | tar -xz -C "$BUILD_DIR"

# В этих 2х файлах на С были ошибки из-за обновления версий, пришлось их переписать на вызов актуальных функций
# Тут мы меняем нерабочие на актуальные файлы
cp tmp/guac_ssh_key.c tmp/guacamole-server-0.9.9/src/common-ssh/guac_ssh_key.c
cp tmp/ssh_client.c tmp/guacamole-server-0.9.9/src/protocols/ssh/ssh_client.c

#
# Build guacamole-server
#

cd "$BUILD_DIR/guacamole-server-$VERSION"
./configure
make
make install
ldconfig

#
# Clean up after build
#

rm -Rf "$BUILD_DIR/guacamole-server-$VERSION"

