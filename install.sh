#!/bin/bash
set -e

BUILD_DIR="/tmp/blake3-install"
EXT_DIR="/usr/lib/php/20250925"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -r . "$BUILD_DIR/"
cd "$BUILD_DIR"

phpize --clean
phpize
./configure --enable-blake3=shared --with-php-config=/usr/bin/php-config

make clean
make EXTRA_CFLAGS="-DCOMPILE_DL_BLAKE3" blake3.lo c/blake3.lo c/blake3_dispatch.lo c/blake3_portable.lo \
     c/blake3_sse2_x86-64_unix.lo c/blake3_sse41_x86-64_unix.lo \
     c/blake3_avx2_x86-64_unix.lo c/blake3_avx512_x86-64_unix.lo

cc -shared -o modules/blake3.so \
  .libs/blake3.o \
  c/.libs/blake3.o \
  c/.libs/blake3_dispatch.o \
  c/.libs/blake3_portable.o \
  c/.libs/blake3_sse2_x86-64_unix.o \
  c/.libs/blake3_sse41_x86-64_unix.o \
  c/.libs/blake3_avx2_x86-64_unix.o \
  c/.libs/blake3_avx512_x86-64_unix.o

sudo cp modules/blake3.so "$EXT_DIR/"
echo "extension=blake3.so" | sudo tee /etc/php/8.5/mods-available/blake3.ini
sudo phpenmod blake3

php -r "exit(extension_loaded('blake3') ? 0 : 1);" && echo "✓ Installazione completata" || echo "✗ Installazione fallita"
