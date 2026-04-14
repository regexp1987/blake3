#!/bin/bash
# build.sh — Build script for PHP BLAKE3 extension
# Usage: ./build.sh [clean]
set -e

EXT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$EXT_DIR"

case "${1:-}" in
  clean)
    echo "Cleaning build artifacts..."
    rm -rf autom4te.cache configure aclocal.m4 config.h.in config.h config.status \
           config.log Makefile Makefile.* *.lo *.la .libs modules/*.so libs \
           c/*.lo c/*.o c/.libs *.dep c/*.dep *.o 2>/dev/null || true
    echo "Clean complete."
    exit 0
    ;;
esac

echo "=== PHP BLAKE3 Extension v2.0.0 — Build ==="
echo ""

# Step 1: phpize
echo ">> phpize"
phpize 2>&1 | tail -2

# Step 2: configure (detects explicit_bzero, memset_s)
echo ">> configure"
./configure --enable-blake3 >/dev/null 2>&1

# Step 3: Fix PHP 8.4+ Makefile bug
if ! grep -q "include.*Makefile.objects" Makefile 2>/dev/null; then
  echo 'include $(top_srcdir)/Makefile.objects' >> Makefile
fi

# Step 4: Compile
echo ">> compile"
make -j$(nproc) 2>&1 | grep -E "error:|warning:" | grep -v "overriding\|ignoring" || true

# Step 5: Manual build if make didn't produce .so
if [ ! -f "modules/blake3.so" ]; then
  echo ">> manual build"
  cc -I. -I$(pwd) -I$(pwd)/c $(php-config --includes) \
     -DHAVE_CONFIG_H -DCOMPILE_DL_BLAKE3 -O2 -fPIC -c blake3.c -o blake3.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3.c -o c/blake3.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_dispatch.c -o c/blake3_dispatch.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_portable.c -o c/blake3_portable.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_sse2_x86-64_unix.S -o c/blake3_sse2_x86-64_unix.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_sse41_x86-64_unix.S -o c/blake3_sse41_x86-64_unix.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_avx2_x86-64_unix.S -o c/blake3_avx2_x86-64_unix.o 2>/dev/null
  cc -I$(pwd)/c -DHAVE_CONFIG_H -O2 -fPIC -c c/blake3_avx512_x86-64_unix.S -o c/blake3_avx512_x86-64_unix.o 2>/dev/null
  cc -shared -o modules/blake3.so blake3.o c/*.o
fi

# Step 6: Verify
SO="modules/blake3.so"
if [ -f "$SO" ]; then
  SIZE=$(stat -c%s "$SO" 2>/dev/null || stat -f%z "$SO" 2>/dev/null)
  echo ""
  echo "✅ blake3.so — ${SIZE} bytes"
  echo ""
  echo ">> Quick test:"
  php -d extension="$EXT_DIR/$SO" -r "
    echo '  blake3(\"hello\") = ' . blake3('hello') . PHP_EOL;
    echo '  version = ' . blake3_version() . PHP_EOL;
    echo '  explicit_bzero = ' . (defined('HAVE_EXPLICIT_BZERO') ? 'yes' : 'volatile fallback') . PHP_EOL;
  " 2>&1
else
  echo "❌ Build failed"
  exit 1
fi
