PHP_ARG_ENABLE([blake3],
  [whether to enable blake3 support],
  [AS_HELP_STRING([--enable-blake3],
    [Enable blake3 support])])

if test "$PHP_BLAKE3" != "no"; then
  AC_DEFINE(HAVE_BLAKE3, 1, [Have BLAKE3 support])

  AC_CHECK_FUNCS([explicit_bzero])
  if test "$ac_cv_func_explicit_bzero" != "yes"; then
    AC_CHECK_FUNCS([memset_s])
  fi

  PHP_NEW_EXTENSION(blake3, \
    blake3.c \
    c/blake3.c \
    c/blake3_dispatch.c \
    c/blake3_portable.c \
    c/blake3_sse2_x86-64_unix.S \
    c/blake3_sse41_x86-64_unix.S \
    c/blake3_avx2_x86-64_unix.S \
    c/blake3_avx512_x86-64_unix.S, \
    $ext_shared, \
    -I@ext_srcdir@/c -I@ext_builddir@/c)
fi
