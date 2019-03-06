dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(trace, for trace support,
[  --enable-trace            Build php-trace], no, no)

if test "$PHP_TRACE" != "no"; then
  PHP_TRACE_CFLAGS="-D_GNU_SOURCE"
  PHP_TRACE_FILES="php_trace.c"
  
  PHP_SUBST(PHP_TRACE_CFLAGS)
  PHP_SUBST(PHP_TRACE_FILES)
  PHP_SUBST(TRACE_EXTRA_LIBS)
  
  PHP_ADD_MAKEFILE_FRAGMENT([$abs_srcdir/sapi/trace/Makefile.frag], [$abs_srcdir/sapi/trace], [$abs_builddir/sapi/trace])
  PHP_SELECT_SAPI(trace, program, $PHP_TRACE_FILES, $PHP_TRACE_CFLAGS, [$(SAPI_TRACE_PATH)])

  BUILD_TRACE_BINARY="sapi/trace/php-trace"
  BUILD_TRACE_BIN="\$(LIBTOOL) --mode=link \
        \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(PHP_RPATHS) \
                \$(PHP_GLOBAL_OBJS) \
                \$(PHP_BINARY_OBJS) \
                \$(PHP_TRACE_OBJS) \
                \$(EXTRA_LIBS) \
                \$(TRACE_EXTRA_LIBS) \
                \$(ZEND_EXTRA_LIBS) \
         -o \$(BUILD_TRACE_BINARY)"

  PHP_SUBST(BUILD_TRACE_BINARY)
  PHP_SUBST(BUILD_TRACE_BIN)
fi

dnl ## Local Variables:
dnl ## tab-width: 4
dnl ## End:
