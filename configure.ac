AC_INIT([brutelock], [1.1.2], [info@intuitivereason.com])
AM_INIT_AUTOMAKE(brutelock, 1.1.2, [foreign])
AC_PROG_CC

AC_PREFIX_DEFAULT(/usr/local/brutelock)

AC_MSG_CHECKING(for xml2-config);
xmlconfig=`which xml2-config`;
if test $xmlconfig; then
    AC_MSG_RESULT(yes);
    flags=`${xmlconfig} --cflags`;
    CFLAGS="${CFLAGS} ${flags}";
    flags=`${xmlconfig} --libs`;
    LDFLAGS="${LDFLAGS} ${flags}";
else
    AC_MSG_RESULT(no);
    AC_WARN(xml2-config not found); 
fi;

AC_MSG_CHECKING(for curl-config);
curlconfig=`which curl-config`;
if test $curlconfig; then
    AC_MSG_RESULT(yes);
    flags=`${curlconfig} --cflags`;
    CFLAGS="${CFLAGS} ${flags}";
    flags=`${curlconfig} --libs`;
    LDFLAGS="${LDFLAGS} ${flags}";
else
    AC_MSG_RESULT(no);
    AC_WARN(curl-config not found); 
fi;

AC_ARG_ENABLE(
    debug,
    [  --enable-debug          Turns on debugging support],
    debug=yes
)
if test $debug ; then
    AC_MSG_NOTICE(debug support enabled);
    CFLAGS="$CFLAGS -DDEBUG"
fi

AM_CONDITIONAL([LOGROTATE], [test -d /etc/logrotate.d])

AC_CONFIG_FILES([
    Makefile
])
AC_OUTPUT

