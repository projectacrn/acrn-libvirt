dnl The acrn driver

AC_DEFUN([LIBVIRT_DRIVER_ARG_ACRN],[
    LIBVIRT_ARG_WITH_FEATURE([ACRN], [Acrn], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_ACRN],[
    if test "$with_acrn" != "no" ; then
        AC_PATH_PROG([ACRNDM], [acrn-dm], [], [$PATH:/usr/bin])
        AC_PATH_PROG([ACRNCTL], [acrnctl], [], [$PATH:/usr/bin])

        if test -z "$ACRNDM" || test -z "$ACRNCTL"; then
            if test "$with_acrn" = "check"; then
                with_acrn="no"
            else
                AC_MSG_ERROR([The acrn driver cannot be enabled])
            fi
        else
            with_acrn="yes"
        fi
    fi

    if test "$with_acrn" = "yes"; then
        AC_DEFINE_UNQUOTED([WITH_ACRN], 1, [whether acrn driver is enabled])
        AC_DEFINE_UNQUOTED([ACRNDM], ["$ACRNDM"],
                           [Location of the acrn-dm tool])
        AC_DEFINE_UNQUOTED([ACRNCTL], ["$ACRNCTL"],
                           [Location of the acrnctl tool])
    fi
    AM_CONDITIONAL([WITH_ACRN], [test "$with_acrn" = "yes"])
])

dnl Build with gnulib's getopt which contains a reentrant interface
AC_DEFUN([gl_REPLACE_GETOPT_ALWAYS], [])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_ACRN],[
    LIBVIRT_RESULT([Acrn], [$with_acrn])
])
