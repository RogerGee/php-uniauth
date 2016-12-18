PHP_ARG_ENABLE(uniauth,[Whether to enable the "uniauth" extension],
    [  --enable-uniauth          Enable "uniauth extension support])

if test $PHP_UNIAUTH != "no"; then
    PHP_SUBST(UNIAUTH_SHARED_LIBADD)
    PHP_NEW_EXTENSION(uniauth,uniauth.c,$ext_shared)
fi
