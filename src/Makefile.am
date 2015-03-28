plugin_LTLIBRARIES = libaf_alg.la

libaf_alg_la_SOURCES = aes.h \
	ciphers.c \
	des.h \
	digests.c \
	digests.h \
	e_af_alg.c \
	e_af_alg.h

libaf_alg_la_CFLAGS = $(OPENSSL_CFLAGS)
libaf_alg_la_LIBADD = $(OPENSSL_LIBS)
libaf_alg_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS)
libaf_alg_la_LIBTOOLFLAGS = --tag=disable-static

noinst_HEADERS = aes.h \
	ciphers.h \
	des.h \
	digests.h \
	e_af_alg.h
