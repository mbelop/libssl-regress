

CFLAGS+=	-I${.CURDIR}/
LDFLAGS= 	-L${.CURDIR}/../libssl -lssl

REGRESS_TARGETS=	test_aes	\
			test_arc4	\
			test_base64	\
			test_bignum	\
			test_des	\
			test_md5	\
			test_rsa	\
			test_sha1	\
			test_sha2	\
			test_sha4	\
			test_x509parse

.include <bsd.regress.mk>
