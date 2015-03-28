#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/engine.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "e_af_alg.h"
#include "digests.h"

int af_alg_DIGEST_init(EVP_MD_CTX *ctx, struct sockaddr_alg *sa)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);

	if( (ddata->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1 )
		return 0;

	if( bind(ddata->tfmfd, (struct sockaddr *)sa, sizeof(struct sockaddr_alg)) != 0 )
	{
		TRACE("bind");
		return 0;
	}

	if( (ddata->opfd = accept(ddata->tfmfd,NULL,0)) == -1 )
	{
		TRACE("accept");
		return 0;
	}

	return 1;
}

int af_alg_DIGEST_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r;
	r = send(ddata->opfd, data, length, MSG_MORE);
	if( r < 0 || (size_t)r < length )
		return 0;
	return 1;
}

int af_alg_DIGEST_final(EVP_MD_CTX *ctx, unsigned char *md, int len)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( read(ddata->opfd, md, len) != len )
		return 0;

	return 1;
}

int af_alg_DIGEST_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from)
{
	struct af_alg_digest_data *from = DIGEST_DATA(_from);
	struct af_alg_digest_data *to = DIGEST_DATA(_to);
	if( from == NULL || to == NULL )
		return 1;
	if( (to->opfd = accept(from->opfd, NULL, 0)) == -1 )
		return 0;
	if( (to->tfmfd = accept(from->tfmfd, NULL, 0)) == -1 )
		return 0;
	return 1;
}

int af_alg_DIGEST_cleanup(EVP_MD_CTX *ctx)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( ddata->opfd != -1 )
		close(ddata->opfd);
	if( ddata->tfmfd != -1 )
		close(ddata->tfmfd);
	return 0;
}

int af_alg_list_digests(ENGINE *e __U__, const EVP_MD **digest, const int **nids, int nid)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	if( !digest )
	{
		*nids = digests_used.data;
		return digests_used.len;
	}

	if( NID_store_contains(&digests_used, nid) == false )
		return 0;

	switch( nid )
	{
#define CASE(name)\
case NID_##name:\
	*digest = &af_alg_##name##_md;\
	break;

	CASE(md4)
	CASE(md5)
	CASE(sha1)
	CASE(sha224)
	CASE(sha256)
	CASE(sha512)
#undef CASE

	default:
		*digest = NULL;
	}
	TRACE("digest %p\n", *digest);
	return (*digest != NULL);
}

/**
 * MD4 & MD5
 */
DECLARE_DIGEST(md4, MD4)
DECLARE_MD(md4, MD4, MD4)

DECLARE_DIGEST(md5, MD5)
DECLARE_MD(md5, MD5, MD5)

/**
 * SHA
 */
DECLARE_DIGEST(sha1, SHA)
DECLARE_MD(sha1, SHA, SHA)

DECLARE_DIGEST(sha224, SHA224)
DECLARE_MD(sha224, SHA224, SHA)

DECLARE_DIGEST(sha256, SHA256)
DECLARE_MD(sha256, SHA256, SHA256)

DECLARE_DIGEST(sha512, SHA512)
DECLARE_MD(sha512, SHA512, SHA512)



