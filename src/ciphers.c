#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/aes.h>
#include <openssl/engine.h>

#include "e_af_alg.h"
#include "ciphers.h"
#include "aes.h"
#include "des.h"

int af_alg_CIPHER_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa, const unsigned char *key, const unsigned char *iv __U__, int enc __U__)
{
	TRACE("%s %p\n", __PRETTY_FUNCTION__, ctx);
	int keylen = EVP_CIPHER_CTX_key_length(ctx);
	struct af_alg_cipher_data *acd = CIPHER_DATA(ctx);

	acd->op = -1;

	if( ctx->encrypt )
		acd->type = ALG_OP_ENCRYPT;
	else
		acd->type = ALG_OP_DECRYPT;

	if((acd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
	{
		TRACE("socket");
		return 0;
	}

	if( bind(acd->tfmfd, (struct sockaddr *)sa, sizeof(struct sockaddr_alg)) == -1 )
	{
		TRACE("bind");
		return 0;
	}

	if (setsockopt(acd->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1)
	{
		TRACE("setsockopt");
		return 0;
	}

	return 1;
}

int af_alg_CIPHER_cleanup_key(EVP_CIPHER_CTX *ctx)
{
	TRACE("%s %p\n", __PRETTY_FUNCTION__, ctx);
	struct af_alg_cipher_data *acd = CIPHER_DATA(ctx);
	if( acd->tfmfd != -1 )
		close(acd->tfmfd);
	if( acd->op != -1 )
		close(acd->op);
	return 1;
}


int af_alg_CIPHER_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	TRACE("%s %p\n", __PRETTY_FUNCTION__, ctx);
	struct af_alg_cipher_data *acd = CIPHER_DATA(ctx);
	int block_size = EVP_CIPHER_CTX_block_size(ctx);
	struct msghdr msg = {.msg_name = NULL};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(acd->type)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + block_size)];
	ssize_t len;
	unsigned char save_iv[block_size];

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = 0;
	msg.msg_controllen = sizeof(buf);
	if( acd->op == -1 )
	{
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1)
			return 0;
	}
	/* set operation type encrypt|decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);

	/* set IV - or update if it was set before */
	if(!ctx->encrypt)
		memcpy(save_iv, in_arg + nbytes - block_size, block_size);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + block_size);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = block_size;
	memcpy(ivm->iv, ctx->iv, block_size);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned int todo = nbytes;
	unsigned int done = 0;
	while( todo-done > 0 )
	{
		iov.iov_base = (void *)(in_arg + done);
		iov.iov_len = todo-done;

		if((len = sendmsg(acd->op, &msg, 0)) == -1)
			return 0;

		if (read(acd->op, out_arg+done, len) != len)
			return 0;

		/* do not update IV for following chunks */
		msg.msg_controllen = 0;
		done += len;
	}

	/* copy IV for next iteration */
	if(ctx->encrypt)
		memcpy(ctx->iv, out_arg + done - block_size, block_size);
	else
		memcpy(ctx->iv, save_iv, block_size);
	return 1;
}

int af_alg_list_ciphers(ENGINE *e __U__, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	if( !cipher )
	{
		*nids = ciphers_used.data;
		return ciphers_used.len;
	}

	if( NID_store_contains(&ciphers_used, nid) == false )
		return 0;

	switch( nid )
	{
#define CASE(name)\
case NID_##name:\
	*cipher = &af_alg_##name;\
	break;
	CASE(aes_128_cbc);
	CASE(aes_192_cbc);
	CASE(aes_256_cbc);
	CASE(des_cbc);
	CASE(des_ede3_cbc);
#undef CASE
	default:
		*cipher = NULL;
	}
	TRACE("cipher %p\n", *cipher);
	return(*cipher != 0);
}

/**
 * DES
 */
DECLARE_CIPHER(des, cbc(des))
DECLARE_DES_EVP(des, 8)

DECLARE_CIPHER(des_ede3, cbc(des3_ede))
DECLARE_DES_EVP(des_ede3, 24)

/**
 * AES
 */
DECLARE_CIPHER(aes, cbc(aes))
#define EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE
DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(256,cbc,CBC);
#undef EVP_CIPHER_block_size_CBC

