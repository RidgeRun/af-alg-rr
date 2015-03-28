/* Written by Markus Koetter (nepenthesdev@gmail.com) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <memory.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdbool.h>

#include "e_af_alg.h"
#include "ciphers.h"
#include "digests.h"


#define DYNAMIC_ENGINE
#define AF_ALG_ENGINE_ID	"af_alg"
#define AF_ALG_ENGINE_NAME	"use AF_ALG for AES crypto"

bool NID_store_contains(struct NID_store *store, int nid)
{
	TRACE("%s %p %i (%s) (%i)\n", __PRETTY_FUNCTION__, store, nid, OBJ_nid2sn(nid), (int)store->len);
	size_t i=0;
	for( i=0;i<store->len;i++ )
	{
		TRACE("%s ...\n", OBJ_nid2sn(store->data[i]));
		if( store->data[i] == nid )
			return true;
	}
	return false;
}

bool NID_store_add(struct NID_store *store, int nid)
{
	TRACE("%s %p %i (%s) (%i)\n", __PRETTY_FUNCTION__, store, nid, OBJ_nid2sn(nid), (int)store->len);
	int *r = malloc((store->len+1) * sizeof(int));
	memcpy(r, store->data, store->len * sizeof(int));
	free(store->data);
	store->data = r;
	store->data[store->len] = nid;
	store->len += 1;
	return true;
}

static int CIPHER_to_nid(const EVP_CIPHER *c)
{
	return EVP_CIPHER_nid(c);
}

static int MD_to_nid(const EVP_MD *d)
{
	return EVP_MD_type(d);
}

static bool NID_store_from_string(struct NID_store *store, struct NID_store *available, const char *names,
								  const void *(*by_name)(const char *),
								  int (*to_nid)(const void *))
{
	char *str, *r;
	char *c = NULL;
	r = str = strdup(names);
	while( (c = strtok_r(r, " ", &r)) != NULL )
	{
		const void *ec = by_name(c);
		if( ec == NULL )
		{
			/* the cipher/digest is unknown */
			TRACE("unknown %s\n", c);
			return false;
		}
		int nid = to_nid(ec);
		if( NID_store_contains(available, nid) == false )
			/* we do not support the cipher */
			return false;

		if( NID_store_add(store, nid) == false)
			return false;
	}
	return true;
}

int digest_nids[] = {
	NID_md4,
	NID_md5,
	NID_sha1,
	NID_sha224,
	NID_sha256,
	NID_sha512,
};

struct NID_store digests_available =
{
	.len = sizeof(digest_nids)/sizeof(digest_nids[0]),
	.data = digest_nids,
};

struct NID_store digests_used =
{
	.len = 0,
};

int cipher_nids[] = {
	NID_des_cbc,
	NID_des_ede3_cbc,
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
};

struct NID_store ciphers_available =
{
	.len = sizeof(cipher_nids)/sizeof(cipher_nids[0]),
	.data = cipher_nids,
};

struct NID_store ciphers_used =
{
	.len = 0,
};

int af_alg_init(ENGINE * engine __U__)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	int sock;
	if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	close(sock);
	return 1;
}

int af_alg_finish(ENGINE * engine __U__)
{
	return 1;
}
/* The definitions for control commands specific to this engine */
#define AF_ALG_CMD_CIPHERS	ENGINE_CMD_BASE
#define AF_ALG_CMD_DIGESTS	(ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN af_alg_cmd_defns[] = {
	{AF_ALG_CMD_CIPHERS,"CIPHERS","which ciphers to run",ENGINE_CMD_FLAG_STRING},
	{AF_ALG_CMD_DIGESTS,"DIGESTS","which digests to run",ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

static int af_alg_ctrl(ENGINE *e, int cmd, long i __U__, void *p, void (*f)() __U__)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	OpenSSL_add_all_algorithms();
	switch( cmd )
	{
	case AF_ALG_CMD_CIPHERS:
		if( p == NULL )
			return 1;
		if( NID_store_from_string(&ciphers_used, &ciphers_available, p, (void *)EVP_get_cipherbyname, (void *)CIPHER_to_nid) == false )
			return 0;
		ENGINE_unregister_ciphers(e);
		ENGINE_register_ciphers(e);
		return 1;
	case AF_ALG_CMD_DIGESTS:
		if( p == NULL )
			return 1;
		if( NID_store_from_string(&digests_used, &digests_available, p, (void *)EVP_get_digestbyname, (void *)MD_to_nid) == false )
			return 0;
		ENGINE_unregister_digests(e);
		ENGINE_register_digests(e);
		return 1;

	default:
		break;
	}
	return 0;
}

static int af_alg_bind_helper(ENGINE * e)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	if( !ENGINE_set_id(e, AF_ALG_ENGINE_ID) ||
		!ENGINE_set_init_function(e, af_alg_init) ||
		!ENGINE_set_finish_function(e, af_alg_finish) ||
		!ENGINE_set_name(e, AF_ALG_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, af_alg_list_ciphers) ||
		!ENGINE_set_digests (e, af_alg_list_digests) ||
		!ENGINE_set_ctrl_function(e, af_alg_ctrl) ||
		!ENGINE_set_cmd_defns(e, af_alg_cmd_defns))
		return 0;
	return 1;
}

ENGINE *ENGINE_af_alg(void)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	ENGINE *eng = ENGINE_new();
	if( !eng )
		return NULL;

	if( !af_alg_bind_helper(eng) )
	{
		ENGINE_free(eng);
		return NULL;
	}
	return eng;
}

static int af_alg_bind_fn(ENGINE *e, const char *id)
{
	TRACE("%s\n", __PRETTY_FUNCTION__);
	if( id && (strcmp(id, AF_ALG_ENGINE_ID) != 0) )
		return 0;

	if( !af_alg_bind_helper(e) )
		return 0;

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(af_alg_bind_fn)

