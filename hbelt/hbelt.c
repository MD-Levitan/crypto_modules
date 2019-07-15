/*
 * ADD tzii.
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 1991-1992, RSA Data Security, Inc. Created 1991.
 * All rights reserved.
 *
 * Derived from the RSA Data Security, Inc. MD5 Message-out Algorithm.
 * Ported to fulfill hasher_t interface.
 *
 * ctx program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * ctx program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#define HASH_SIZE_BELT_256 32

struct crypto_hbelt_ctx {
	
	/*
	 * State of the hasher.
	 */
	uint32_t h[8];
	uint32_t s[4];
	uint32_t c[4];
	uint32_t t[16];
	uint8_t buffer[32];
	unsigned long buf_len;
};


#define	enc_round(_a,_b,_c,_d,_e,_k1,_k2,_k3,_k4,_k5,_k6,_k7,_i) \
	do { \
		(_b)^=G_5((_a)+(_k1)); \
		(_c)^=G_21((_d)+(_k2)); \
		(_a)-=G_13((_b)+(_k3)); \
		(_e)=G_21((_b)+(_c)+(_k4))^((_i)+1); \
		(_b)+=(_e); \
		(_c)-=(_e); \
		(_d)+=G_13((_c)+(_k5)); \
		(_b)^=G_21((_a)+(_k6)); \
		(_c)^=G_5((_d)+(_k7)); \
	} while(0)
#define	dec_round(_a,_b,_c,_d,_e,_k1,_k2,_k3,_k4,_k5,_k6,_k7,_i) \
	do { \
		(_b)^=G_5((_a)+(_k7)); \
		(_c)^=G_21((_d)+(_k6)); \
		(_a)-=G_13((_b)+(_k5)); \
		(_e)=G_21((_b)+(_c)+(_k4))^((_i)+1); \
		(_b)+=(_e); \
		(_c)-=(_e); \
		(_d)+=G_13((_c)+(_k3)); \
		(_b)^=G_21((_a)+(_k2)); \
		(_c)^=G_5((_d)+(_k1)); \
	} while(0)

#define _(h, n) (((h) << (n)) | ((h) >> (32 - (n))))
#define H(n) \
static const uint32_t H##n[] = { \
_(0xb1,n),_(0x94,n),_(0xba,n),_(0xc8,n),_(0x0a,n),_(0x08,n),_(0xf5,n),_(0x3b,n), \
_(0x36,n),_(0x6d,n),_(0x00,n),_(0x8e,n),_(0x58,n),_(0x4a,n),_(0x5d,n),_(0xe4,n), \
_(0x85,n),_(0x04,n),_(0xfa,n),_(0x9d,n),_(0x1b,n),_(0xb6,n),_(0xc7,n),_(0xac,n), \
_(0x25,n),_(0x2e,n),_(0x72,n),_(0xc2,n),_(0x02,n),_(0xfd,n),_(0xce,n),_(0x0d,n), \
_(0x5b,n),_(0xe3,n),_(0xd6,n),_(0x12,n),_(0x17,n),_(0xb9,n),_(0x61,n),_(0x81,n), \
_(0xfe,n),_(0x67,n),_(0x86,n),_(0xad,n),_(0x71,n),_(0x6b,n),_(0x89,n),_(0x0b,n), \
_(0x5c,n),_(0xb0,n),_(0xc0,n),_(0xff,n),_(0x33,n),_(0xc3,n),_(0x56,n),_(0xb8,n), \
_(0x35,n),_(0xc4,n),_(0x05,n),_(0xae,n),_(0xd8,n),_(0xe0,n),_(0x7f,n),_(0x99,n), \
_(0xe1,n),_(0x2b,n),_(0xdc,n),_(0x1a,n),_(0xe2,n),_(0x82,n),_(0x57,n),_(0xec,n), \
_(0x70,n),_(0x3f,n),_(0xcc,n),_(0xf0,n),_(0x95,n),_(0xee,n),_(0x8d,n),_(0xf1,n), \
_(0xc1,n),_(0xab,n),_(0x76,n),_(0x38,n),_(0x9f,n),_(0xe6,n),_(0x78,n),_(0xca,n), \
_(0xf7,n),_(0xc6,n),_(0xf8,n),_(0x60,n),_(0xd5,n),_(0xbb,n),_(0x9c,n),_(0x4f,n), \
_(0xf3,n),_(0x3c,n),_(0x65,n),_(0x7b,n),_(0x63,n),_(0x7c,n),_(0x30,n),_(0x6a,n), \
_(0xdd,n),_(0x4e,n),_(0xa7,n),_(0x79,n),_(0x9e,n),_(0xb2,n),_(0x3d,n),_(0x31,n), \
_(0x3e,n),_(0x98,n),_(0xb5,n),_(0x6e,n),_(0x27,n),_(0xd3,n),_(0xbc,n),_(0xcf,n), \
_(0x59,n),_(0x1e,n),_(0x18,n),_(0x1f,n),_(0x4c,n),_(0x5a,n),_(0xb7,n),_(0x93,n), \
_(0xe9,n),_(0xde,n),_(0xe7,n),_(0x2c,n),_(0x8f,n),_(0x0c,n),_(0x0f,n),_(0xa6,n), \
_(0x2d,n),_(0xdb,n),_(0x49,n),_(0xf4,n),_(0x6f,n),_(0x73,n),_(0x96,n),_(0x47,n), \
_(0x06,n),_(0x07,n),_(0x53,n),_(0x16,n),_(0xed,n),_(0x24,n),_(0x7a,n),_(0x37,n), \
_(0x39,n),_(0xcb,n),_(0xa3,n),_(0x83,n),_(0x03,n),_(0xa9,n),_(0x8b,n),_(0xf6,n), \
_(0x92,n),_(0xbd,n),_(0x9b,n),_(0x1c,n),_(0xe5,n),_(0xd1,n),_(0x41,n),_(0x01,n), \
_(0x54,n),_(0x45,n),_(0xfb,n),_(0xc9,n),_(0x5e,n),_(0x4d,n),_(0x0e,n),_(0xf2,n), \
_(0x68,n),_(0x20,n),_(0x80,n),_(0xaa,n),_(0x22,n),_(0x7d,n),_(0x64,n),_(0x2f,n), \
_(0x26,n),_(0x87,n),_(0xf9,n),_(0x34,n),_(0x90,n),_(0x40,n),_(0x55,n),_(0x11,n), \
_(0xbe,n),_(0x32,n),_(0x97,n),_(0x13,n),_(0x43,n),_(0xfc,n),_(0x9a,n),_(0x48,n), \
_(0xa0,n),_(0x2a,n),_(0x88,n),_(0x5f,n),_(0x19,n),_(0x4b,n),_(0x09,n),_(0xa1,n), \
_(0x7e,n),_(0xcd,n),_(0xa4,n),_(0xd0,n),_(0x15,n),_(0x44,n),_(0xaf,n),_(0x8c,n), \
_(0xa5,n),_(0x84,n),_(0x50,n),_(0xbf,n),_(0x66,n),_(0xd2,n),_(0xe8,n),_(0x8a,n), \
_(0xa2,n),_(0xd7,n),_(0x46,n),_(0x52,n),_(0x42,n),_(0xa8,n),_(0xdf,n),_(0xb3,n), \
_(0x69,n),_(0x74,n),_(0xc5,n),_(0x51,n),_(0xeb,n),_(0x23,n),_(0x29,n),_(0x21,n), \
_(0xd4,n),_(0xef,n),_(0xd9,n),_(0xb4,n),_(0x3a,n),_(0x62,n),_(0x28,n),_(0x75,n), \
_(0x91,n),_(0x14,n),_(0x10,n),_(0xea,n),_(0x77,n),_(0x6c,n),_(0xda,n),_(0x1d,n) \
}

H(5);
H(13);
H(21);
H(29);

#undef _
#undef H

EXPORT_SYMBOL_GPL(H5);
EXPORT_SYMBOL_GPL(H13);
EXPORT_SYMBOL_GPL(H21);
EXPORT_SYMBOL_GPL(H29);

static __inline uint32_t G_5(uint32_t u)
{
	return H5 [(u >>  0) & 0xff] | H13[(u >>  8) & 0xff] |
	       H21[(u >> 16) & 0xff] | H29[(u >> 24) & 0xff];
}

static __inline uint32_t G_13(uint32_t u)
{
	return H13[(u >>  0) & 0xff] | H21[(u >>  8) & 0xff] |
	       H29[(u >> 16) & 0xff] | H5 [(u >> 24) & 0xff];
}

static __inline uint32_t G_21(uint32_t u)
{
	return H21[(u >>  0) & 0xff] | H29[(u >>  8) & 0xff] |
	       H5 [(u >> 16) & 0xff] | H13[(u >> 24) & 0xff];
}

static __inline uint32_t load_u32(const u_char *n)
{
	return	(((uint32_t)n[0]) <<  0) | (((uint32_t)n[1]) <<  8) |
		(((uint32_t)n[2]) << 16) | (((uint32_t)n[3]) << 24) ;
}

static __inline void store_u32(u_char *n, uint32_t x)
{
	n[0] = x >>  0; n[1] = x >>  8;
	n[2] = x >> 16; n[3] = x >> 24;
}

#define p2ul(n) ((unsigned long)(n))

static __inline void u128_mov_aligned(void *d, const void *s)
{
	((uint64_t *)d)[0] = ((uint64_t *)s)[0];
	((uint64_t *)d)[1] = ((uint64_t *)s)[1];
}

static __inline void u128_mov(void *d, const void *s)
{
	if ((p2ul(d) | p2ul(s)) % 8)
		memcpy(d, s, 16);
	else
		u128_mov_aligned(d, s);
}

static __inline void u128_xor_aligned(void *r, const void *a, const void *b)
{
	((uint64_t *)r)[0] = ((uint64_t *)a)[0] ^ ((uint64_t *)b)[0];
	((uint64_t *)r)[1] = ((uint64_t *)a)[1] ^ ((uint64_t *)b)[1];
}

static __inline void u128_xor_unaligned(uint8_t *r, const uint8_t *a,
					const uint8_t *b)
{
	int i;
	for(i = 0; i < 16; ++i)
		r[i] = a[i] ^ b[i];
}

static __inline void u128_xor(void *r, const void *a, const void *b)
{
	if ((p2ul(r) | p2ul(a) | p2ul(b)) % 8)
		u128_xor_unaligned(r, a, b);
	else
		u128_xor_aligned(r, a, b);
}

static __inline void u128_add_word(void  *__r, const void *__lh, uint64_t n)
{
	const uint64_t *lh = __lh;
	uint64_t *r = __r;
	n = (r[0] = lh[0] + n) < lh[0];
	r[1] = lh[1] + n;
}

static __inline void u128_sub_word(void *__r, const void *__lh, uint64_t n)
{
	const uint64_t *lh = __lh;
	uint64_t *r = __r;
	n = (r[0] = lh[0] - n) > lh[0];
	r[1] = lh[1] - n;
}

static void belt_blk_enc(const uint32_t *key, const u_char *x, u_char *y)
{
	register uint32_t a, b, c, d, e;

	a = load_u32(x +  0);
	b = load_u32(x +  4);
	c = load_u32(x +  8);
	d = load_u32(x + 12);

	enc_round(a,b,c,d,e,key[0],key[1],key[2],key[3],key[4],key[5],key[6],0);
	enc_round(b,d,a,c,e,key[7],key[0],key[1],key[2],key[3],key[4],key[5],1);
	enc_round(d,c,b,a,e,key[6],key[7],key[0],key[1],key[2],key[3],key[4],2);
	enc_round(c,a,d,b,e,key[5],key[6],key[7],key[0],key[1],key[2],key[3],3);
	enc_round(a,b,c,d,e,key[4],key[5],key[6],key[7],key[0],key[1],key[2],4);
	enc_round(b,d,a,c,e,key[3],key[4],key[5],key[6],key[7],key[0],key[1],5);
	enc_round(d,c,b,a,e,key[2],key[3],key[4],key[5],key[6],key[7],key[0],6);
	enc_round(c,a,d,b,e,key[1],key[2],key[3],key[4],key[5],key[6],key[7],7);

	store_u32(y +  0, b);
	store_u32(y +  4, d);
	store_u32(y +  8, a);
	store_u32(y + 12, c);
}

/* 512 -> 128 */
static void hbelt_sigma1(uint32_t *r, uint32_t *t, const uint32_t *u12, const uint32_t *u34)
{
	u128_xor(t, u34, u34 + 4);
	belt_blk_enc(u12, (void *) t, (void *) r);
	u128_xor(r, r, t);
}

/* 512 -> 256 */
static void hbelt_sigma2(uint32_t *r, uint32_t *k, const uint32_t *u12, const uint32_t *u34)
{
	hbelt_sigma1(k, k + 4, u12, u34);
	u128_mov(k + 4, u34 + 4);
	belt_blk_enc(k, (void *) u12, (void *) r);
	u128_xor(r, r, u12);

	k[0] ^= ~0; k[1] ^= ~0; k[2] ^= ~0; k[3] ^= ~0;
	u128_mov(k + 4, u34);
	belt_blk_enc(k, (void *) (u12 + 4), (void *) (r + 4));
	u128_xor(r + 4, r + 4, u12 + 4);
}

static void hbelt_step(struct crypto_hbelt_ctx *ctx, uint8_t *data)
{
	/* ctx->t256 <- sigma_1(X_i || h) */
	hbelt_sigma1(ctx->t, ctx->t + 4, (void *) data, ctx->h);
	/* ctx->s <- ctx->s ^ sigma_1(X_i || h) */
	u128_xor(ctx->s, ctx->s, ctx->t);

	/* ctx->h <- sigma_2(X_i || h) */
	hbelt_sigma2(ctx->t, ctx->t + 8, (void *) data, ctx->h);
	u128_mov(ctx->h + 0, ctx->t + 0);
	u128_mov(ctx->h + 4, ctx->t + 4);

	u128_add_word(ctx->c, ctx->c, 32 * 8);
}


/* HBELT block update operation. Continues an HBELT message-out
 * operation, processing another message block, and updating the
 * context.
 */
static int hbelt_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	struct crypto_hbelt_ctx *ctx = shash_desc_ctx(desc);
	
 	size_t shift_len = 0;
	while ((len + ctx->buf_len) >= 32)
	{
		memcpy(ctx->buffer + ctx->buf_len, data + shift_len, 32 - ctx->buf_len);
		hbelt_step(ctx, ctx->buffer);
		len -= (32 - ctx->buf_len);
		shift_len += (32 - ctx->buf_len);
		ctx->buf_len = 0;  
	}
	if(len)
	{
		memcpy(ctx->buffer + ctx->buf_len, data + shift_len, len);
		ctx->buf_len += len;
	}
	
	return 0;
}

/* HBELT finalization. Ends an HBELT message-out operation, writing the
 * the message out and zeroizing the context.
 */

static int hbelt_final(struct shash_desc *desc, u8 *out)
{
	struct crypto_hbelt_ctx *ctx = shash_desc_ctx(desc);

	while (ctx->buf_len >= 32) {
		hbelt_step(ctx, ctx->buffer);
		ctx->buf_len -= 32;
	}
	if (ctx->buf_len) {
		memset(ctx->buffer + ctx->buf_len, 0, 32 - ctx->buf_len);
		hbelt_step(ctx, ctx->buffer);
		u128_sub_word(ctx->c, ctx->c, (32 - ctx->buf_len) * 8);
	}

	u128_mov(ctx->t, ctx->c);
	u128_mov(ctx->t + 4, ctx->s);
	hbelt_sigma2((void *) out, ctx->t + 8, ctx->t, ctx->h);
}

static int hbelt_init(struct shash_desc *desc)
{
	struct crypto_hbelt_ctx *ctx = shash_desc_ctx(desc);
	
	ctx->buf_len = 0;
	ctx->s[0] = ctx->s[1] = ctx->s[2] = ctx->s[3] = 0;
	ctx->c[0] = ctx->c[1] = ctx->c[2] = ctx->c[3] = 0;
	ctx->h[0] = 0xc8ba94b1;
	ctx->h[1] = 0x3bf5080a;
	ctx->h[2] = 0x8e006d36;
	ctx->h[3] = 0xe45d4a58;
	ctx->h[4] = 0x9dfa0485;
	ctx->h[5] = 0xacc7b61b;
	ctx->h[6] = 0xc2722e25;
	ctx->h[7] = 0x0dcefd02;
	
	return 0;
}

static int hbelt_export(struct shash_desc *desc, void *out)
{
	struct crypto_hbelt_ctx *ctx = shash_desc_ctx(desc);

	memcpy(out, ctx, sizeof(*ctx));
	return 0;
}

static int hbelt_import(struct shash_desc *desc, const void *in)
{
	struct crypto_hbelt_ctx *ctx = shash_desc_ctx(desc);

	memcpy(ctx, in, sizeof(*ctx));
	return 0;
}

static struct shash_alg alg = {
	.digestsize	=	HASH_SIZE_BELT_256,
	.init		=	hbelt_init,
	.update		=	hbelt_update,
	.final		=	hbelt_final,
	.export		=	hbelt_export,
	.import		=	hbelt_import,
	.descsize	=	sizeof(struct crypto_hbelt_ctx),
	.statesize	=	sizeof(struct crypto_hbelt_ctx),
	.base		=	{
		.cra_name	 =	"hbelt",
		.cra_driver_name =	"hbelt",
		.cra_blocksize	 =	HASH_SIZE_BELT_256,
		.cra_module	 =	THIS_MODULE,
	}
};

static int __init hbelt_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit hbelt_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

subsys_initcall(hbelt_mod_init);
module_exit(hbelt_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("STB 34.101.31 belt-hash");
MODULE_ALIAS_CRYPTO("hbelt");
