/*
 * Cryptographic API.
 *
 * BELT Cipher Algorithm.
 *
 *
 * Linux developer:
 *  Maksim Dzerkach <ovsyanka@protonmail.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 * ---------------------------------------------------------------------------
 */

#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>

#define BELT_KS_LENGTH 8

#define BELT_KEY_SIZE 32
#define BELT_MIN_KEY_SIZE 16
#define BELT_MAX_KEY_SIZE 32
#define BELT_KEYSIZE_128 16
#define BELT_KEYSIZE_192 24
#define BELT_KEYSIZE_256 32
#define BELT_BLOCK_SIZE 16

struct crypto_belt_ctx {
    uint32_t key[BELT_KS_LENGTH];
    uint32_t key_length;
};

/* slower but generic big endian or with data alignment restrictions */
/* some additional "const" touches to stop "gcc -Wcast-qual" complains --jjo */
#define word_in(x)                                   \
    ((uint32_t)(((unsigned char *)(x))[0]) |         \
     ((uint32_t)(((unsigned char *)(x))[1]) << 8) |  \
     ((uint32_t)(((unsigned char *)(x))[2]) << 16) | \
     ((uint32_t)(((unsigned char *)(x))[3]) << 24))
#define const_word_in(x)                                         \
    ((const uint32_t)(((const unsigned char *)(x))[0]) |         \
     ((const uint32_t)(((const unsigned char *)(x))[1]) << 8) |  \
     ((const uint32_t)(((const unsigned char *)(x))[2]) << 16) | \
     ((const uint32_t)(((const unsigned char *)(x))[3]) << 24))
#define word_out(x, v)                                                       \
    ((unsigned char *)(x))[0] = (v), ((unsigned char *)(x))[1] = ((v) >> 8), \
                    ((unsigned char *)(x))[2] = ((v) >> 16),                 \
                    ((unsigned char *)(x))[3] = ((v) >> 24)
#define const_word_out(x, v)                                             \
    ((const unsigned char *)(x))[0] = (v),                               \
                          ((const unsigned char *)(x))[1] = ((v) >> 8),  \
                          ((const unsigned char *)(x))[2] = ((v) >> 16), \
                          ((const unsigned char *)(x))[3] = ((v) >> 24)

// Belt round functions.
#define enc_round(_a, _b, _c, _d, _e, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _i) \
    do {                                                                     \
        (_b) ^= G_5((_a) + (_k1));                                           \
        (_c) ^= G_21((_d) + (_k2));                                          \
        (_a) -= G_13((_b) + (_k3));                                          \
        (_e) = G_21((_b) + (_c) + (_k4)) ^ ((_i) + 1);                       \
        (_b) += (_e);                                                        \
        (_c) -= (_e);                                                        \
        (_d) += G_13((_c) + (_k5));                                          \
        (_b) ^= G_21((_a) + (_k6));                                          \
        (_c) ^= G_5((_d) + (_k7));                                           \
    } while (0)
#define dec_round(_a, _b, _c, _d, _e, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _i) \
    do {                                                                     \
        (_b) ^= G_5((_a) + (_k7));                                           \
        (_c) ^= G_21((_d) + (_k6));                                          \
        (_a) -= G_13((_b) + (_k5));                                          \
        (_e) = G_21((_b) + (_c) + (_k4)) ^ ((_i) + 1);                       \
        (_b) += (_e);                                                        \
        (_c) -= (_e);                                                        \
        (_d) += G_13((_c) + (_k3));                                          \
        (_b) ^= G_21((_a) + (_k2));                                          \
        (_c) ^= G_5((_d) + (_k1));                                           \
    } while (0)

#define _(h, n) ((((uint32_t)h) << (n)) | ((h) >> (32 - (n))))
#define H(n)                                                                  \
    static const uint32_t                                                     \
        H##n[] = {_(0xb1, n), _(0x94, n), _(0xba, n), _(0xc8, n), _(0x0a, n), \
                  _(0x08, n), _(0xf5, n), _(0x3b, n), _(0x36, n), _(0x6d, n), \
                  _(0x00, n), _(0x8e, n), _(0x58, n), _(0x4a, n), _(0x5d, n), \
                  _(0xe4, n), _(0x85, n), _(0x04, n), _(0xfa, n), _(0x9d, n), \
                  _(0x1b, n), _(0xb6, n), _(0xc7, n), _(0xac, n), _(0x25, n), \
                  _(0x2e, n), _(0x72, n), _(0xc2, n), _(0x02, n), _(0xfd, n), \
                  _(0xce, n), _(0x0d, n), _(0x5b, n), _(0xe3, n), _(0xd6, n), \
                  _(0x12, n), _(0x17, n), _(0xb9, n), _(0x61, n), _(0x81, n), \
                  _(0xfe, n), _(0x67, n), _(0x86, n), _(0xad, n), _(0x71, n), \
                  _(0x6b, n), _(0x89, n), _(0x0b, n), _(0x5c, n), _(0xb0, n), \
                  _(0xc0, n), _(0xff, n), _(0x33, n), _(0xc3, n), _(0x56, n), \
                  _(0xb8, n), _(0x35, n), _(0xc4, n), _(0x05, n), _(0xae, n), \
                  _(0xd8, n), _(0xe0, n), _(0x7f, n), _(0x99, n), _(0xe1, n), \
                  _(0x2b, n), _(0xdc, n), _(0x1a, n), _(0xe2, n), _(0x82, n), \
                  _(0x57, n), _(0xec, n), _(0x70, n), _(0x3f, n), _(0xcc, n), \
                  _(0xf0, n), _(0x95, n), _(0xee, n), _(0x8d, n), _(0xf1, n), \
                  _(0xc1, n), _(0xab, n), _(0x76, n), _(0x38, n), _(0x9f, n), \
                  _(0xe6, n), _(0x78, n), _(0xca, n), _(0xf7, n), _(0xc6, n), \
                  _(0xf8, n), _(0x60, n), _(0xd5, n), _(0xbb, n), _(0x9c, n), \
                  _(0x4f, n), _(0xf3, n), _(0x3c, n), _(0x65, n), _(0x7b, n), \
                  _(0x63, n), _(0x7c, n), _(0x30, n), _(0x6a, n), _(0xdd, n), \
                  _(0x4e, n), _(0xa7, n), _(0x79, n), _(0x9e, n), _(0xb2, n), \
                  _(0x3d, n), _(0x31, n), _(0x3e, n), _(0x98, n), _(0xb5, n), \
                  _(0x6e, n), _(0x27, n), _(0xd3, n), _(0xbc, n), _(0xcf, n), \
                  _(0x59, n), _(0x1e, n), _(0x18, n), _(0x1f, n), _(0x4c, n), \
                  _(0x5a, n), _(0xb7, n), _(0x93, n), _(0xe9, n), _(0xde, n), \
                  _(0xe7, n), _(0x2c, n), _(0x8f, n), _(0x0c, n), _(0x0f, n), \
                  _(0xa6, n), _(0x2d, n), _(0xdb, n), _(0x49, n), _(0xf4, n), \
                  _(0x6f, n), _(0x73, n), _(0x96, n), _(0x47, n), _(0x06, n), \
                  _(0x07, n), _(0x53, n), _(0x16, n), _(0xed, n), _(0x24, n), \
                  _(0x7a, n), _(0x37, n), _(0x39, n), _(0xcb, n), _(0xa3, n), \
                  _(0x83, n), _(0x03, n), _(0xa9, n), _(0x8b, n), _(0xf6, n), \
                  _(0x92, n), _(0xbd, n), _(0x9b, n), _(0x1c, n), _(0xe5, n), \
                  _(0xd1, n), _(0x41, n), _(0x01, n), _(0x54, n), _(0x45, n), \
                  _(0xfb, n), _(0xc9, n), _(0x5e, n), _(0x4d, n), _(0x0e, n), \
                  _(0xf2, n), _(0x68, n), _(0x20, n), _(0x80, n), _(0xaa, n), \
                  _(0x22, n), _(0x7d, n), _(0x64, n), _(0x2f, n), _(0x26, n), \
                  _(0x87, n), _(0xf9, n), _(0x34, n), _(0x90, n), _(0x40, n), \
                  _(0x55, n), _(0x11, n), _(0xbe, n), _(0x32, n), _(0x97, n), \
                  _(0x13, n), _(0x43, n), _(0xfc, n), _(0x9a, n), _(0x48, n), \
                  _(0xa0, n), _(0x2a, n), _(0x88, n), _(0x5f, n), _(0x19, n), \
                  _(0x4b, n), _(0x09, n), _(0xa1, n), _(0x7e, n), _(0xcd, n), \
                  _(0xa4, n), _(0xd0, n), _(0x15, n), _(0x44, n), _(0xaf, n), \
                  _(0x8c, n), _(0xa5, n), _(0x84, n), _(0x50, n), _(0xbf, n), \
                  _(0x66, n), _(0xd2, n), _(0xe8, n), _(0x8a, n), _(0xa2, n), \
                  _(0xd7, n), _(0x46, n), _(0x52, n), _(0x42, n), _(0xa8, n), \
                  _(0xdf, n), _(0xb3, n), _(0x69, n), _(0x74, n), _(0xc5, n), \
                  _(0x51, n), _(0xeb, n), _(0x23, n), _(0x29, n), _(0x21, n), \
                  _(0xd4, n), _(0xef, n), _(0xd9, n), _(0xb4, n), _(0x3a, n), \
                  _(0x62, n), _(0x28, n), _(0x75, n), _(0x91, n), _(0x14, n), \
                  _(0x10, n), _(0xea, n), _(0x77, n), _(0x6c, n), _(0xda, n), \
                  _(0x1d, n)}

H(5);
H(13);
H(21);
H(29);

#undef _
#undef H

extern const u32 crypto_belt_h5[256] __alias(H5);
extern const u32 crypto_belt_h13[256] __alias(H13);
extern const u32 crypto_belt_h21[256] __alias(H21);
extern const u32 crypto_belt_h29[256] __alias(H29);

EXPORT_SYMBOL(crypto_belt_h5);
EXPORT_SYMBOL(crypto_belt_h13);
EXPORT_SYMBOL(crypto_belt_h21);
EXPORT_SYMBOL(crypto_belt_h29);

static __inline uint32_t G_5(uint32_t u) {
    return H5[(u >> 0) & 0xff] | H13[(u >> 8) & 0xff] | H21[(u >> 16) & 0xff] |
           H29[(u >> 24) & 0xff];
}

static __inline uint32_t G_13(uint32_t u) {
    return H13[(u >> 0) & 0xff] | H21[(u >> 8) & 0xff] | H29[(u >> 16) & 0xff] |
           H5[(u >> 24) & 0xff];
}

static __inline uint32_t G_21(uint32_t u) {
    return H21[(u >> 0) & 0xff] | H29[(u >> 8) & 0xff] | H5[(u >> 16) & 0xff] |
           H13[(u >> 24) & 0xff];
}

static __inline uint32_t load_uint32_t(const u_char *n) {
    return (((uint32_t)n[0]) << 0) | (((uint32_t)n[1]) << 8) |
           (((uint32_t)n[2]) << 16) | (((uint32_t)n[3]) << 24);
}

static __inline void store_uint32_t(u_char *n, uint32_t x) {
    n[0] = x >> 0;
    n[1] = x >> 8;
    n[2] = x >> 16;
    n[3] = x >> 24;
}

/**
 * belt_expand_key - Expands the BELT key as described in STB 34.101.31
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 */
int belt_expand_key(struct crypto_belt_ctx *ctx, const u8 *in_key,
                    unsigned int key_len) {
    if ((key_len != BELT_KEYSIZE_128 && key_len != BELT_KEYSIZE_192 &&
         key_len != BELT_KEYSIZE_256) ||
        in_key == NULL)
        return 1;

    ctx->key_length = key_len;
    ctx->key[0] = const_word_in(in_key);
    ctx->key[1] = const_word_in(in_key + 4);
    ctx->key[2] = const_word_in(in_key + 8);
    ctx->key[3] = const_word_in(in_key + 12);
    switch (key_len) {
        case BELT_KEYSIZE_256:
            ctx->key[4] = const_word_in(in_key + 16);
            ctx->key[5] = const_word_in(in_key + 20);
            ctx->key[6] = const_word_in(in_key + 24);
            ctx->key[7] = const_word_in(in_key + 28);

            break;
        case BELT_KEYSIZE_192:
            ctx->key[4] = const_word_in(in_key + 16);
            ctx->key[5] = const_word_in(in_key + 20);
            ctx->key[6] = ctx->key[0] ^ ctx->key[1] ^ ctx->key[2];
            ctx->key[7] = ctx->key[3] ^ ctx->key[4] ^ ctx->key[5];
            break;
        case BELT_KEYSIZE_128:
            ctx->key[4] = ctx->key[0];
            ctx->key[5] = ctx->key[1];
            ctx->key[6] = ctx->key[2];
            ctx->key[7] = ctx->key[3];
            break;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(belt_expand_key);

/**
 * belt_set_key - Set the BELT key.
 * @tfm:	The %crypto_tfm that is used in the context.
 * @in_key:	The input key.
 * @key_len:	The size of the key.
 *
 * Returns 0 on success, on failure the %CRYPTO_TFM_RES_BAD_KEY_LEN flag in tfm
 * is set. The function uses crypto_aes_expand_key() to expand the key.
 * &crypto_aes_ctx _must_ be the private data embedded in @tfm which is
 * retrieved with crypto_tfm_ctx().
 */
int belt_set_key(struct crypto_tfm *tfm, const u8 *in_key,
                 unsigned int key_len) {
    struct crypto_belt_ctx *ctx = crypto_tfm_ctx(tfm);
    int ret;
    ret = belt_expand_key(ctx, in_key, key_len);
    if (!ret) return 0;
    return 1;
}
EXPORT_SYMBOL_GPL(belt_set_key);

/**
 * Encrypt a single block of data.
 */

static void encrypt_block(const uint32_t *key, const unsigned char in_blk[],
                          unsigned char out_blk[]) {
    register uint32_t a, b, c, d, e;

    a = load_uint32_t(in_blk + 0);
    b = load_uint32_t(in_blk + 4);
    c = load_uint32_t(in_blk + 8);
    d = load_uint32_t(in_blk + 12);

    enc_round(a, b, c, d, e, key[0], key[1], key[2], key[3], key[4], key[5],
              key[6], 0);
    enc_round(b, d, a, c, e, key[7], key[0], key[1], key[2], key[3], key[4],
              key[5], 1);
    enc_round(d, c, b, a, e, key[6], key[7], key[0], key[1], key[2], key[3],
              key[4], 2);
    enc_round(c, a, d, b, e, key[5], key[6], key[7], key[0], key[1], key[2],
              key[3], 3);
    enc_round(a, b, c, d, e, key[4], key[5], key[6], key[7], key[0], key[1],
              key[2], 4);
    enc_round(b, d, a, c, e, key[3], key[4], key[5], key[6], key[7], key[0],
              key[1], 5);
    enc_round(d, c, b, a, e, key[2], key[3], key[4], key[5], key[6], key[7],
              key[0], 6);
    enc_round(c, a, d, b, e, key[1], key[2], key[3], key[4], key[5], key[6],
              key[7], 7);

    store_uint32_t(out_blk + 0, b);
    store_uint32_t(out_blk + 4, d);
    store_uint32_t(out_blk + 8, a);
    store_uint32_t(out_blk + 12, c);
}

/**
 * Decrypt a single block of data.
 */
static void decrypt_block(const uint32_t *key, const unsigned char in_blk[],
                          unsigned char out_blk[]) {
    register uint32_t a, b, c, d, e;

    a = load_uint32_t(in_blk + 0);
    b = load_uint32_t(in_blk + 4);
    c = load_uint32_t(in_blk + 8);
    d = load_uint32_t(in_blk + 12);

    dec_round(a, b, c, d, e, key[1], key[2], key[3], key[4], key[5], key[6],
              key[7], 7);
    dec_round(c, a, d, b, e, key[2], key[3], key[4], key[5], key[6], key[7],
              key[0], 6);
    dec_round(d, c, b, a, e, key[3], key[4], key[5], key[6], key[7], key[0],
              key[1], 5);
    dec_round(b, d, a, c, e, key[4], key[5], key[6], key[7], key[0], key[1],
              key[2], 4);
    dec_round(a, b, c, d, e, key[5], key[6], key[7], key[0], key[1], key[2],
              key[3], 3);
    dec_round(c, a, d, b, e, key[6], key[7], key[0], key[1], key[2], key[3],
              key[4], 2);
    dec_round(d, c, b, a, e, key[7], key[0], key[1], key[2], key[3], key[4],
              key[5], 1);
    dec_round(b, d, a, c, e, key[0], key[1], key[2], key[3], key[4], key[5],
              key[6], 0);

    store_uint32_t(out_blk + 0, c);
    store_uint32_t(out_blk + 4, a);
    store_uint32_t(out_blk + 8, d);
    store_uint32_t(out_blk + 12, b);
}

static void belt_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in) {
    const struct crypto_belt_ctx *ctx = crypto_tfm_ctx(tfm);
    const uint32_t *kp = ctx->key;
    encrypt_block(kp, in, out);
}

static void belt_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in) {
    const struct crypto_belt_ctx *ctx = crypto_tfm_ctx(tfm);
    const uint32_t *kp = ctx->key;
    decrypt_block(kp, in, out);
}

static struct crypto_alg belt_alg = {
    .cra_name = "belt",
    .cra_driver_name = "belt",
    .cra_priority = 16,
    .cra_flags = CRYPTO_ALG_TYPE_CIPHER,
    .cra_alignmask = 3,
    .cra_blocksize = BELT_BLOCK_SIZE,
    .cra_ctxsize = sizeof(struct crypto_belt_ctx),
    .cra_module = THIS_MODULE,
    .cra_list = LIST_HEAD_INIT(belt_alg.cra_list),
    .cra_u = {.cipher = {.cia_min_keysize = BELT_MIN_KEY_SIZE,
                         .cia_max_keysize = BELT_MAX_KEY_SIZE,
                         .cia_setkey = belt_set_key,
                         .cia_encrypt = belt_encrypt,
                         .cia_decrypt = belt_decrypt}}};
static int __init belt_init(void) { return crypto_register_alg(&belt_alg); }
static void __exit belt_fini(void) { crypto_unregister_alg(&belt_alg); }
module_init(belt_init);
module_exit(belt_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("STB 34.101.31 belt");
MODULE_ALIAS_CRYPTO("belt");
