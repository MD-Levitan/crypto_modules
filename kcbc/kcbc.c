/*
 * Cryptographic API.
 *
 * Cipher Algorithm Template For BMAC.
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

#include <crypto/internal/hash.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#define KCBC_BLOCK_SIZE        16
#define KCBC_QWORD_SIZE        4


/*
 * +------------------------
 * | <parent tfm>
 * +------------------------
 * | kcbc_tfm_ctx
 * +------------------------
 * | buf (KCBC_BLOCK_SIZE* 2)
 * +------------------------
 */
struct kcbc_tfm_ctx {
    struct crypto_cipher *child;
    uint32_t consts[2 * KCBC_QWORD_SIZE];
};

/*
 * +------------------------
 * | <shash desc>
 * +------------------------
 * | kcbc_desc_ctx
 * +------------------------
 * | s   (KMAC_BLOCK_SIZE)
 * +------------------------
 * | r   (KMAC_BLOCK_SIZE)
 * +------------------------
 */
struct kcbc_desc_ctx {
    unsigned int len;
    uint8_t s[KCBC_BLOCK_SIZE];
    uint8_t r[KCBC_BLOCK_SIZE];
};

static int crypto_kcbc_setkey(struct crypto_shash *parent,
                                const uint8_t *inkey, unsigned int keylen)
{
    struct kcbc_tfm_ctx *ctx = crypto_shash_ctx(parent);
    uint32_t *const1 = ctx->consts;
    uint32_t *const2 = const1 + KCBC_QWORD_SIZE;
    uint32_t tmp = 0;
    int err = 0;

    if ((err = crypto_cipher_setkey(ctx->child, inkey, keylen)))
        return err;

    memset((uint8_t *) const1, 0, KCBC_BLOCK_SIZE);
    crypto_cipher_encrypt_one(ctx->child, (uint8_t *) const1, (uint8_t *) const1);
    memcpy((uint8_t *) const2, (uint8_t *) const1, KCBC_BLOCK_SIZE);

    tmp = const1[0] ^ const1[1];
    const1[0] = const1[1];
    const1[1] = const1[2];
    const1[2] = const1[3];
    const1[3] = tmp;

    tmp = const2[0] ^ const2[3];
    const2[3] = const2[2];
    const2[2] = const2[1];
    const2[1] = const2[0];
    const2[0] = tmp;

    return err;
}

static int crypto_kcbc_digest_init(struct shash_desc *pdesc)
{
    struct kcbc_desc_ctx *ctx = shash_desc_ctx(pdesc);

    ctx->len = 0;

    memset((uint8_t *) ctx->s, 0, KCBC_BLOCK_SIZE * sizeof(uint8_t));
    memset((uint8_t *) ctx->r, 0, KCBC_BLOCK_SIZE * sizeof(uint8_t));
    return 0;
}

static int crypto_kcbc_digest_update(struct shash_desc *pdesc, const uint8_t *p,
                                     unsigned int len)
{
    struct crypto_shash *parent = pdesc->tfm;
    struct kcbc_tfm_ctx *tctx = crypto_shash_ctx(parent);
    struct kcbc_desc_ctx *ctx = shash_desc_ctx(pdesc);
    struct crypto_cipher *tfm = tctx->child;

    int bs = crypto_shash_blocksize(parent);
    // odds == s
    // prev == r
    uint8_t *odds = ctx->s;
    uint8_t *prev = ctx->r;

    /* checking the data can fill the block */
    if ((ctx->len + len) <= bs) {
        memcpy(odds + ctx->len, p, len);
        ctx->len += len;
        return 0;
    }

    /* filling odds with new data and encrypting it */
    memcpy(odds + ctx->len, p, bs - ctx->len);
    len -= bs - ctx->len;
    p += bs - ctx->len;

    crypto_xor(prev, odds, bs);
    crypto_cipher_encrypt_one(tfm, prev, prev);

    /* clearing the length */
    ctx->len = 0;

    /* encrypting the rest of data */
    while (len > bs) {
        crypto_xor(prev, p, bs);
        crypto_cipher_encrypt_one(tfm, prev, prev);
        p += bs;
        len -= bs;
    }

    /* keeping the surplus of blocksize */
    if (len) {
        memcpy(odds, p, len);
        ctx->len = len;
    }

    return 0;
}

static int crypto_kcbc_digest_final(struct shash_desc *pdesc, uint8_t *out)
{
    struct crypto_shash *parent = pdesc->tfm;
    struct kcbc_tfm_ctx *tctx = crypto_shash_ctx(parent);
    struct kcbc_desc_ctx *ctx = shash_desc_ctx(pdesc);
    struct crypto_cipher *tfm = tctx->child;
    int bs = crypto_shash_blocksize(parent);
    uint32_t *const1 = tctx->consts;
    uint32_t *const2 = tctx->consts + KCBC_QWORD_SIZE;

    // odds == s
    // prev == r
    uint8_t *odds = ctx->s;
    uint8_t *prev = ctx->r;
 
    if (ctx->len != bs) {
        unsigned int rlen;
        uint8_t *p = odds + ctx->len;

        *p = 0x80;
        p++;

        rlen = bs - ctx->len -1;
        if (rlen)
            memset(p, 0, rlen);

        crypto_xor(odds, (uint8_t *)const2, bs);
    }
    else {
        crypto_xor(odds, (uint8_t *)const1, bs);
    }

    crypto_xor(prev, odds, bs);

    crypto_cipher_encrypt_one(tfm, out, prev);

    return 0;
}

static int kcbc_init_tfm(struct crypto_tfm *tfm)
{
    struct crypto_cipher *cipher;
    struct crypto_instance *inst = (void *)tfm->__crt_alg;
    struct crypto_spawn *spawn = crypto_instance_ctx(inst);
    struct kcbc_tfm_ctx *ctx = crypto_tfm_ctx(tfm);

    cipher = crypto_spawn_cipher(spawn);
    if (IS_ERR(cipher))
        return PTR_ERR(cipher);

    ctx->child = cipher;

    return 0;
};

static void kcbc_exit_tfm(struct crypto_tfm *tfm)
{
    struct kcbc_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
    crypto_free_cipher(ctx->child);
}

static int kcbc_create(struct crypto_template *tmpl, struct rtattr **tb)
{
    struct shash_instance *inst;
    struct crypto_alg *alg;
    unsigned long alignmask;
    int err;

    err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SHASH);
    if (err)
        return err;

    alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER,
                              CRYPTO_ALG_TYPE_MASK);
    if (IS_ERR(alg))
        return PTR_ERR(alg);

    switch(alg->cra_blocksize) {
        case KCBC_BLOCK_SIZE:
            break;
        default:
            goto out_put_alg;
    }

    inst = shash_alloc_instance("kcbc", alg);
    err = PTR_ERR(inst);
    if (IS_ERR(inst))
        goto out_put_alg;

    err = crypto_init_spawn(shash_instance_ctx(inst), alg,
                            shash_crypto_instance(inst),
                            CRYPTO_ALG_TYPE_MASK);
    if (err)
        goto out_free_inst;

    alignmask = alg->cra_alignmask | 3;
    inst->alg.base.cra_alignmask = alignmask;
    inst->alg.base.cra_priority = alg->cra_priority;
    inst->alg.base.cra_blocksize = alg->cra_blocksize;

    inst->alg.digestsize = alg->cra_blocksize;
    inst->alg.descsize = ALIGN(sizeof(struct kcbc_desc_ctx),
                               crypto_tfm_ctx_alignment()) +
                         (alignmask &
                          ~(crypto_tfm_ctx_alignment() - 1)) +
                         alg->cra_blocksize * 2;

    inst->alg.base.cra_ctxsize = ALIGN(sizeof(struct kcbc_tfm_ctx),
                                       alignmask + 1) +
                                 alg->cra_blocksize * 2;
    inst->alg.base.cra_init = kcbc_init_tfm;
    inst->alg.base.cra_exit = kcbc_exit_tfm;

    inst->alg.init = crypto_kcbc_digest_init;
    inst->alg.update = crypto_kcbc_digest_update;
    inst->alg.final = crypto_kcbc_digest_final;
    inst->alg.setkey = crypto_kcbc_setkey;

    err = shash_register_instance(tmpl, inst);
    if (err) {
        out_free_inst:
        shash_free_instance(shash_crypto_instance(inst));
    }

    out_put_alg:
    crypto_mod_put(alg);
    return err;
}

static struct crypto_template crypto_kcbc_tmpl = {
        .name = "kcbc",
        .create = kcbc_create,
        .free = shash_free_instance,
        .module = THIS_MODULE,
};

static int __init crypto_kcbc_module_init(void)
{
    return crypto_register_template(&crypto_kcbc_tmpl);
}

static void __exit crypto_kcbc_module_exit(void)
{
    crypto_unregister_template(&crypto_kcbc_tmpl);
}

subsys_initcall(crypto_kcbc_module_init);
module_exit(crypto_kcbc_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KCBC keyed hash algorithm");
MODULE_ALIAS_CRYPTO("kcbc");