/*
 * Cryptographic API.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/lz4k.h>

struct lz4k_ctx {
	void *lz4k_comp_mem;
};

static int lz4k_init(struct crypto_tfm *tfm)
{
	struct lz4k_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->lz4k_comp_mem = vmalloc(LZ4K_MEM_COMPRESS);
	if (!ctx->lz4k_comp_mem)
		return -ENOMEM;

	return 0;
}

static void lz4k_exit(struct crypto_tfm *tfm)
{
	struct lz4k_ctx *ctx = crypto_tfm_ctx(tfm);
	vfree(ctx->lz4k_comp_mem);
}

static int lz4k_compress_crypto(struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct lz4k_ctx *ctx = crypto_tfm_ctx(tfm);
	size_t tmp_len = *dlen;
	int err;

	err = lz4k_compress(src, slen, dst, &tmp_len, ctx->lz4k_comp_mem);

	if (err < 0)
		return -EINVAL;

	*dlen = tmp_len;
	return 0;
}

static int lz4k_decompress_crypto(struct crypto_tfm *tfm, const u8 *src,
			      unsigned int slen, u8 *dst, unsigned int *dlen)
{
	int err;
	size_t tmp_len = *dlen;

	err = lz4k_decompress_safe(src, slen, dst, &tmp_len);

	if (err < 0)
		return -EINVAL;

	*dlen = tmp_len;
	return 0;

}

static struct crypto_alg alg = {
	.cra_name		= "lz4k",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct lz4k_ctx),
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(alg.cra_list),
	.cra_init		= lz4k_init,
	.cra_exit		= lz4k_exit,
	.cra_u			= { .compress = {
	.coa_compress	= lz4k_compress_crypto,
	.coa_decompress	= lz4k_decompress_crypto }
	}
};

static int __init lz4k_mod_init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit lz4k_mod_fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(lz4k_mod_init);
module_exit(lz4k_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LZ77 with 4K Compression Algorithm");
