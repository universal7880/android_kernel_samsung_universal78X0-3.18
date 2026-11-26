// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity builtin signature verification
 *
 * Copyright 2019 Google LLC
 */

#include "fsverity_private.h"

#include <crypto/pkcs7.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/slab.h>
#include <linux/sysctl.h>

static struct key *fsverity_keyring;
static int fsverity_require_signatures;

static struct ctl_table fsverity_sysctls[] = {
	{
		.procname = "require_signatures",
		.data = &fsverity_require_signatures,
		.maxlen = sizeof(fsverity_require_signatures),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = &(int){ 0 },
		.extra2 = &(int){ 1 },
	},
	{ }
};

int fsverity_check_signature_required(const struct fsverity_info *vi)
{
	if (READ_ONCE(fsverity_require_signatures) && !vi->signature_verified) {
		fsverity_err(vi->inode, "require_signatures=1, rejecting unsigned file");
		return -EPERM;
	}
	return 0;
}

int fsverity_verify_signature(struct fsverity_info *vi,
			      const struct fsverity_descriptor *desc)
{
	const struct fsverity_hash_alg *alg = vi->tree_params.hash_alg;
	const u32 sig_size = le32_to_cpu(desc->sig_size);
	struct fsverity_signed_digest *digest;
	struct pkcs7_message *message;
	bool system_trusted;
	size_t digest_len;
	int err;

	if (!sig_size)
		return fsverity_check_signature_required(vi);
	if (!fsverity_keyring)
		return -ENOKEY;

	digest_len = sizeof(*digest) + alg->digest_size;
	digest = kzalloc(digest_len, GFP_KERNEL);
	if (!digest)
		return -ENOMEM;

	memcpy(digest->magic, "FSVerity", sizeof(digest->magic));
	digest->digest_algorithm = cpu_to_le16(alg - fsverity_hash_algs);
	digest->digest_size = cpu_to_le16(alg->digest_size);
	memcpy(digest->digest, vi->measurement, alg->digest_size);

	message = pkcs7_parse_message(desc->signature, sig_size);
	if (IS_ERR(message)) {
		err = PTR_ERR(message);
		goto out_free_digest;
	}

	err = pkcs7_supply_detached_data(message, digest, digest_len);
	if (!err)
		err = pkcs7_verify(message);
	/*
	 * The 3.18 verifier returns zero if a signature chains to the supplied
	 * keyring. Its extra out parameter reports the matched key's
	 * KEY_FLAG_TRUSTED status, which is independent of fs-verity trust.
	 */
	if (!err)
		err = pkcs7_validate_trust(message, fsverity_keyring, &system_trusted);
	pkcs7_free_message(message);
out_free_digest:
	kfree(digest);
	if (err) {
		fsverity_err(vi->inode, "builtin signature verification failed: %d", err);
		return err;
	}

	vi->signature_verified = true;
	return 0;
}

int __init fsverity_init_signature(void)
{
	struct key *ring;

	ring = keyring_alloc(".fs-verity", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			     current_cred(), KEY_POS_SEARCH | KEY_USR_VIEW |
			     KEY_USR_READ | KEY_USR_WRITE | KEY_USR_SEARCH |
			     KEY_USR_SETATTR, KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(ring))
		return PTR_ERR(ring);

	if (!register_sysctl("fs/verity", fsverity_sysctls)) {
		key_put(ring);
		return -ENOMEM;
	}
	fsverity_keyring = ring;
	return 0;
}
