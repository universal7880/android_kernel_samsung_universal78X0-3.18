/*
 * linux/fs/ext4/readpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2015, Google, Inc.
 *
 * This was originally taken from fs/mpage.c
 *
 * The intent is the ext4_mpage_readpages() function here is intended
 * to replace mpage_readpages() in the general case, not just for
 * encrypted files.  It has some limitations (see below), where it
 * will fall back to read_block_full_page(), but these limitations
 * should only be hit when page_size != block_size.
 *
 * This will allow us to attach a callback function to support ext4
 * encryption.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_CACHE_SIZE setups.
 *
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>

#include "ext4.h"
#include <trace/events/android_fs.h>

struct ext4_read_ctx {
	struct bio *bio;
	struct work_struct decrypt_work;
	struct work_struct verify_work;
};

static bool ext4_page_needs_verity(const struct inode *inode, pgoff_t index)
{
	/* The Merkle tree is itself read through this mapping, past EOF. */
	return fsverity_active(inode) &&
	       index < DIV_ROUND_UP_ULL(i_size_read(inode), PAGE_SIZE);
}

static void
ext4_trace_read_completion(struct bio *bio, int err)
{
	struct page *first_page = bio->bi_io_vec[0].bv_page;

	if (first_page != NULL)
		trace_android_fs_dataread_end(first_page->mapping->host,
					      page_offset(first_page),
					      bio->bi_iter.bi_size);
}

static void ext4_finish_verity_bio(struct bio *bio, int err)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (err || PageError(page)) {
			ClearPageUptodate(page);
			SetPageError(page);
		} else {
			SetPageUptodate(page);
		}
		unlock_page(page);
	}

	kfree(bio->bi_private);
	bio_put(bio);
}

static void ext4_verify_read_work(struct work_struct *work)
{
	struct ext4_read_ctx *ctx =
		container_of(work, struct ext4_read_ctx, verify_work);

	fsverity_verify_bio(ctx->bio);
	ext4_finish_verity_bio(ctx->bio, 0);
}

static void ext4_decrypt_read_work(struct work_struct *work)
{
	struct ext4_read_ctx *ctx =
		container_of(work, struct ext4_read_ctx, decrypt_work);

	fscrypt_decrypt_bio(ctx->bio);
	/*
	 * Verify plaintext on a different workqueue. Verification can wait
	 * for reads of Merkle tree blocks that also need decryption.
	 */
	fsverity_enqueue_verify_work(&ctx->verify_work);
}

static void ext4_verity_end_io(struct bio *bio, int err)
{
	struct ext4_read_ctx *ctx = bio->bi_private;

	if (trace_android_fs_dataread_start_enabled())
		ext4_trace_read_completion(bio, err);

	if (err)
		ext4_finish_verity_bio(bio, err);
	else if (ext4_encrypted_inode(bio->bi_io_vec[0].bv_page->mapping->host))
		fscrypt_enqueue_decrypt_work(&ctx->decrypt_work);
	else
		fsverity_enqueue_verify_work(&ctx->verify_work);
}

static int ext4_set_verity_read_ctx(struct bio *bio)
{
	struct ext4_read_ctx *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_NOFS);
	if (!ctx)
		return -ENOMEM;

	ctx->bio = bio;
	INIT_WORK(&ctx->decrypt_work, ext4_decrypt_read_work);
	INIT_WORK(&ctx->verify_work, ext4_verify_read_work);
	bio->bi_private = ctx;
	return 0;
}

static void mpage_end_io(struct bio *bio, int err)
{
	struct bio_vec *bv;
	int i;

	if (trace_android_fs_dataread_start_enabled())
		ext4_trace_read_completion(bio, err);

	if (bio->bi_private) {
		struct fscrypt_ctx *ctx = bio->bi_private;

		if (err) {
			fscrypt_release_ctx(ctx);
		} else {
			fscrypt_enqueue_decrypt_bio(ctx, bio);
			return;
		}
	}
	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

static void
ext4_submit_bio_read(struct bio *bio)
{
	if (trace_android_fs_dataread_start_enabled()) {
		struct page *first_page = bio->bi_io_vec[0].bv_page;

		if (first_page != NULL) {
			char *path, pathbuf[MAX_TRACE_PATHBUF_LEN];

			path = android_fstrace_get_pathname(pathbuf,
						    MAX_TRACE_PATHBUF_LEN,
						    first_page->mapping->host);
			trace_android_fs_dataread_start(
				first_page->mapping->host,
				page_offset(first_page),
				bio->bi_iter.bi_size,
				current->pid,
				path,
				current->comm);
		}
	}
	submit_bio(READ, bio);
}

int ext4_mpage_readpages(struct address_space *mapping,
			 struct list_head *pages, struct page *page,
			 unsigned nr_pages)
{
	struct bio *bio = NULL;
	bool bio_verify = false;
	unsigned page_idx;
	sector_t last_block_in_bio = 0;

	struct inode *inode = mapping->host;
	bool decrypt = ext4_encrypted_inode(inode) && S_ISREG(inode->i_mode);
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	struct block_device *bdev = inode->i_sb->s_bdev;
	int length;
	unsigned relative_block = 0;
	loff_t read_limit = i_size_read(inode);
	struct ext4_map_blocks map;

	if (IS_VERITY(inode) || ext4_verity_in_progress(inode))
		read_limit = inode->i_sb->s_maxbytes;

	map.m_pblk = 0;
	map.m_lblk = 0;
	map.m_len = 0;
	map.m_flags = 0;

	for (page_idx = 0; nr_pages; page_idx++, nr_pages--) {
		bool verify;
		int fully_mapped = 1;
		unsigned first_hole = blocks_per_page;

		prefetchw(&page->flags);
		if (pages) {
			page = list_entry(pages->prev, struct page, lru);
			list_del(&page->lru);
			if (add_to_page_cache_lru(page, mapping,
						  page->index, GFP_KERNEL))
				goto next_page;
		}

		verify = ext4_page_needs_verity(inode, page->index);
		if (page_has_buffers(page) &&
		    (!(IS_VERITY(inode) || ext4_verity_in_progress(inode)) ||
		     !try_to_free_buffers(page)))
			goto confused;

		if (verify)
			ClearPageError(page);

		block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);
		last_block = block_in_file + nr_pages * blocks_per_page;
		last_block_in_file = (read_limit + blocksize - 1) >> blkbits;
		if (last_block > last_block_in_file)
			last_block = last_block_in_file;
		page_block = 0;

		/*
		 * Map blocks using the previous result first.
		 */
		if ((map.m_flags & EXT4_MAP_MAPPED) &&
		    block_in_file > map.m_lblk &&
		    block_in_file < (map.m_lblk + map.m_len)) {
			unsigned map_offset = block_in_file - map.m_lblk;
			unsigned last = map.m_len - map_offset;

			for (relative_block = 0; ; relative_block++) {
				if (relative_block == last) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				}
				if (page_block == blocks_per_page)
					break;
				blocks[page_block] = map.m_pblk + map_offset +
					relative_block;
				page_block++;
				block_in_file++;
			}
		}

		/*
		 * Then do more ext4_map_blocks() calls until we are
		 * done with this page.
		 */
		while (page_block < blocks_per_page) {
			if (block_in_file < last_block) {
				map.m_lblk = block_in_file;
				map.m_len = last_block - block_in_file;

				if (ext4_map_blocks(NULL, inode, &map, 0) < 0) {
					goto set_error_page;
				}
			} else {
				map.m_flags = 0;
			}
			if ((map.m_flags & EXT4_MAP_MAPPED) == 0) {
				fully_mapped = 0;
				if (first_hole == blocks_per_page)
					first_hole = page_block;
				page_block++;
				block_in_file++;
				continue;
			}
			if (first_hole != blocks_per_page)
				goto confused;		/* hole -> non-hole */

			/* Contiguous blocks? */
			if (page_block && blocks[page_block-1] != map.m_pblk-1)
				goto confused;
			for (relative_block = 0; ; relative_block++) {
				if (relative_block == map.m_len) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				} else if (page_block == blocks_per_page)
					break;
				blocks[page_block] = map.m_pblk+relative_block;
				page_block++;
				block_in_file++;
			}
		}
		if (first_hole != blocks_per_page) {
			zero_user_segment(page, first_hole << blkbits,
					  PAGE_CACHE_SIZE);
			if (first_hole == 0) {
				if (verify) {
					if (bio) {
						ext4_submit_bio_read(bio);
						bio = NULL;
					}
					if (!fsverity_verify_page(page))
						goto set_error_page;
				}
				SetPageUptodate(page);
				unlock_page(page);
				goto next_page;
			}
		} else if (fully_mapped) {
			SetPageMappedToDisk(page);
		}
		if (!verify && fully_mapped && blocks_per_page == 1 &&
		    !PageUptodate(page) && cleancache_get_page(page) == 0) {
			SetPageUptodate(page);
			goto confused;
		}

		/*
		 * This page will go to BIO.  Do we need to send this
		 * BIO off first?
		 */
		/* A verification worker must never wait on its own bio. */
		if (bio && (last_block_in_bio != blocks[0] - 1 ||
			    bio_verify != verify)) {
		submit_and_realloc:
			ext4_submit_bio_read(bio);
			bio = NULL;
		}
		if (bio == NULL) {
			bio = bio_alloc(GFP_NOFS,
				min_t(int, nr_pages, bio_get_nr_vecs(bdev)));
			if (!bio)
				goto set_error_page;
			if (verify) {
				if (ext4_set_verity_read_ctx(bio))
					goto free_bio;
				bio->bi_end_io = ext4_verity_end_io;
			} else {
				if (decrypt) {
					struct fscrypt_ctx *ctx;

					ctx = fscrypt_get_ctx(inode, GFP_NOFS);
					if (IS_ERR(ctx))
						goto free_bio;
					bio->bi_private = ctx;
				}
				bio->bi_end_io = mpage_end_io;
			}
			bio_verify = verify;
			bio->bi_bdev = bdev;
			bio->bi_iter.bi_sector = blocks[0] << (blkbits - 9);
		}

		length = first_hole << blkbits;
		if (bio_add_page(bio, page, length, 0) < length)
			goto submit_and_realloc;

		if (((map.m_flags & EXT4_MAP_BOUNDARY) &&
		     (relative_block == map.m_len)) ||
		    (first_hole != blocks_per_page)) {
			ext4_submit_bio_read(bio);
			bio = NULL;
		} else
			last_block_in_bio = blocks[blocks_per_page - 1];
		goto next_page;
	free_bio:
		bio_put(bio);
		bio = NULL;
		goto set_error_page;
	confused:
		if (bio) {
			ext4_submit_bio_read(bio);
			bio = NULL;
		}
		/*
		 * Verity uses one filesystem block per page. Don't pass
		 * a verity page to the buffer-head path, which completes
		 * reads without verification and stops at i_size.
		 */
		if (IS_VERITY(inode) || ext4_verity_in_progress(inode))
			goto set_error_page;
		if (!PageUptodate(page))
			block_read_full_page(page, ext4_get_block);
		else
			unlock_page(page);
		goto next_page;
	set_error_page:
		ClearPageUptodate(page);
		SetPageError(page);
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
		unlock_page(page);
	next_page:
		if (pages)
			page_cache_release(page);
	}
	BUG_ON(pages && !list_empty(pages));
	if (bio)
		ext4_submit_bio_read(bio);
	return 0;
}
