/*
 *	Network shim interface for protocols that live below L3 but above L2
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Authors:	James R. Leu <jleu@mindspring.com>
 *              Igor Maravic <igorm@etf.rs>
 *
 */
#ifndef _NET_SHIM_H
#define _NET_SHIM_H

#include <net/dst.h>
#include <linux/list.h>
#include <linux/shim.h>

#define SHIMNAMSIZ 4

struct shim_blk;

struct shim {
	int			(*build)(struct shim_blk *, struct dst_entry *);
	char		name[SHIMNAMSIZ + 1];
};

struct shim_blk {
	struct shim *shim;
	short datalen;
	char data[0];
};

extern struct shim mpls_uc_shim;

/**
 *	shim_build_blk - allocate memory for a shim blk and fill it with data
 *			 from rta
 *	@rta: data describing shim
 *
 *	Allocate a shim blk which links directly to the shim
 *	proto for use by the forwarding plane
 */
static inline struct shim_blk *shim_build_blk(struct rtshim* rta)
{
	struct shim_blk *sblk;
	
	if (!rta)
		return NULL;
		
	sblk = kzalloc(sizeof(*sblk) + rta->datalen, GFP_ATOMIC);
	if (sblk) {
		sblk->shim = &mpls_uc_shim;
		BUG_ON(!sblk->shim);
		sblk->datalen = rta->datalen;
		memcpy(sblk->data, rta->data, rta->datalen);
			
		return sblk;
	}	
	return NULL;
}

/**
 *	shim_destroy_blk - free memory a refcnts used bt a shim blk
 *	@sblk: shim blk
 *
 *	Release ref to shim proto and free memory
 */
static inline void shim_destroy_blk(struct shim_blk *sblk)
{		
	kfree(sblk);	
}

/**
 *	shim_unbuild_blk - copy data from various parts of a shim block
 *			   into a form which can be used by netlink
 *	@rta: contigous destination memory of size rtshim + datalen
 *	@sblk: active shim blk
 *
 *	Search the kernels list of shim handlers looking for
 *	a handler with this specific name
 */
static inline void shim_unbuild_blk(struct rtshim* rta, struct shim_blk *sblk)
{	
	rta->datalen = sblk->datalen;
	memcpy(rta->data, sblk->data, sblk->datalen);
}

/**
 *	shim_cfg_blk_cmp - compare config info with an active shim blk
 *	@a: config data
 *	@b: shim blk
 *
 *	Used for comparing new config data with existing shim blks
 */
static inline int shim_cfg_blk_cmp(struct rtshim *a, struct shim_blk *b)
{
	int n = 0;
	
	if (a && b) {
		n = memcmp(a->data, b->data, a->datalen);
	} else {
		if (a) n = 1;
		if (b) n = -1;
	}	
	return n;
}

/**
 *	shim_blk_cmp - compare two active shim blks
 *	@a: shim blk
 *	@b: shim blk
 *
 *	Used for comparing two existing shim blks
 */
static inline int shim_blk_cmp(struct shim_blk *a, struct shim_blk *b)
{
	int n = 0;
	
	if (a && b) {
		n = memcmp(a->data, b->data, a->datalen);
	} else {
		if (a) n = 1;
		if (b) n = -1;
	}	
	return n;
}

#endif
