/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 *      It implements:
 *      -add/get/del/flush for the out label tree
 *      -binding of FEC to out label
 *
 * Authors:
 *      James Leu        <jleu@mindspring.com>
 *      Ramon Casellas   <casellas@infres.enst.fr>
 *      Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas <casellas@infres.enst.fr>
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 ****************************************************************************/

#include <net/mpls.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <net/dst.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>		/* must be before route.h */
#include <linux/ip.h>		/* must be before route.h */
#include <linux/inetdevice.h>	/* must be before route.h */
#include <net/route.h>		/* must be before ip_fib.h */
#include <net/ip_fib.h>
#include <linux/genetlink.h>
#include <net/net_namespace.h>

/**
 * mpls_nhlfe_tree: Radix Tree to hold NHLFE objects
 **/
RADIX_TREE(mpls_nhlfe_tree, GFP_ATOMIC);

/**
 * mpls_nhlfe_lock: lock for tree access.
 **/
DEFINE_SPINLOCK(mpls_nhlfe_lock);

LIST_HEAD(mpls_nhlfe_list);

/* forward declarations */
static struct dst_entry *nhlfe_dst_check(struct dst_entry *dst, u32 cookie);
static unsigned int      nhlfe_dst_default_advmss(const struct dst_entry *dst);
static unsigned int      nhlfe_dst_mtu(const struct dst_entry *dst);
static void              nhlfe_dst_destroy(struct dst_entry *dst);
static struct dst_entry *nhlfe_dst_negative_advice(struct dst_entry *dst);
static void              nhlfe_dst_link_failure(struct sk_buff *skb);
static void              nhlfe_dst_update_pmtu(struct dst_entry *dst, u32 mtu);
static int               nhlfe_dst_gc(struct dst_ops *ops);
static struct neighbour *nhlfe_dst_neigh_lookup(
						const struct dst_entry *dst,
						const void *daddr);

static struct dst_ops nhlfe_dst_ops __read_mostly = {
	.family	=  AF_MPLS,
	.protocol = cpu_to_be16(ETH_P_MPLS_UC),
	.gc	= nhlfe_dst_gc,
	.check = nhlfe_dst_check,
	.default_advmss = nhlfe_dst_default_advmss,
	.mtu =  nhlfe_dst_mtu,
	.cow_metrics = dst_cow_metrics_generic,
	.destroy = nhlfe_dst_destroy,
	.negative_advice = nhlfe_dst_negative_advice,
	.link_failure = nhlfe_dst_link_failure,
	.update_pmtu = nhlfe_dst_update_pmtu,
	.neigh_lookup = nhlfe_dst_neigh_lookup,
};

static struct dst_entry *nhlfe_dst_check(struct dst_entry *dst, u32 cookie)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return NULL;
}

static unsigned int nhlfe_dst_default_advmss(const struct dst_entry *dst)
{
	unsigned int advmss = dst_metric_raw(dst, RTAX_ADVMSS);
	MPLS_ENTER;
	MPLS_DEBUG("NHLFE default advmss %u\n", advmss);
	MPLS_EXIT;
	return advmss;
}

static unsigned int nhlfe_dst_mtu(const struct dst_entry *dst)
{
	unsigned int mtu = dst_metric_raw(dst, RTAX_MTU);
	MPLS_ENTER;
	if (mtu)
		goto out;
	BUG_ON(!dst->dev);
	mtu = dst->dev->mtu;
out:
	MPLS_DEBUG("NHLFE default mtu %u\n", mtu);
	MPLS_EXIT;
	return mtu;
}

/**
 *      nhlfe_dst_destroy - cleanup for a MPLS dst_entry
 *      @dst: 'this', object that is being destroyed.
 *
 *      The object ends life here. Perform the necessary
 *      clean up.
 **/

static void nhlfe_dst_destroy(struct dst_entry *dst)
{
	struct mpls_nhlfe *nhlfe = container_of(dst,
			struct mpls_nhlfe, dst);
	MPLS_ENTER;

	mpls_proto_release(nhlfe->nhlfe_proto);
	dst_destroy_metrics_generic(dst);
	MPLS_EXIT;
}

static struct dst_entry *nhlfe_dst_negative_advice(struct dst_entry *dst)
{
	struct mpls_nhlfe *nhlfe = (struct mpls_nhlfe *)dst;
	struct dst_entry *ret = dst;

	MPLS_ENTER;
	if (nhlfe) {
		if (dst->obsolete > 0 || nhlfe->dst.expires) {
			mpls_nhlfe_release(nhlfe);
			ret = NULL;
		}
	}
	MPLS_EXIT;
	return ret;
}

static void nhlfe_dst_link_failure(struct sk_buff *skb)
{
	struct mpls_nhlfe *nhlfe;
	MPLS_ENTER;
	/* icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);*/
	nhlfe = (struct mpls_nhlfe *)skb_dst(skb);
	if (nhlfe)
		dst_set_expires(&nhlfe->dst, 0);
	MPLS_EXIT;
}

static int mpls_dst_mtu_expires = 10 * 60 * HZ;
static int mpls_dst_min_pmtu = 512 + 20 + 20 + 4;

static void nhlfe_dst_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	MPLS_ENTER;
	if (dst_mtu(dst) > mtu &&
			mtu >= 68 &&
			!(dst_metric_locked(dst, RTAX_MTU))) {
		if (mtu < mpls_dst_min_pmtu) {
			u32 lock = dst_metric(dst, RTAX_LOCK);
			mtu = mpls_dst_min_pmtu;
			dst_metric_set(dst, RTAX_LOCK, lock | (1 << RTAX_MTU));
		}
		dst_metric_set(dst, RTAX_MTU, mtu);
		dst_set_expires(dst, mpls_dst_mtu_expires);
	}
	MPLS_EXIT;
}

static struct neighbour *nhlfe_dst_neigh_lookup(
			const struct dst_entry *dst,
			const void *daddr)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return NULL;
}

static int nhlfe_dst_gc(struct dst_ops *ops)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return 0;
}

/**
 *      nhlfe_dst_alloc - construct a mpls_nhlfe entry.
 *
 **/

struct mpls_nhlfe *nhlfe_dst_alloc(unsigned int key)
{
	struct mpls_nhlfe *nhlfe;

	MPLS_ENTER;

	nhlfe = dst_alloc(&nhlfe_dst_ops, NULL, 1, 0, 0);
	if (unlikely(!nhlfe)) {
		MPLS_EXIT;
		return NULL;
	}

	nhlfe->dst.input = mpls_switch;
	nhlfe->dst.output = mpls_output;

	INIT_LIST_HEAD(&nhlfe->list_in);
	INIT_LIST_HEAD(&nhlfe->dev_entry);
	INIT_LIST_HEAD(&nhlfe->global);

	nhlfe->nhlfe_instr = NULL;
	nhlfe->nhlfe_proto = NULL;
	nhlfe->nhlfe_propagate_ttl = 1;
	nhlfe->nhlfe_age = jiffies;
	nhlfe->nhlfe_key = key;
	dst_metric_set(&nhlfe->dst, RTAX_MTU, MPLS_INVALID_MTU);
	nhlfe->nhlfe_owner = RTPROT_UNSPEC;

	MPLS_EXIT;
	return nhlfe;

}

/**
 * mpls_insert_nhlfe - Inserts the given NHLFE object in the MPLS
 *   Output Information Radix Tree using the given key.
 * @key : key to use
 * @nhlfe : nhlfe object.
 *
 * Returns 0 on success, or:
 *     -ENOMEM : unable to allocate node in the radix tree.
 **/

int mpls_insert_nhlfe(unsigned int key, struct mpls_nhlfe *nhlfe)
{
	int retval = 0;
	MPLS_ENTER;
	spin_lock_bh(&mpls_nhlfe_lock);

	retval = radix_tree_insert(&mpls_nhlfe_tree, key, nhlfe);
	if (unlikely(retval)) {
		retval = -ENOMEM;
		goto out;
	}

	list_add_rcu(&nhlfe->global, &mpls_nhlfe_list);

out:
	spin_unlock_bh(&mpls_nhlfe_lock);
	MPLS_EXIT;
	return retval;
}


/**
 *	mpls_remove_nhlfe - Remove the node given the key from the MPLS
 *	Output Information Radix Tree.
 *	@key : key to use
 *
 *	This function deletes the NHLFE object from the Radix Tree, but please
 *	also note that the object is not freed, and that the caller is
 *	responsible for	decreasing the refcount if necessary.
 **/

struct mpls_nhlfe *mpls_remove_nhlfe(unsigned int key)
{
	struct mpls_nhlfe *nhlfe;

	MPLS_ENTER;
	spin_lock_bh(&mpls_nhlfe_lock);

	nhlfe = radix_tree_delete(&mpls_nhlfe_tree, key);
	if (!nhlfe) {
		MPLS_DEBUG("NHLFE node with key %u not found.\n", key);
		goto out;
	}

	list_del_rcu(&nhlfe->global);

out:
	spin_unlock_bh(&mpls_nhlfe_lock);
	MPLS_EXIT;
	return nhlfe;
}


/**
 *	mpls_get_nhlfe - Get a reference to a NHLFE object.
 *	@key : key to look for in the NHLFE Radix Tree.
 *
 *	This function can be used to get a reference to a NHLFE object
 *	given a key.
 *	Returns a pointer to the NHLFE object, NULL on error.
 *
 *	Remark: this function increases the refcount of the NHLFE object,
 *	since it calls to mpls_nhlfe_hold. Caller is responsible to release
 *	the object when it is no longer needed (by using "mpls_nhlfe_release").
 **/

inline struct mpls_nhlfe *mpls_get_nhlfe(unsigned int key)
{
	struct mpls_nhlfe *nhlfe = NULL;
	MPLS_ENTER;
	rcu_read_lock();
	nhlfe = radix_tree_lookup(&mpls_nhlfe_tree, key);
	smp_read_barrier_depends();
	if (likely(nhlfe))
		mpls_nhlfe_hold(nhlfe);

	rcu_read_unlock();

	MPLS_EXIT;
	return nhlfe;
}
EXPORT_SYMBOL(mpls_get_nhlfe);

/**
 *	mpls_destroy_nhlfe_instrs - Destroy NHLFE instruction list.
 *	@nhlfe:	NHLFE object
 *
 *      This function completely destroys the instruction list for this
 *      NHLFE object.
 *
 *      nhlfe_instr is set to NULL.
 **/

void mpls_destroy_nhlfe_instrs(struct mpls_nhlfe *nhlfe)
{
	MPLS_ENTER;
	if (nhlfe->nhlfe_instr) {
		mpls_instrs_free(nhlfe->nhlfe_instr);
		nhlfe->nhlfe_instr = NULL;
	}
	MPLS_EXIT;
}

int mpls_nhlfe_set_instrs(struct mpls_out_label_req *mol,
			struct mpls_instr_elem *mie,
			int length)
{
	struct mpls_instr_req *instr_old = NULL;
	int no_instr_old = 0;
	int retval = 0;
	struct mpls_instr *instr = NULL;
	struct mpls_nhlfe *nhlfe = mpls_get_nhlfe_label(mol);
	MPLS_ENTER;

	if (!nhlfe)
		return -EINVAL;

	/* Commit the new ones */
	if (nhlfe->nhlfe_instr) {
		no_instr_old = mpls_no_instrs(nhlfe->nhlfe_instr);
		instr_old = kmalloc(sizeof(*instr_old) +
			no_instr_old * sizeof(struct mpls_instr_elem),
			GFP_ATOMIC);
		if (unlikely(!instr_old)) {
			mpls_nhlfe_release(nhlfe);
			MPLS_EXIT;
			return -EINVAL;
		}
		mpls_instrs_unbuild(nhlfe->nhlfe_instr, instr_old);
		mpls_instrs_free(nhlfe->nhlfe_instr);
	}

	/* Build temporary opcode set from mie */
	if (!mpls_instrs_build(mie, &instr,
			length, MPLS_OUT, nhlfe)) {
		/*replace with old instructions in case there were an error*/
		if (instr_old)
			mpls_instrs_build(instr_old->mir_instr, &instr,
				instr_old->mir_instr_length,
				MPLS_OUT, nhlfe);

		MPLS_DEBUG("Returns -1\n");
		retval = -EINVAL;
	}
	nhlfe->nhlfe_instr = instr;
	mpls_nhlfe_release(nhlfe);
	kfree(instr_old);
	MPLS_EXIT;
	return retval;
}

/**
 *	mpls_set_out_label_propagate_ttl - set the propagate_ttl status
 *	@mol: request with the NHLFE key and desired propagate_ttl status
 *
 *	Update the NHLFE object (using the key in the request) with the
 *	propagate_ttl from the request
 **/

int mpls_set_out_label_propagate_ttl(struct mpls_out_label_req *mol)
{
	unsigned int key = mpls_label2key(0, &mol->mol_label);
	struct mpls_nhlfe *nhlfe = mpls_get_nhlfe(key);
	MPLS_ENTER;
	if (!nhlfe) {
		MPLS_EXIT;
		return -ESRCH;
	}

	nhlfe->nhlfe_propagate_ttl = mol->mol_propagate_ttl;

	mpls_nhlfe_release(nhlfe);
	MPLS_EXIT;
	return 0;
}

/*
 * mpls_get_nhlfe_label - returns existing nhlfe,
 * if there is no ilm returns NULL
 */
struct mpls_nhlfe *mpls_get_nhlfe_label(struct mpls_out_label_req *mol)
{
	unsigned int key = mpls_label2key(0, &mol->mol_label);
	struct mpls_nhlfe *nhlfe = mpls_get_nhlfe(key);
	MPLS_ENTER;
	MPLS_EXIT;
	return nhlfe;
}

/**
 *	mpls_add_out_label - Add a new outgoing label to the database.
 *	@out:request containing the label
 *
 *	Adds a new outgoing label to the outgoing tree. We first
 *  check that the entry does not exist,
 *	allocate a new NHLFE object and reset it.
 **/

struct mpls_nhlfe *mpls_add_out_label(struct mpls_out_label_req *out)
{
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key = 0;

	MPLS_ENTER;
	BUG_ON(!out);
	BUG_ON(out->mol_label.ml_type != MPLS_LABEL_KEY);
	/* Create a new key */
	key = out->mol_label.u.ml_key;
	if (!key)
		return ERR_PTR(-ENOMEM);
	/*
	 * Check if the NHLFE is already in the tree.
	 * It should not exist.
	 */
	nhlfe = mpls_get_nhlfe(key);

	if (unlikely(nhlfe)) {
		MPLS_DEBUG("Node %u already exists in radix tree\n", key);

		/* release the refcnt held by mpls_get_nhlfe */
		mpls_nhlfe_release(nhlfe);
		MPLS_EXIT;
		return ERR_PTR(-EEXIST);
	}

	/*
	 * Allocate a new Output Information/Label,
	 */
	nhlfe = nhlfe_dst_alloc(key);
	if (unlikely(!nhlfe))
		return ERR_PTR(-ENOMEM);

	nhlfe->nhlfe_owner = out->mol_owner;

	/* Insert into NHLFE tree */
	if (unlikely(mpls_insert_nhlfe(key, nhlfe))) {
		mpls_nhlfe_release(nhlfe);
		MPLS_EXIT;
		return ERR_PTR(-ENOMEM);
	}

	MPLS_EXIT;
	return nhlfe;
}

/*
 * mpls_nhlfe_del_list_in - changes FWD to PEEK in all ilms in the list
 * @nhlfe:  nhlfe holding the list_in
 *
 */
static void mpls_nhlfe_del_list_in(struct mpls_nhlfe *nhlfe)
{
	struct list_head *nhlfe_in = &nhlfe->list_in;
	struct list_head *pos = NULL;
	struct list_head *tmp = NULL;
	struct mpls_ilm *holder;
	MPLS_ENTER;
	/* Iterate all ILM objects present in the list_in
	 * of the nhlfe.
	 */
	list_for_each_safe(pos, tmp, nhlfe_in) {
		struct mpls_instr *mi  = NULL;

		holder = list_entry(pos, struct mpls_ilm, nhlfe_entry);

		mpls_ilm_hold(holder);

		/*detach in to out */
		/* Check that there is an instruction set! */
		if (unlikely(!holder->ilm_instr)) {
			MPLS_DEBUG("No instruction Set!");
			goto del;
		}

		/* Fetch the last instr, make sure it is FWD*/
		mi = mpls_instr_getlast(holder->ilm_instr);

		if (!mi || mi->mi_opcode != MPLS_OP_FWD) {
			MPLS_DEBUG("opcode FWD not found!\n");
			goto del;
		}

		/* Make sure it is the good nhlfe */
		if (!mi->mi_data || nhlfe->nhlfe_key !=
			_mpls_as_nhlfe(mi->mi_data)->nhlfe_key) {
			/* Do not release the NHLFE, it was invalid */
			MPLS_DEBUG("Invalid NHLFE  %u\n",
				_mpls_as_nhlfe(mi->mi_data)->nhlfe_key);
			goto del;
		}

		/* The new last opcode for this ILM is now drop */
		mi->mi_opcode = MPLS_OP_DROP;
		/* With no data */
		mi->mi_data = NULL;
del:
		/* Even if there are errors release nhlfe -
		 * if __refcnt is less then 0 we will have warning,
		 * but at least nhlfe is going to be deleted
		 */
		mpls_nhlfe_release(nhlfe);
		mpls_ilm_release(holder);
		list_del(pos);
	}
	MPLS_EXIT;
}

/**
 *	mpls_del_nhlfe - Remove a NHLFE from the tree
 *	@nhlfe: nhlfe entry to delete
 **/
int mpls_del_nhlfe(struct mpls_nhlfe *nhlfe, int seq, int pid)
{
	int retval;

	MPLS_ENTER;

	BUG_ON(!nhlfe);

	/*
	 * This code starts the process of removing a NHLFE from the
	 * system.  The first thing we we do it remove it from the tree
	 * so no one else can get a reference to it.  Then we notify the
	 * higher layer protocols that they should give up thier references
	 * soon (does not need to happen immediatly, the dst system allows
	 * for this.
	 */

	/* remove the NHLFE from the tree */
	mpls_remove_nhlfe(nhlfe->nhlfe_key);

	/*
	 * Clean ilms holding this nhlfe
	 */
	mpls_nhlfe_del_list_in(nhlfe);

	/* From now on, drop packets */
	nhlfe->dst.output = dst_discard;

	retval = mpls_nhlfe_event(MPLS_GRP_NHLFE_NAME,
		MPLS_CMD_DELNHLFE, nhlfe, seq, pid);

	/* Destroy the instructions on this NHLFE, so as to no longer
	 * hold refs to interfaces and other NHLFE's. */
	mpls_destroy_nhlfe_instrs(nhlfe);

	/* schedule all higher layer protocols to give up their references */
	mpls_proto_cache_flush_all(&init_net);

	WARN_ON(atomic_read(&nhlfe->dst.__refcnt) != 1);
	/* Let the dst system know we're done with this NHLFE */
	mpls_nhlfe_drop(nhlfe);

	MPLS_EXIT;
	return retval;
}

/**
 *	mpls_del_out_label - Remove a NHLFE from the tree
 *	@out: request.
 **/

int mpls_del_out_label(struct mpls_out_label_req *out, int seq, int pid)
{
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key;
	int retval;

	MPLS_ENTER;

	key = mpls_label2key(0, &out->mol_label);

	nhlfe = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("Node %u was not in tree\n", key);
		MPLS_EXIT;
		return  -ESRCH;
	}

	/*
	 * This code starts the process of removing a NHLFE from the
	 * system.  The first thing we we do it remove it from the tree
	 * so no one else can get a reference to it.  Then we notify the
	 * higher layer protocols that they should give up thier references
	 * soon (does not need to happen immediatly, the dst system allows
	 * for this.
	 */

	/*
	 * Clean ilms holding this nhlfe
	 */
	mpls_nhlfe_del_list_in(nhlfe);

	/* remove the NHLFE from the tree */
	mpls_remove_nhlfe(nhlfe->nhlfe_key);

	/* Remove reference taken on mpls_get_nhlfe() */
	mpls_nhlfe_release(nhlfe);

	/* From now on, drop packets */
	nhlfe->dst.input = nhlfe->dst.output = dst_discard;

	retval = mpls_nhlfe_event(MPLS_GRP_NHLFE_NAME,
		MPLS_CMD_DELNHLFE, nhlfe, seq, pid);

	/* Destroy the instructions on this NHLFE, so as to no longer
	 * hold refs to interfaces and other NHLFE's. */
	mpls_destroy_nhlfe_instrs(nhlfe);

	/* schedule all higher layer protocols to give up their references */
	mpls_proto_cache_flush_all(&init_net);

	WARN_ON(atomic_read(&nhlfe->dst.__refcnt) != 1);
	/* Let the dst system know we're done with this NHLFE */
	mpls_nhlfe_drop(nhlfe);

	MPLS_EXIT;
	return retval;
}

/**
 * mpls_set_out_label_mtu - change the MTU for this NHLFE.
 * @out: Request containing the new MTU.
 *
 * Update the NHLFE object (using the key in the request) with the passed
 * MTU.
 **/

int mpls_set_out_label_mtu(struct mpls_out_label_req *out)
{
	struct mpls_nhlfe *nhlfe = NULL;
	int retval = 0;
	unsigned int key;

	BUG_ON(!out);
	MPLS_ENTER;

	key = out->mol_label.u.ml_key;
	nhlfe = mpls_get_nhlfe(key);

	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("Node %u does not exists in radix tree\n", key);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* Update the MTU if possible */
	if (nhlfe->nhlfe_mtu_limit >= out->mol_mtu) {
		dst_metric_set(&nhlfe->dst, RTAX_MTU, out->mol_mtu);
	} else {
		MPLS_DEBUG("MTU is larger than lower layer (%d > %d)\n",
				out->mol_mtu, nhlfe->nhlfe_mtu_limit);
		/* release the refcnt held by mpls_get_nhlfe */
		mpls_nhlfe_release(nhlfe);
		MPLS_EXIT;
		return -EINVAL;
	}

	/* release the refcnt held by mpls_get_nhlfe */
	mpls_nhlfe_release(nhlfe);

	/* force the layer 3 protocols to re-find and dsts (NHLFEs),
	 * thus picking up the new MTU
	 */
	mpls_proto_cache_flush_all(&init_net);

	MPLS_EXIT;
	return retval;
}

int __init mpls_nhlfe_init(void)
{
	MPLS_ENTER;
	if (dst_entries_init(&nhlfe_dst_ops) < 0)
		panic("MPLS: failed to allocate nhlfe_dst_ops counter\n");

	nhlfe_dst_ops.kmem_cachep = kmem_cache_create("nhlfe_dst_cache",
		sizeof(struct mpls_nhlfe), 0, SLAB_HWCACHE_ALIGN, NULL);

	if (!nhlfe_dst_ops.kmem_cachep) {
		printk(KERN_ERR "MPLS: failed to alloc nhlfe_dst_cache\n");
		dst_entries_destroy(&nhlfe_dst_ops);
		MPLS_EXIT;
		return -ENOMEM;
	}
	MPLS_EXIT;
	return 0;
}

void mpls_nhlfe_exit(void)
{
	MPLS_ENTER;
	if (nhlfe_dst_ops.kmem_cachep)
		kmem_cache_destroy(nhlfe_dst_ops.kmem_cachep);

	dst_entries_destroy(&nhlfe_dst_ops);
	MPLS_EXIT;
}
