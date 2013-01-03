/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 *      Hash code is reused from Jozsef Kadlecsik's ip_set_ahash.h
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 * ****************************************************************************/

#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/in.h>		/* must be before route.h */
#include <linux/ip.h>		/* must be before route.h */
#include <linux/inetdevice.h>	/* must be before route.h */
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/mpls.h>
#include "mpls_cmd.h"

const struct {
	struct nhlfe nhlfe;
	struct __instr instr[2];
} pop_peek_nhlfe = {
	.nhlfe = {
		.no_instr = 2,
		.no_push = 0,
		.no_pop = 1,
	},
	.instr = {
		{
			.data = 1,
			.cmd = MPLS_ATTR_POP,
		},
		{
			.data = 0,
			.cmd = MPLS_ATTR_PEEK,
		},
	},
};

const static struct ilm
ipv4_explicit_null =
{
		.key = {
			.label = 0x0,
			.owner = RTPROT_BOOT,
			.tc = 0,
		},
		.nhlfe = (struct nhlfe *)&pop_peek_nhlfe.nhlfe,
};

const static struct ilm
ipv6_explicit_null =
{
		.key = {
			.label = 0x2,
			.owner = RTPROT_BOOT,
			.tc = 0,
		},
		.nhlfe = (struct nhlfe *)&pop_peek_nhlfe.nhlfe,
};

const struct ilm *
mpls_reserved[MAX_RES_LABEL] = {
	&ipv4_explicit_null,	/* IPv4 EXPLICIT NULL */
	NULL,			/* ROUTER ALERT - unimplemented */
	&ipv6_explicit_null,	/* IPv6 EXPLICIT NULL */
	NULL,			/* IMPLICIT NULL */
};

#define __is_reserved_label(key) ((key)->label <= MAX_RES_LABEL)

static inline void
__destroy_ilm_instrs(struct ilm *ilm)
{
	__nhlfe_free(ilm->nhlfe);
	rcu_assign_pointer(ilm->nhlfe, NULL);
}

static inline void
ilm_copy(struct ilm *dst, const struct ilm *src)
{
	smp_wmb();
	memcpy(dst, src, sizeof(struct ilm));
}

static inline bool
ilm_key_equal(const struct mpls_key *data,
		    const struct mpls_key *rhs,
		    u32 *multi, bool exact_match)
{
	return data->label == rhs->label &&
		(++*multi) &&
		(data->tc == rhs->tc || (!data->tc && !exact_match));
}

/* Hash implementation */

/* Hashing which uses arrays to resolve clashing. The hash table is resized
 * (doubled) when searching becomes too long.
 * Internally jhash is used with the assumption that the size of the
 * stored data is a multiple of sizeof(u32).
 *
 * Readers and resizing
 *
 * Resizing can be triggered by userspace command only, and those
 * are serialized by the rtnl mutex. Read side must be protected by
 * proper RCU locking.
 */

/* A hash bucket */
struct hbucket {
	struct ilm __rcu *ilm;	/* the array of the values */
	u8 size;		/* size of the array */
	u8 pos;			/* position of the first free entry */
};

/* The hash table: the table size stored here in order to make resizing easy */
struct htable {
	union {
		struct rcu_head rcu;
		struct work_struct work;
	};
	u8 htable_bits;		/* size of hash table == 2^htable_bits */
	struct hbucket bucket[0]; /* hashtable buckets */
};

/* The hash structure */
struct ilm_hash {
	struct htable __rcu *table; /* the hash table */
	u32 elements;		/* current element */
	u32 initval;		/* random jhash init value */
	u8 hash_max;		/* max elements in an array block */
};

static int ilm_net_id __read_mostly;

/* Per-net hash tables */
struct ilm_net {
	struct ilm_hash h;
};

/* Number of elements to store in an initial array block */
#define HASH_INIT_SIZE			4

/* Max number of elements to store in an array block */
#define HASH_MAX_SIZE			(3 * HASH_INIT_SIZE)

/* Max number of elements can be tuned */
#define HASH_MAX(h)			((h)->hash_max)

#define DEFAULT_HASHSIZE		1024

#define HKEY_DATALEN	sizeof(struct mpls_key)

#define HKEY(label, initval, htable_bits)				\
	(jhash2((u32 *)(label), HKEY_DATALEN/sizeof(u32), initval)	\
		& jhash_mask(htable_bits))

/* Get the ith element from the array block n */
#define __hash_data_rtnl(n, i)						\
	((struct ilm *)(rtnl_dereference((n)->ilm) + (i)))

#define __hash_data_rcu(n, i)						\
	((struct ilm *)(rcu_dereference((n)->ilm) + (i)))

#define hbucket(h, i)							\
	(&((h)->bucket[(i)]))

static inline u8
tune_hash_max(u8 curr, u32 multi)
{
	u32 n;

	if (multi < curr)
		return curr;

	n = curr + HASH_INIT_SIZE;
	/* Currently, at listing one hash bucket must fit into a message.
	 * Therefore we have a hard limit here.
	 */
	return n > curr && n <= 64 ? n : curr;
}

#define TUNE_HASH_MAX(h, multi)						\
	((h)->hash_max = tune_hash_max((h)->hash_max, multi))

static struct htable *
__htable_alloc(size_t size)
{
	struct htable *htable = NULL;

	if (size <= PAGE_SIZE)
		htable = kzalloc(size, GFP_KERNEL);
	else
		htable = vzalloc(size);

	return htable;
}

static void __htable_vfree(struct work_struct *arg)
{
	struct htable *htable = container_of(arg, struct htable, work);
	vfree(htable);
}

static void
__htable_free(struct rcu_head *head)
{
	struct htable *htable = container_of(head, struct htable, rcu);
	if (is_vmalloc_addr(htable)) {
		INIT_WORK(&htable->work, __htable_vfree);
		schedule_work(&htable->work);
	} else
		kfree(htable);
}

static inline void
__hbucket_free(struct hbucket *bucket, bool leave_instr)
{
	int j;
	struct hbucket *n = bucket;
	struct ilm *ilm = rtnl_dereference(n->ilm);

	for (j = 0; j < n->size && !leave_instr; j++)
		__destroy_ilm_instrs(ilm);

	if (n->size)
		kfree(ilm);
}

static inline void
__hbucket_free_rcu(struct hbucket *bucket, bool leave_instr)
{
	int j;
	struct hbucket *n = bucket;
	struct ilm *ilm = rtnl_dereference(n->ilm);

	for (j = 0; j < n->size && !leave_instr; j++)
		__destroy_ilm_instrs(ilm);

	if (n->size)
		kfree_rcu(ilm, rcu);
}

static size_t
__htable_size(u8 hbits)
{
	size_t hsize;

	/* We must fit both into u32 in jhash and size_t */
	if (hbits > 31)
		return 0;
	hsize = jhash_size(hbits);
	if ((((size_t)-1) - sizeof(struct htable))/sizeof(struct hbucket)
	    < hsize)
		return 0;

	return hsize * sizeof(struct hbucket) + sizeof(struct htable);
}

/* Compute htable_bits from the user input parameter hashsize */
static u8
__htable_bits(u32 hashsize)
{
	/* Assume that hashsize == 2^htable_bits */
	u8 bits = fls(hashsize - 1);
	if (jhash_size(bits) != hashsize)
		/* Round up to the first 2^n value */
		bits = fls(hashsize);

	return bits;
}

/* Destroy the hashtable part of the set */
static void
__hash_destroy_rcu(struct htable *t, bool leave_instr)
{
	struct hbucket *n;
	u32 i;

	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		__hbucket_free_rcu(n, leave_instr);
	}

	call_rcu(&t->rcu, __htable_free);
}

static void
__hash_destroy(struct htable *t, bool leave_instr)
{
	struct hbucket *n;
	u32 i;

	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		__hbucket_free(n, leave_instr);
	}

	__htable_free(&t->rcu);
}

static inline void
__ilm_array_make_space(struct hbucket *n, int pos)
{
	int i;
	for (i = n->pos - 2; i >= pos; --i)
		ilm_copy(__hash_data_rtnl(n, i + 1), __hash_data_rtnl(n, i));
}

static inline void
__ilm_array_fill_space(struct hbucket *n, int pos)
{
	int i;
	for (i = pos; i < n->pos - 1; ++i)
		ilm_copy(__hash_data_rtnl(n, i), __hash_data_rtnl(n, i + 1));
}

static inline int
__get_pos(struct hbucket *n, const struct mpls_key *key)
{
	int pos;
	const struct mpls_key *o_key;
	for (pos = 0; pos < n->pos - 1; ++pos) {
		o_key = &__hash_data_rtnl(n, pos)->key;
		if (o_key->label < key->label)
			goto out;
		else if (o_key->label == key->label &&
				o_key->tc < key->tc)
			goto out;
	}

out:
	__ilm_array_make_space(n, pos);
	return pos;
}

/* Add an element to the hash table when resizing the set:
 * we spare the maintenance of the internal counters. */
static struct ilm*
__ilm_add(struct hbucket *n, const struct mpls_key *key, u8 hash_max)
{
	struct ilm *ilm;
	int pos;

	if (n->pos >= n->size) {
		struct ilm *tmp;

		if (n->size >= hash_max)
			/* Trigger rehashing */
			return ERR_PTR(-EAGAIN);

		tmp = kzalloc((n->size + HASH_INIT_SIZE)
			      * sizeof(struct ilm), GFP_KERNEL);
		if (unlikely(!tmp))
			return ERR_PTR(-ENOMEM);

		if (n->size) {
			memcpy(tmp, rtnl_dereference(n->ilm), sizeof(struct ilm) * n->size);
			__hbucket_free_rcu(n, true);
		}

		rcu_assign_pointer(n->ilm, tmp);
		n->size += HASH_INIT_SIZE;
	}
	n->pos++;
	pos = __get_pos(n, key);
	ilm = __hash_data_rtnl(n, pos);

	return ilm;
}

static inline void
ilm_hash_destroy(struct net *net)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;

	__hash_destroy_rcu(rtnl_dereference(h->table), false);
}

/* Resize a hash: create a new hash table with doubling the hashsize
 * and inserting the elements to it. Repeat until we succeed or
 * fail due to memory pressures. */
static int
ilm_hash_resize(const struct net *net)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t, *orig = rtnl_dereference(h->table);
	u8 htable_bits = orig->htable_bits;
	const struct ilm *old_ilm;
	struct hbucket *n, *m;
	u32 i, j;
	u32 label;
	struct ilm *new_ilm;

retry:
	new_ilm = NULL;
	htable_bits++;

	if (unlikely(htable_bits > 31)) {
		/* In case we have plenty of memory :-) */
		printk(KERN_WARNING "Cannot increase the hashsize further\n");
		return -ENOBUFS;
	}

	t = __htable_alloc(sizeof(*t)
			 + jhash_size(htable_bits) * sizeof(struct hbucket));
	if (unlikely(!t))
		return -ENOMEM;

	t->htable_bits = htable_bits;

	for (i = 0; i < jhash_size(orig->htable_bits); i++) {
		n = hbucket(orig, i);
		for (j = 0; j < n->pos; j++) {
			old_ilm = __hash_data_rtnl(n, j);
			label = old_ilm->key.label;

			m = hbucket(t, HKEY(&label, h->initval, htable_bits));
			new_ilm = __ilm_add(m, &old_ilm->key, HASH_MAX(h));

			if (IS_ERR(new_ilm)) {
				__hash_destroy(t, true);
				if (PTR_ERR(new_ilm) == -EAGAIN)
					goto retry;
				return PTR_ERR(new_ilm);
			}

			ilm_copy(new_ilm, old_ilm);
		}
	}

	rcu_assign_pointer(h->table, t);

	__hash_destroy_rcu(orig, true);

	return 0;
}

/* Add an element to a hash and update the internal counters when succeeded,
 * otherwise report the proper error code. */
static struct ilm *
ilm_add(const struct net *net, struct mpls_key *key)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t;
	struct hbucket *n;
	struct ilm *ilm;
	int i;
	u32 label = key->label;
	u32 hkey, multi = 0;

retry:
	t = rtnl_dereference(h->table);
	hkey = HKEY(&label, h->initval, t->htable_bits);
	n = hbucket(t, hkey);

	for (i = 0; i < n->pos; i++) {
		if (ilm_key_equal(&__hash_data_rtnl(n, i)->key, key, &multi, true)) {
			ilm = ERR_PTR(-EEXIST);
			goto out;
		}
	}

	TUNE_HASH_MAX(h, multi);
	ilm = __ilm_add(n, key, HASH_MAX(h));
	if (IS_ERR(ilm)) {
		if (PTR_ERR(ilm) == -EAGAIN) {
			int ret;
			ret = ilm_hash_resize(net);
			if (likely(!ret))
				goto retry;
		}
		goto out;
	}

	h->elements++;
out:
	return ilm;
}

/* Delete an element from the hash: shift remaining elements left
 * and free up space if possible.
 */
static int
ilm_del(const struct net *net, struct mpls_key *key)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t = rtnl_dereference(h->table);
	struct hbucket *n;
	u32 label = key->label;
	u32 hkey, multi = 0;
	struct ilm *data;
	int i;

	hkey = HKEY(&label, h->initval, t->htable_bits);
	n = hbucket(t, hkey);

	for (i = 0; i < n->pos; i++) {
		data = __hash_data_rtnl(n, i);

		if (!ilm_key_equal(&data->key, key, &multi, true))
			continue;

		__destroy_ilm_instrs(data);

		if (i != n->pos - 1)
			/* Not last one */
			__ilm_array_fill_space(n, i);

		n->pos--;
		h->elements--;

		if (n->pos + HASH_INIT_SIZE < n->size) {
			struct ilm *tmp =
				kzalloc((n->size - HASH_INIT_SIZE) * sizeof(struct ilm), GFP_KERNEL | __GFP_NOWARN);
			if (unlikely(!tmp))
				return 0;

			n->size -= HASH_INIT_SIZE;
			memcpy(tmp, n->ilm, n->size * sizeof(struct ilm));

			__hbucket_free_rcu(n, true);
			rcu_assign_pointer(n->ilm, tmp);
		}
		return 0;
	}

	return -ESRCH;
}

static int
ilm_set_nhlfe(struct ilm *ilm, struct nlattr **instr)
{
	struct nhlfe *nhlfe = NULL;
	struct nhlfe *old_nhlfe = NULL;

	old_nhlfe = rtnl_dereference(ilm->nhlfe);

	nhlfe = __nhlfe_build(instr);
	if (IS_ERR(nhlfe))
		return PTR_ERR(nhlfe);

	rcu_assign_pointer(ilm->nhlfe, nhlfe);
	__nhlfe_free(old_nhlfe);

	return 0;
}

static struct ilm *
get_ilm(const struct net *net, const struct mpls_key *key, bool exact_match)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t = !exact_match ? rcu_dereference(h->table) : rtnl_dereference(h->table);
	struct hbucket *n;
	struct ilm *ilm;
	int i;
	u32 label = key->label;
	u32 hkey, multi = 0;

	hkey = HKEY(&label, h->initval, t->htable_bits);
	n = hbucket(t, hkey);
	for (i = 0; i < n->pos; i++) {
		ilm = !exact_match ? __hash_data_rcu(n, i) : __hash_data_rtnl(n, i);
		if (ilm_key_equal(&ilm->key, key, &multi, exact_match))
			return ilm;
	}
	return NULL;
}

static const struct ilm *
get_ilm_input(const struct net *net, const struct mpls_key *key)
{
	const struct ilm *ilm = NULL;

	/* handle the reserved label range */
	if (__is_reserved_label(key))
		ilm = mpls_reserved[key->label];
	else
		ilm = get_ilm(net, key, false);

	return ilm;
}

static struct ilm *
add_ilm(struct ilmsg *ilm_msg, struct nlattr **instr, const struct net *net)
{
	struct ilm *ilm;
	struct nhlfe *nhlfe;
	struct mpls_key key = ilm_msg->key;

	key.tc = ilm_msg->tc;
	key.owner = ilm_msg->owner;

	if (__is_reserved_label(&key))
		return ERR_PTR(-EINVAL);

	nhlfe = __nhlfe_build(instr);
	if (IS_ERR(nhlfe))
		return (struct ilm *)nhlfe;

	ilm = ilm_add(net, &key);
	if (unlikely(IS_ERR(ilm))) {
		kfree(nhlfe);
		return ilm;
	}

	ilm->key = key;
	rcu_assign_pointer(ilm->nhlfe, nhlfe);

	return ilm;
}

static int
del_ilm(struct ilmsg *ilm_msg, const struct net *net)
{
	struct mpls_key key = ilm_msg->key;
	key.tc = ilm_msg->tc;

	return ilm_del(net, &key);
}

/* Utility functions for forwarding and receiving */
static int
mpls_finish_forward(struct sk_buff *skb, const struct nhlfe *nhlfe);

static int
mpls_push_pending_frames(struct sock *sk, struct flowi4 *fl4, void *extra)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct mpls_hdr_payload *payload = (struct mpls_hdr_payload *)extra;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		return 0;

	iph = ip_hdr(skb);
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

	if (unlikely(!__push_mpls_hdr_payload(skb, payload)))
		goto err;

	mpls_hdr(skb)->ttl = MPLSCB(skb)->hdr.ttl = iph->ttl;

	skb->dev = skb_dst(skb)->dev;

	return mpls_finish_forward(skb, payload->nhlfe);
err:
	return -ENOBUFS;
}

static bool
__fragmentation_allowed(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	struct mpls_hdr *hdr = mpls_hdr(skb);
	struct iphdr *ip_hdr;

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC)))
		goto err;

	while (!hdr->s)
		hdr++;

	ip_hdr = (struct iphdr *)(++hdr);

	if (ip_hdr->version == 4) {
		if (ip_hdr->frag_off & htons(IP_DF)) {
			struct mpls_hdr_payload buf;
			if (unlikely(strip_mpls_headers(skb, &buf) != 0))
				goto err;
			buf.nhlfe = nhlfe;
			__icmp_ext_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(dst_mtu(skb_dst(skb))),
					buf.data_len, ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS, &buf,
					mpls_push_pending_frames);
			goto err;
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (ip_hdr->version == 6) {
		if (skb->len >= IPV6_MIN_MTU ||
			!ipv6_has_fragment_hdr(skb)) {
			/* TODO */
			goto err;
		}
	}
#endif

	return true;
err:
	return false;
}

static inline int
decrement_ttl(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	if (likely(skb->protocol == htons(ETH_P_MPLS_UC))) {
		struct mpls_hdr *mplshdr = mpls_hdr(skb);
		if (mplshdr->ttl <= 1) {
			struct mpls_hdr_payload buf;
			if (unlikely(strip_mpls_headers(skb, &buf) != 0))
				goto err;
			buf.nhlfe = nhlfe;
			switch (skb->protocol) {
			case htons(ETH_P_IP):
				__icmp_ext_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0,
						buf.data_len, ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS, &buf,
						mpls_push_pending_frames);
				break;
#if IS_ENABLED(CONFIG_IPV6)
			case htons(ETH_P_IPV6):
				/* TODO */
				break;
#endif
			}
			goto err;
		}
		MPLSCB(skb)->hdr.ttl = --mplshdr->ttl;
	} else
		goto discard;

	return 0;
err:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTERRORS);
	return -MPLS_ERR;

discard:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}


/* Forwarding and receiving functions */

static int
mpls_finish_forward(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	const struct __instr *mi;
	int ret;

	mi = get_first_instruction(nhlfe);

	if (mi->cmd == MPLS_ATTR_POP) {
		ret = mpls_pop(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_DSCP) {
		ret = mpls_dscp(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_TC_INDEX) {
		ret = mpls_tc_index(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_SWAP) {
		ret = mpls_swap(skb, mi++);
		if (unlikely(ret))
			goto free_skb;

		if (mi->cmd != MPLS_ATTR_PUSH)
			goto send;
		else
			goto push;
	}

	if (mi->cmd == MPLS_ATTR_PUSH) {
push:
		ret = mpls_push(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
		goto send;
	}

	if (mi->cmd == MPLS_ATTR_PEEK) {
		ret = mpls_peek(skb, mi);
		if (unlikely(ret))
			goto free_skb;
		else
			goto end;
	}

send:
	ret = mpls_send(skb, mi);
	goto end;

free_skb:
	dev_kfree_skb(skb);
end:
	return ret;
}

static int
mpls_forward(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	const struct __instr *mi;
	struct dst_entry *dst = NULL;
	int ret = -NET_XMIT_DROP;
	int mpls_delta_headroom = (nhlfe->no_push - nhlfe->no_pop) * MPLS_HDR_LEN;
	unsigned int mpls_headroom =
			(mpls_delta_headroom > 0) ? mpls_delta_headroom : 0;

	if (skb_cow_head(skb, mpls_headroom) < 0)
		goto out_discard;

	mi = get_last_instruction(nhlfe);
	if (mi->cmd == MPLS_ATTR_SEND_IPv4) {
		dst = mpls_get_dst_ipv4(skb, mi);
		if (!dst)
			goto free_skb;

send_common:
		__mpls_set_dst(skb, dst);

		if (unlikely((skb->len + mpls_delta_headroom > skb_dst(skb)->dev->mtu) &&
				!__fragmentation_allowed(skb, nhlfe)))
			goto free_skb;

		ret = decrement_ttl(skb, nhlfe);
		if (unlikely(ret))
			goto free_skb;

		goto exec_cmds;
	}

	if (mi->cmd == MPLS_ATTR_SEND_IPv6) {
		dst = mpls_get_dst_ipv6(skb, mi);
		if (!dst)
			goto free_skb;

		goto send_common;
	}

exec_cmds:
	mpls_finish_forward(skb, nhlfe);
	goto end;

out_discard:
	ret = -NET_XMIT_DROP;
	MPLS_INC_STATS(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
free_skb:
	dev_kfree_skb(skb);
end:
	return ret;
}

static inline int
mpls_input(struct sk_buff *skb, struct net_device *dev, const struct mpls_key *key)
{
	const struct ilm *ilm;
	int ret = NET_RX_DROP;

	rcu_read_lock();
	ilm = get_ilm_input(dev_net(skb->dev), key);
	if (unlikely(!(ilm && ilm->nhlfe))) {
		rcu_read_unlock();
		MPLS_INC_STATS_BH(dev_net(dev),
			MPLS_MIB_IFINLABELLOOKUPFAILURES);
		goto mpls_input_drop;
	}

	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INPACKETS);
	MPLS_ADD_STATS_BH(dev_net(dev), MPLS_MIB_INOCTETS, skb->len);

	ret = mpls_forward(skb, ilm->nhlfe);
	rcu_read_unlock();
	return ret;

mpls_input_drop:
	kfree_skb(skb);

	return ret;
}

/* Main receiving function */
int
mpls_recv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig)
{
	struct mpls_skb_cb *cb;
	struct mpls_key key;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto mpls_rcv_drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto mpls_rcv_err;

	if (!pskb_may_pull(skb, MPLS_HDR_LEN))
		goto mpls_rcv_err;

	cb = MPLSCB(skb);

	label_entry_peek(skb);

	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_IEEE802:
	case ARPHRD_PPP:
	case ARPHRD_LOOPBACK:
	case ARPHRD_HDLC:
	case ARPHRD_IPGRE:
		key.label_l = ntohs(cb->hdr.label_l);
		key.label_u = cb->hdr.label_u;
		key.tc = cb->hdr.tc;
		break;
	default:
		goto mpls_rcv_err;
	}

	return mpls_input(skb, dev, &key);

mpls_rcv_out:
	kfree_skb(skb);
	return NET_RX_DROP;

mpls_rcv_err:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
	goto mpls_rcv_out;

mpls_rcv_drop:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
	goto mpls_rcv_out;
}

/* Netlink functions */

static struct nla_policy ilm_policy[__MPLS_ATTR_MAX] __read_mostly = {
	[MPLS_ATTR_POP] = { .type = NLA_U8, },
	[MPLS_ATTR_DSCP] = { .type = NLA_U8 },
	[MPLS_ATTR_TC_INDEX] = { .type = NLA_U16, },
	[MPLS_ATTR_SWAP] = { .type = NLA_U32, },
	[MPLS_ATTR_PUSH] = { .type = NLA_NESTED, },
	[MPLS_ATTR_PEEK] = { .type = NLA_FLAG, },
	[MPLS_ATTR_SEND_IPv4] = { .len = sizeof(struct mpls_nh), },
	[MPLS_ATTR_SEND_IPv6] = { .len = sizeof(struct mpls_nh), },
	[MPLS_ATTR_INSTR_COUNT] = { .type = NLA_U8, },
};

static int
ilm_event(int event, const struct ilmsg *req, struct net *net, int pid, int seq)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct ilmsg *ilm_msg;
	int err;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	err = -EMSGSIZE;
	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ilm_msg), 0);
	if (!nlh)
		goto nlmsg_failure;

	ilm_msg = nlmsg_data(nlh);
	ilm_msg->family = PF_MPLS;
	ilm_msg->key = req->key;
	ilm_msg->tc = req->tc;
	ilm_msg->owner = req->owner;

	nlmsg_end(skb, nlh);

	rtnl_notify(skb, net, 0, RTNLGRP_MPLS, NULL, GFP_KERNEL);
	return 0;

nlmsg_failure:
	nlmsg_free(skb);
	rtnl_set_sk_err(net, RTNLGRP_MPLS, err);
	return err;
}

static int
fill_ilm(struct sk_buff *skb, const struct ilm *ilm,
					int seq, int pid, int event, int flags)
{
	struct ilmsg *ilm_msg;
	struct nlmsghdr *nlh;
	int ret = 0;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ilm_msg), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ilm_msg = nlmsg_data(nlh);
	ilm_msg->family = PF_MPLS;
	ilm_msg->key = ilm->key;
	ilm_msg->tc = ilm->key.tc;
	ilm_msg->owner = ilm->key.owner;

	ret = __nhlfe_dump(rcu_dereference(ilm->nhlfe), skb);
	if (unlikely(ret < 0))
		goto err;

	return nlmsg_end(skb, nlh);
err:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int
mpls_ilm_new(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ilmsg *ilm_msg;
	struct nlattr *tb[MPLS_ATTR_MAX + 1];
	struct ilm *ilm;
	struct net *net = sock_net(skb->sk);
	int retval = 0;

	retval = nlmsg_parse(nlh, sizeof(*ilm_msg), tb, MPLS_ATTR_MAX, ilm_policy);
	if (retval < 0)
		return retval;

	ilm_msg = nlmsg_data(nlh);
	if (unlikely(!ilm_msg))
		return -EINVAL;

	if (ilm_msg->tc > TC_MAX)
		return -EINVAL;

	if (nlh->nlmsg_flags & NLM_F_CREATE) {
		ilm = add_ilm(ilm_msg, tb, net);

		if (unlikely(IS_ERR(ilm)))
			return PTR_ERR(ilm);
	} else if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		struct mpls_key key = ilm_msg->key;
		key.tc = ilm_msg->tc;

		ilm = get_ilm(net, &key, true);
		if (unlikely(!ilm))
			return -ESRCH;

		retval = ilm_set_nhlfe(ilm, tb);
	} else
		return -EINVAL;

	if (likely(!retval))
		ilm_event(RTM_NEWROUTE, ilm_msg, net, nlh->nlmsg_pid, nlh->nlmsg_seq);
	else if (nlh->nlmsg_flags & NLM_F_CREATE)
		del_ilm(ilm_msg, net);

	return retval;
}

static int
mpls_ilm_del(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ilmsg *ilm_msg;
	struct net *net = sock_net(skb->sk);
	int retval;

	retval = nlmsg_validate(nlh, sizeof(*ilm_msg), MPLS_ATTR_MAX, ilm_policy);
	if (unlikely(retval < 0))
		return retval;

	ilm_msg = nlmsg_data(nlh);

	retval = del_ilm(ilm_msg, net);
	if (likely(!retval))
		ilm_event(RTM_DELROUTE, ilm_msg, net, nlh->nlmsg_pid, nlh->nlmsg_seq);

	return retval;
}

static int
mpls_ilm_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct htable *t;
	struct hbucket *n;
	struct ilm *ilm;
	int i;

	rcu_read_lock();
	for (; cb->args[0] < MAX_RES_LABEL; ++cb->args[0]) {
		if (likely(mpls_reserved[cb->args[0]])) {
			if (fill_ilm(skb, mpls_reserved[cb->args[0]], cb->nlh->nlmsg_seq,
					NETLINK_CREDS(cb->skb)->pid, RTM_NEWROUTE, NLM_F_MULTI) < 0)
				goto out;
		}
	}

	t = rcu_dereference(ilmn->h.table);

	for (; (cb->args[0] - MAX_RES_LABEL) < jhash_size(t->htable_bits); cb->args[0]++) {
		n = hbucket(t, cb->args[0] - MAX_RES_LABEL);

		for (i = 0; i < n->pos; i++) {
			ilm = __hash_data_rcu(n, i);
			if (fill_ilm(skb, ilm, cb->nlh->nlmsg_seq, NETLINK_CREDS(cb->skb)->pid,
					RTM_NEWROUTE, NLM_F_MULTI) < 0)
				goto out;
		}
	}

out:
	rcu_read_unlock();

	return skb->len;
}

/* Init functions */

static int __net_init ilm_init_net(struct net *net)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct htable *t;
	size_t hsize;
	u8 hbits;

	memset(&ilmn->h, 0, sizeof(ilmn->h));

	get_random_bytes(&ilmn->h.initval, sizeof(ilmn->h.initval));

	hbits = __htable_bits(DEFAULT_HASHSIZE);
	hsize = __htable_size(hbits);

	t = __htable_alloc(hsize);
	t->htable_bits = hbits;

	rcu_assign_pointer(ilmn->h.table, t);

	return 0;
}

static void __net_exit ilm_exit_net(struct net *net)
{
	rtnl_lock();
	ilm_hash_destroy(net);
	rtnl_unlock();
}

static struct pernet_operations ilm_net_ops = {
	.init = ilm_init_net,
	.exit = ilm_exit_net,
	.id   = &ilm_net_id,
	.size = sizeof(struct ilm_net),
};

int __init ilm_init(void)
{
	int err;
	err = register_pernet_subsys(&ilm_net_ops);
	if (unlikely(err))
		return err;

	err = __rtnl_register(PF_MPLS, RTM_NEWROUTE, mpls_ilm_new, NULL, NULL);
	if (unlikely(err))
		goto error;

	err = __rtnl_register(PF_MPLS, RTM_DELROUTE, mpls_ilm_del, NULL, NULL);
	if (unlikely(err))
		goto error;

	err = __rtnl_register(PF_MPLS, RTM_GETROUTE, NULL, mpls_ilm_dump, NULL);
	if (unlikely(err))
		goto error;

	return 0;

error:
	rtnl_unregister_all(PF_MPLS);
	return err;
}

void ilm_exit(void)
{
	rtnl_unregister_all(PF_MPLS);
	unregister_pernet_subsys(&ilm_net_ops);
}
