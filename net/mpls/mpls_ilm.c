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
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <net/ip_fib.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/mpls.h>
#include "mpls_cmd.h"

int ilm_net_id __read_mostly;

static const struct nhlfe pop_peek_nhlfe = {
	.refcnt = ATOMIC_INIT(1),
	.num_pop = 1,
};

static const struct ilm ipv4_explicit_null = {
	.label = MPLS_LABEL_EXPLICIT_NULL_IPV4,
	.owner = RTPROT_BOOT,
	.tc = 0,
	.nhlfe = (struct nhlfe *) &pop_peek_nhlfe,
};

static const struct ilm ipv6_explicit_null = {
	.label = MPLS_LABEL_EXPLICIT_NULL_IPV6,
	.owner = RTPROT_BOOT,
	.tc = 0,
	.nhlfe = (struct nhlfe *) &pop_peek_nhlfe,
};

static const struct ilm *mpls_reserved[MPLS_LABEL_MAX_RESERVED] = {
	[MPLS_LABEL_EXPLICIT_NULL_IPV4] = &ipv4_explicit_null,
	[MPLS_LABEL_EXPLICIT_NULL_IPV6] = &ipv6_explicit_null,
};

static inline void
__destroy_ilm_instrs_rcu(struct ilm *ilm)
{
	__nhlfe_free_rcu(ilm->nhlfe);
	rcu_assign_pointer(ilm->nhlfe, NULL);
}

static inline void
ilm_copy(struct ilm *dst, const struct ilm *src)
{
	smp_wmb();
	memcpy(dst, src, sizeof(struct ilm));
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

/* Number of elements to store in an initial array block */
#define HASH_INIT_SIZE			4

/* Max number of elements to store in an array block */
#define HASH_MAX_SIZE			(3 * HASH_INIT_SIZE)

/* Max number of elements can be tuned */
#define HASH_MAX(h)			((h)->hash_max)

#define DEFAULT_HASHSIZE		1024

/* Get the ith element from the array block n */
#define __hash_data_rtnl(n, i)						\
	((struct ilm *)(rtnl_dereference((n)->ilm) + (i)))

#define __hash_data_rcu(n, i)						\
	((struct ilm *)(rcu_dereference((n)->ilm) + (i)))

#define __hash_data_rcu_rtnl(n, i)					\
	((struct ilm *)(rcu_dereference_rtnl((n)->ilm) + (i)))

static inline struct hbucket *hbucket(struct htable *h, u32 i)
{
	return &h->bucket[i];
}

static inline u32 HKEY(u32 label, u32 initval, u8 htable_bits)
{
	/* Can't use TC as hash key as we do also non-exact lookups
	 * where TC is ignored */
	return jhash_1word(label, initval) & jhash_mask(htable_bits);
}

static inline void tune_hash_max(struct ilm_hash *h, u32 label_collisions)
{
	u32 max = h->hash_max + HASH_INIT_SIZE;

	/* Currently, at listing one hash bucket must fit into a message.
	 * Therefore we have a hard limit here. */
	if (max > 64)
		max = 64;

	if (label_collisions >= h->hash_max)
		h->hash_max = max;
}

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
__hbucket_free(struct hbucket *bucket)
{
	if (bucket->size)
		kfree(__hash_data_rtnl(bucket, 0));
}

static inline void
__hbucket_free_rcu(struct hbucket *bucket, bool leave_instr)
{
	int j;

	for (j = 0; j < bucket->size && !leave_instr; j++)
		__destroy_ilm_instrs_rcu(__hash_data_rtnl(bucket, j));

	if (bucket->size)
		kfree_rcu(__hash_data_rtnl(bucket, 0), rcu);
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
__hash_destroy(struct htable *t)
{
	struct hbucket *n;
	u32 i;

	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		__hbucket_free(n);
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
__get_pos(struct hbucket *n, u32 label, u8 tc)
{
	int pos;

	for (pos = 0; pos < n->pos - 1; ++pos) {
		struct ilm *hilm = __hash_data_rtnl(n, pos);
		if (hilm->label < label)
			break;
		if (hilm->label == label && hilm->tc < tc)
			break;
	}
	__ilm_array_make_space(n, pos);
	return pos;
}

/* Add an element to the hash table when resizing the set:
 * we spare the maintenance of the internal counters. */
static struct ilm*
__ilm_add(struct hbucket *n, u32 label, u8 tc, u8 hash_max)
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
	pos = __get_pos(n, label, tc);
	ilm = __hash_data_rtnl(n, pos);

	return ilm;
}

static inline void
ilm_hash_destroy(struct ilm_net *ilmn)
{
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
	struct ilm *new_ilm;

retry:
	new_ilm = NULL;
	htable_bits++;

	if (unlikely(htable_bits > 31)) {
		/* In case we have plenty of memory :-) */
		printk(KERN_WARNING "MPLS: Cannot increase the hashsize further\n");
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

			m = hbucket(t, HKEY(old_ilm->label, h->initval, htable_bits));
			new_ilm = __ilm_add(m, old_ilm->label, old_ilm->tc, HASH_MAX(h));

			if (IS_ERR(new_ilm)) {
				__hash_destroy(t);
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
ilm_add(const struct net *net, u32 label, u8 tc)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t;
	struct hbucket *n;
	struct ilm *ilm;
	int i, ret;
	u32 hkey, label_collisions = 0;

retry:
	t = rtnl_dereference(h->table);
	hkey = HKEY(label, h->initval, t->htable_bits);
	n = hbucket(t, hkey);

	for (i = 0; i < n->pos; i++) {
		ilm = __hash_data_rtnl(n, i);
		if (ilm->label != label)
			continue;
		if (ilm->tc == tc)
			return ERR_PTR(-EEXIST);
		label_collisions++;
	}
	tune_hash_max(h, label_collisions);

	ilm = __ilm_add(n, label, tc, HASH_MAX(h));
	if (IS_ERR(ilm)) {
		if (PTR_ERR(ilm) != -EAGAIN)
			return ERR_CAST(ilm);

		ret = ilm_hash_resize(net);
		if (likely(!ret))
			goto retry;
	} else
		h->elements++;

	ilm->label = label;
	ilm->tc = tc;
	return ilm;
}

static void
__ilm_del(struct ilm_hash *h, struct hbucket *n, int pos, struct ilm *ilm)
{
	__destroy_ilm_instrs_rcu(ilm);

	if (pos != n->pos - 1)
		/* Not last one */
		__ilm_array_fill_space(n, pos);

	n->pos--;
	h->elements--;

	if (n->pos + HASH_INIT_SIZE < n->size) {
		struct ilm *tmp;

		tmp = kzalloc((n->size - HASH_INIT_SIZE) * sizeof(struct ilm), GFP_KERNEL | __GFP_NOWARN);
		if (unlikely(!tmp))
			return;

		n->size -= HASH_INIT_SIZE;
		memcpy(tmp, n->ilm, n->size * sizeof(struct ilm));

		__hbucket_free_rcu(n, true);
		rcu_assign_pointer(n->ilm, tmp);
	}
}

/* Delete an element from the hash: shift remaining elements left
 * and free up space if possible. Returns copy of the deleted ilm.
 */
static int
ilm_del(const struct net *net, u32 label, u8 tc, struct ilm *ilm)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t = rtnl_dereference(h->table);
	struct hbucket *n;
	u32 hkey;
	struct ilm *data;
	int i;

	hkey = HKEY(label, h->initval, t->htable_bits);
	n = hbucket(t, hkey);

	for (i = 0; i < n->pos; i++) {
		data = __hash_data_rtnl(n, i);

		if (data->label != label || data->tc != tc)
			continue;

		if (ilm != NULL)
			ilm_copy(ilm, data);

		__destroy_ilm_instrs_rcu(data);

		if (i != n->pos - 1)
			/* Not last one */
			__ilm_array_fill_space(n, i);

		n->pos--;
		h->elements--;

		if (n->pos + HASH_INIT_SIZE < n->size) {
			struct ilm *tmp;

			tmp = kzalloc((n->size - HASH_INIT_SIZE) * sizeof(struct ilm), GFP_KERNEL | __GFP_NOWARN);
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

static int ilm_init_net(struct net *net);
static void ilm_cleanup_net(struct net *net);

static void
ilm_sync_master_dev_down(const struct net *net, const struct net_device *dev)
{
	/*
	 * Calling this function is only allowed with acquired RTNL lock
	 */
	ASSERT_RTNL();

	if (dev != __mpls_master_dev(net))
		return;

	/*
	 * Destroy all ilm entries on this net
	 * We can't operate MPLS on net, if master dev is down, or if it isn't MPLS enabled
	 */
	ilm_cleanup_net((struct net *)net);
	ilm_init_net((struct net *)net);
}

static void
ilm_sync_dev_down(const struct net *net, const struct net_device *dev)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct htable *t;
	struct hbucket *n;
	struct ilm *ilm;
	int i, j;

	/*
	 * Calling this function is only allowed with acquired RTNL lock
	 */
	ASSERT_RTNL();

	t = rtnl_dereference(ilmn->h.table);

	for (i = 0; i < jhash_size(t->htable_bits); ++i) {
bucket_restart:
		n = hbucket(t, i);

		for (j = 0; j < n->pos; j++) {
			ilm = __hash_data_rtnl(n, j);
			if (rtnl_dereference(ilm->nhlfe)->dev == dev) {
				__ilm_del(&ilmn->h, n, j, ilm);
				goto bucket_restart;
			}
		}
	}
}

int mpls_ilm_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	switch (event) {
	case NETDEV_UP:
		/*
		 * TODO - Create ilm_sync_up when
		 * MPLS multipath is implemented.
		 * Before calling ilm_sync_up we should
		 * first check if IFF_MPLS flag is set!
		 */
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		/*
		 * TODO - When the multipath is implemented this two cases
		 * need to be different
		 * - NETDEV_DOWN       - Marks multipath hops in route as dead,
		 *                       or delete route if it isn't multipath
		 * - NETDEV_UNREGISTER - Deletes all routes with this dev
		 */
		ilm_sync_master_dev_down(dev_net(dev), dev);
		ilm_sync_dev_down(dev_net(dev), dev);
		break;
	case NETDEV_CHANGEMPLS:
		if (!(dev->flags & IFF_MPLS)) {
			ilm_sync_master_dev_down(dev_net(dev), dev);
			ilm_sync_dev_down(dev_net(dev), dev);
		}
		/* TODO - Other case should be implemented when multipath is implemented */
		break;
	}
	return NOTIFY_DONE;
}

static struct ilm *
get_ilm(const struct net *net, u32 label, u8 tc, bool exact_match)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	struct ilm_hash *h = &ilmn->h;
	struct htable *t = rcu_dereference_rtnl(h->table);
	struct hbucket *n;
	struct ilm *ilm;
	int i;

	n = hbucket(t, HKEY(label, h->initval, t->htable_bits));
	for (i = 0; i < n->pos; i++) {
		ilm = __hash_data_rcu_rtnl(n, i);
		if (ilm->label != label)
			continue;
		if (ilm->tc == tc)
			return ilm;
		if (!exact_match && ilm->tc == 0)
			return ilm;
	}
	return NULL;
}

static const struct ilm *
get_ilm_input(const struct net *net, u32 label, u8 tc)
{
	const struct ilm *ilm = NULL;

	/* handle the reserved label range */
	if (mpls_is_reserved_label(label))
		ilm = mpls_reserved[label];
	else
		ilm = get_ilm(net, label, tc, false);

	return ilm;
}

static struct nla_policy ilm_policy[__MPLS_ATTR_MAX] __read_mostly = {
	[MPLSA_POP]		= { .type = NLA_U8 },
	[MPLSA_DSCP]		= { .type = NLA_U8 },
#if IS_ENABLED(CONFIG_NET_SCHED)
	[MPLSA_TC_INDEX]	= { .type = NLA_U16 },
#else
	[MPLSA_TC_INDEX]	= { .type = NLA_PROHIBIT },
#endif
	[MPLSA_SWAP]		= { .type = NLA_U32 },
	[MPLSA_PUSH]		= { .type = NLA_BINARY },
	[MPLSA_NEXTHOP_OIF]	= { .type = NLA_U32 },
	[MPLSA_NEXTHOP_ADDR]	= { .type = NLA_BINARY },
};

static inline void
send_icmp_time_exceeded(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	struct net *net = dev_net(skb->dev);
	struct dst_entry *dst;

	dst = nhlfe_get_nexthop_dst(nhlfe, net, skb);
	if (IS_ERR(dst))
		return;

	skb_dst_set(skb, dst);

	if (unlikely(strip_mpls_headers(skb) != 0))
		return;

	nf_mpls_nhlfe(skb->nf_mpls) = nhlfe;
	nf_mpls_dev(skb->nf_mpls) = skb->dev;

	icmp_ext_send_p(skb->protocol, skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0,
			skb->nf_mpls->hdr_len,
			ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS,
			nf_mpls_hdr_stack(skb->nf_mpls));
}

static inline int
mpls_input(struct sk_buff *skb, struct net_device *dev, u32 label, u8 tc)
{
	const struct ilm *ilm;
	const struct nhlfe *nhlfe;
	int ret;

	rcu_read_lock();
	ilm = get_ilm_input(dev_net(skb->dev), label, tc);
	if (unlikely(ilm == NULL))
		goto err;

	nhlfe = rcu_dereference(ilm->nhlfe);
	if (unlikely(nhlfe == NULL))
		goto err;

	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INPACKETS);
	MPLS_ADD_STATS_BH(dev_net(dev), MPLS_MIB_INOCTETS, skb->len);

	if (nhlfe->flags & MPLS_HAS_NH) {
		if (MPLSCB(skb)->hdr.ttl <= 1) {
			send_icmp_time_exceeded(skb, nhlfe);
			MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_OUTDISCARDS);
			goto free_skb;
		}
		MPLSCB(skb)->hdr.ttl--;
	}
	ret = __nhlfe_send(nhlfe, skb);

	rcu_read_unlock();

	return (ret == NET_XMIT_SUCCESS) ? NET_RX_SUCCESS : NET_RX_DROP;

err:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_IFINLABELLOOKUPFAILURES);
free_skb:
	rcu_read_unlock();
	kfree_skb(skb);
	return NET_RX_DROP;
}

/* Main receiving function */
int
mpls_recv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig)
{
	struct mpls_skb_cb *cb;
	u32 label;
	u8 tc;

	if (skb->pkt_type == PACKET_OTHERHOST ||
		    (dev->flags & (IFF_MPLS | IFF_UP)) != (IFF_MPLS | IFF_UP))
		goto mpls_rcv_drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto mpls_rcv_err;

	if (!pskb_may_pull(skb, MPLS_HDR_LEN))
		goto mpls_rcv_err;

	cb = MPLSCB(skb);

	mpls_peek_label(skb);

	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_IEEE802:
	case ARPHRD_PPP:
	case ARPHRD_LOOPBACK:
	case ARPHRD_MPLS:
	case ARPHRD_HDLC:
	case ARPHRD_IPGRE:
		label = mpls_hdr_label(&cb->hdr);
		tc = cb->hdr.tc;
		break;
	default:
		goto mpls_rcv_err;
	}

	return mpls_input(skb, dev, label, tc);

mpls_rcv_err:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
	goto mpls_rcv_out;
mpls_rcv_drop:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
mpls_rcv_out:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/* Netlink functions */

static struct nla_policy rtm_mpls_policy[RTA_MAX + 1] __read_mostly = {
	[RTA_DST]		= { .type = NLA_U32 },
	[RTA_MPLS]		= { .type = NLA_NESTED },
};

static int fill_ilm(struct sk_buff *skb, const struct ilm *ilm,
		    int seq, int pid, int event, int flags)
{
	struct rtmsg *rtm;
	struct nlmsghdr *nlh;
	struct nlattr *nest;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*rtm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family		= PF_MPLS;
	rtm->rtm_dst_len	= 32;
	rtm->rtm_src_len	= 0;
	rtm->rtm_tos		= __tc_to_dscp(ilm->tc);
	rtm->rtm_table		= RT_TABLE_MAIN;
	rtm->rtm_protocol	= ilm->owner;
	rtm->rtm_scope		= RT_SCOPE_UNIVERSE;
	rtm->rtm_type		= RTN_UNICAST;
	rtm->rtm_flags		= 0;

	if (nla_put_u32(skb, RTA_DST, ilm->label))
		goto nla_put_failure;

	nest = nla_nest_start(skb, RTA_MPLS);
	if (!nest)
		goto nla_put_failure;
	if (__nhlfe_dump(rcu_dereference_rtnl(ilm->nhlfe), skb))
		goto nla_put_failure;
	nla_nest_end(skb, nest);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static void
ilm_event(struct nlmsghdr *nlh, struct net *net, const struct ilm *ilm, int event)
{
	struct sk_buff *skb;
	__u32 seq = nlh ? nlh->nlmsg_seq : 0;
	__u32 pid = nlh ? nlh->nlmsg_pid : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		goto fail;

	err = fill_ilm(skb, ilm, seq, pid, event, 0);
	if (err < 0)
		goto fail;

	rtnl_notify(skb, net, pid, RTNLGRP_MPLS, nlh, GFP_KERNEL);
	return;
fail:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_MPLS, err);
}

static int
mpls_ilm_new(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct rtmsg *rtm;
	struct nlattr *rta[RTA_MAX + 1];
	struct ilm *ilm = NULL;
	struct net *net = sock_net(skb->sk);
	struct nhlfe *nhlfe;
	int err = 0;
	u32 label;
	u8  tc;

	err = nlmsg_parse(nlh, sizeof(*rtm), rta, RTA_MAX, rtm_mpls_policy);
	if (err < 0)
		return err;

	rtm = nlmsg_data(nlh);
	if (rtm->rtm_src_len != 0 ||
	    rtm->rtm_dst_len != 32 || !rta[RTA_DST] ||
	    rtm->rtm_table != RT_TABLE_MAIN ||
	    rtm->rtm_type != RTN_UNICAST)
		return -EINVAL;

	label = nla_get_u32(rta[RTA_DST]);
	tc    = __dscp_to_tc(rtm->rtm_tos);
	if (mpls_is_reserved_label(label) || !mpls_is_valid_label(label) ||
	    tc > TC_MAX)
		return -EINVAL;

	if (!rta[RTA_MPLS])
		return -EINVAL;

	nhlfe = __nhlfe_build(net, rta[RTA_MPLS], ilm_policy, NULL);

	if (IS_ERR(nhlfe))
		return PTR_ERR(nhlfe);

	if (nlh->nlmsg_flags & NLM_F_REPLACE)
		ilm = get_ilm(net, label, tc, true);

	if (ilm)
		__nhlfe_free_rcu(rtnl_dereference(ilm->nhlfe));
	else if (nlh->nlmsg_flags & NLM_F_CREATE) {
		ilm = ilm_add(net, label, tc);
		if (IS_ERR(ilm)) {
			kfree(nhlfe);
			return PTR_ERR(ilm);
		}
	} else
		return -ESRCH;

	ilm->owner = rtm->rtm_protocol;
	rcu_assign_pointer(ilm->nhlfe, nhlfe);
	ilm_event(nlh, net, ilm, RTM_NEWROUTE);

	return 0;
}

static int
mpls_ilm_del(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct rtmsg *rtm;
	struct nlattr *rta[RTA_MAX + 1];
	struct net *net = sock_net(skb->sk);
	struct ilm ilm;
	u32 label;
	u8  tc;
	int err;

	err = nlmsg_parse(nlh, sizeof(*rtm), rta, RTA_MAX, rtm_mpls_policy);
	if (err < 0)
		return err;

	rtm = nlmsg_data(nlh);
	if (rtm->rtm_src_len != 0 ||
	    rtm->rtm_dst_len != 32 || !rta[RTA_DST] ||
	    rtm->rtm_table != RT_TABLE_MAIN)
		return -EINVAL;

	label = nla_get_u32(rta[RTA_DST]);
	tc    = __dscp_to_tc(rtm->rtm_tos);
	if (mpls_is_reserved_label(label) || !mpls_is_valid_label(label) ||
	    tc > TC_MAX)
		return -EINVAL;

	err = ilm_del(net, label, tc, &ilm);
	if (err)
		return err;

	ilm_event(nlh, net, &ilm, RTM_DELROUTE);
	return 0;
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
	for (; cb->args[0] < MPLS_LABEL_MAX_RESERVED; ++cb->args[0]) {
		if (likely(mpls_reserved[cb->args[0]] && !__mpls_master_dev_state(net))) {
			if (fill_ilm(skb, mpls_reserved[cb->args[0]], cb->nlh->nlmsg_seq,
					NETLINK_CREDS(cb->skb)->pid, RTM_NEWROUTE, NLM_F_MULTI) < 0)
				goto out;
		}
	}

	t = rcu_dereference(ilmn->h.table);

	for (; (cb->args[0] - MPLS_LABEL_MAX_RESERVED) < jhash_size(t->htable_bits); cb->args[0]++) {
		n = hbucket(t, cb->args[0] - MPLS_LABEL_MAX_RESERVED);

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

static int ilm_init_net(struct net *net)
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

static void ilm_cleanup_net(struct net *net)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	ASSERT_RTNL();
	ilm_hash_destroy(ilmn);
}

static void __net_exit ilm_exit_net(struct net *net)
{
	rtnl_lock();
	ilm_cleanup_net(net);
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
