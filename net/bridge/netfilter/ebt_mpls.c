/* This is a module which is used for redirecting packets into MPLS land. */


/* (C) 1999-2009 James R. Leu <jleu@mindspring.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/mpls.h>
#include <net/sock.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MPLS.h>
#include <linux/netfilter_bridge/ebtables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James R. Leu <jle@mindspring.com>");
MODULE_DESCRIPTION("ebtables mpls module");

static unsigned int
target(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_MPLS_target_info *mplsinfo = par->targinfo;
	struct mpls_nhlfe *nhlfe = mplsinfo->nhlfe;

	MPLS_ENTER;
	if (!skb_make_writable(skb, 0))
		return EBT_DROP;

	/* until we can pass the proto driver via mpls_output_shim
	 * we'll let it look it up for us based on skb->protocol */
	skb->protocol = htons(ETH_P_ALL);

	/* skb->mac_len is the size of the L2 header
	 *
	 * allocate more headroom (size of L2 header + shim)
	 * push the SKB the size of the L2 header so skb->data
	 * points to the begining of the L2 header
	 *
	 * then
	 *     mac_header = will point to the new header area
	 * and
	 *     network_header = mac_header + mac_len
	 *
	 * network_header is where we put the MPLS shim
	 */

	if (pskb_expand_head(skb, SKB_DATA_ALIGN(skb->mac_len+4),0,GFP_ATOMIC))
		return EBT_DROP;

	skb_push(skb, skb->data - skb_mac_header(skb));
	skb_reset_network_header(skb);

	skb_dst_drop(skb);
	skb_dst_set(skb, &nhlfe->dst);

	dst_output(skb);

	MPLS_EXIT;
	/* don't let anyone else use this frame */
	return EBT_DROP;
}

static int
checkentry(const struct xt_tgchk_param *par)
{
	struct xt_MPLS_target_info *mplsinfo = par->targinfo;

	MPLS_ENTER;
	mplsinfo->nhlfe = mpls_get_nhlfe(mplsinfo->key);
	if (!mplsinfo->nhlfe) {
		printk(KERN_WARNING "mpls: unable to find NHLFE with key %x\n",
				mplsinfo->key);
		return -EINVAL;
	}

	mplsinfo->proto = mpls_proto_find_by_ethertype(htons(ETH_P_ALL));
	if (!mplsinfo->proto) {
		printk(KERN_WARNING "mpls: unable to find ETH_P_ALL driver\n");
		return -EINVAL;
	}

	MPLS_EXIT;
	return 0;
}

static void
destroy(const struct xt_tgdtor_param *par)
{
	struct xt_MPLS_target_info *mplsinfo = par->targinfo;
	struct mpls_nhlfe *nhlfe = mplsinfo->nhlfe;
	struct mpls_prot_driver **proto = (struct mpls_prot_driver **) &mplsinfo->proto;

	MPLS_ENTER;
	if (nhlfe) {
		mpls_nhlfe_release(nhlfe);
		mplsinfo->nhlfe = NULL;
	}

	mpls_proto_release(proto);
	MPLS_EXIT;
}

static struct xt_target ebt_mpls_target __read_mostly = {
		.name		= "mpls",
		.family		= NFPROTO_BRIDGE,
		.revision	= 0,
		.checkentry	= checkentry,
		.target		= target,
		.destroy	= destroy,
		.targetsize	= sizeof(struct xt_MPLS_target_info),
		.me		= THIS_MODULE,
};

static int __init ebt_mpls_init(void)
{
	return xt_register_target(&ebt_mpls_target);
}

static void __exit ebt_mpls_fini(void)
{
	xt_unregister_target(&ebt_mpls_target);
}

module_init(ebt_mpls_init);
module_exit(ebt_mpls_fini);
