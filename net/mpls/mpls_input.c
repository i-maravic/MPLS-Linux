/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *         James Leu        <jleu@mindspring.com>
 *         Ramon Casellas   <casellas@infres.enst.fr>
 *         Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 ****************************************************************************/

#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/netdevice.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/kobject.h>
#include <net/ip.h>
#include <net/icmp.h>
#ifdef CONFIG_IPV6
#include <net/ipv6.h>
#endif
#include <net/mpls.h>
#include <net/xfrm.h>


/**
 *	mpls_input - Begin labelled packet processing.
 *	@skb:        socket buffer, containing the good stuff.
 *	@dev:        device that receives the packet.
 *	@label:      label value + metadata (type)
 *	@labelspace: incoming labelspace.
 **/

static int mpls_input(struct sk_buff *skb, struct net_device *dev,
		struct mpls_label *label, int labelspace)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	MPLS_IN_OPCODE_PROTOTYPE(*func);  /* Function Pointer for Opcodes */
	struct mpls_prot_driver *prot;
	struct mpls_nhlfe *nhlfe = NULL;  /* Current NHLFE */
	struct mpls_ilm  *ilm;            /* Current ILM */
	struct mpls_instr    *mi;
	void *data = NULL;                 /* current data for opcode */
	int  opcode = 0;                   /* Current opcode to execute */
	char *msg = NULL;                  /* Human readable desc. opcode */
	int retval, packet_length = skb->len;

	MPLS_ENTER;

mpls_input_start:

	MPLS_DEBUG("labelspace=%d,label=%d,exp=%01x,B.O.S=%d,TTL=%d\n",
			labelspace, cb->label, cb->exp, cb->bos, cb->ttl);

	/* GET a reference to the ilm given this label value/labelspace*/
	ilm = mpls_get_ilm_by_label(label, labelspace, cb->bos);
	if (unlikely(!ilm)) {
		MPLS_DEBUG("unknown incoming label, dropping\n");
		MPLS_INC_STATS_BH(dev_net(dev),
			MPLS_MIB_IFINLABELLOOKUPFAILURES);
		goto mpls_input_drop;
	}

	/* Iterate all the opcodes for this ILM */
	for_each_instr(ilm->ilm_instr, mi) {
		data   = mi->mi_data;
		opcode = mi->mi_opcode;
		msg    = mpls_ops[opcode].msg;
		func   = mpls_ops[opcode].in;

		MPLS_DEBUG("opcode %s\n", msg);
		if (!func) {
			MPLS_DEBUG("invalid opcode for input: %s\n", msg);
			MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
			goto mpls_input_drop;
		}

		switch (func(&skb, ilm, &nhlfe, data)) {
		case MPLS_RESULT_RECURSE:
			label->ml_type = MPLS_LABEL_GEN;
			label->u.ml_gen = MPLSCB(skb)->label;

			/* drop the previous ILM */
			mpls_ilm_release(ilm);

			goto mpls_input_start;
		case MPLS_RESULT_DLV:
			goto mpls_input_dlv;
		case MPLS_RESULT_FWD:
			goto mpls_input_fwd;
		case MPLS_RESULT_DROP:
			MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
			goto mpls_input_drop;
		case MPLS_RESULT_SUCCESS:
			break;
		}
	}
	MPLS_DEBUG("finished executing in label program without DLV or FWD\n");

	/* fall through to drop */

mpls_input_drop:
	if (ilm)
		mpls_ilm_release(ilm);

	kfree_skb(skb);
	MPLS_DEBUG("dropped\n");
	MPLS_EXIT;
	return NET_RX_DROP;

mpls_input_dlv:
	secpath_reset(skb);
	skb->mac_header = skb->network_header;
	skb_reset_network_header(skb);
	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
		goto mpls_input_drop;
	}

	if (ip_hdr(skb)->version == 4)
		skb->protocol = htons(ETH_P_IP);
	else if (ip_hdr(skb)->version == 6)
		skb->protocol = htons(ETH_P_IPV6);
	else {
		MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
		goto mpls_input_drop;
	}

	skb->pkt_type = PACKET_HOST;
	__skb_tunnel_rx(skb, dev);

	mpls_ilm_release(ilm);

	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INPACKETS);
	MPLS_ADD_STATS_BH(dev_net(dev), MPLS_MIB_INOCTETS, packet_length);

	netif_rx(skb);
	/* we're done with the PDU, it now goes to another layer for handling
	 */
	MPLS_DEBUG("delivering\n");
	MPLS_EXIT;
	return NET_RX_SUCCESS;

mpls_input_fwd:
	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb,
		LL_RESERVED_SPACE(nhlfe->dst.dev) +
		nhlfe->dst.header_len)) {

		printk_ratelimited(KERN_ERR "MPLS: unable to cow skb\n");
		MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
		goto mpls_input_drop;
	}

	cb = MPLSCB(skb);
	prot = cb->prot = nhlfe->nhlfe_proto;

	if (cb->ttl <= 1) {
		MPLS_DEBUG("TTL exceeded\n");

		retval = prot->ttl_expired(&skb);

		if (retval) {
			MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
			goto mpls_input_drop;
		}
		/* otherwise prot->ttl_expired() must have modified the
		 * skb and want it to be forwarded down the LSP
		 */
	}

	cb->label = 0;
	cb->exp = 0;
	cb->flag = 0;

	if (cb->popped_bos) {
		cb->bos = 1;
		skb->protocol = nhlfe->nhlfe_proto->ethertype;
	} else {
		cb->bos = 0;
		skb->protocol = htons(ETH_P_MPLS_UC);
	}

	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INPACKETS);
	MPLS_ADD_STATS_BH(dev_net(dev),
		MPLS_MIB_INOCTETS, packet_length);

	/* hold nhlfe before releasing ilm */
	mpls_nhlfe_hold(nhlfe);

	mpls_ilm_release(ilm);

	(cb->ttl)--;

	skb_dst_set(skb, &nhlfe->dst);

	MPLS_DEBUG("switching\n");
	MPLS_EXIT;
	return dst_input(skb);
}

/**
 *	mpls_skb_recv - Main MPLS packet receive function.
 *	@skb : socket buffer, containing the good stuff.
 *	@dev : device that received the packet.
 *	@pt  : packet type handler.
 **/

int mpls_skb_recv(struct sk_buff *skb,
	struct net_device *dev, struct packet_type *pt,
	struct net_device *orig)
{
	struct mpls_skb_cb *cb;
	int labelspace;
	struct mpls_label label;
	struct mpls_interface *mip = dev->mpls_ptr;

	MPLS_ENTER;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto mpls_rcv_drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto mpls_rcv_err;

	cb = MPLSCB(skb);

	if (!pskb_may_pull(skb, MPLS_HDR_LEN))
		goto mpls_rcv_err;

	labelspace = mip ? mip->labelspace : -1;
	if (unlikely(labelspace < 0)) {
		MPLS_DEBUG("dev %s has no labelspace, dropped!\n", dev->name);
		MPLS_INC_STATS_BH(dev_net(dev),
			MPLS_MIB_IFINLABELLOOKUPFAILURES);
		goto mpls_rcv_out;
	}

	memset(cb, 0, sizeof(struct mpls_skb_cb));
	memset(&label, 0, sizeof(label));
	cb->top_of_stack = skb->data;

	mpls_label_entry_peek(skb);

	/* we need the label struct for when we support ATM and FR */
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
	case ARPHRD_PPP:
	case ARPHRD_LOOPBACK:
	case ARPHRD_HDLC:
	case ARPHRD_IPGRE:
		label.ml_type  = MPLS_LABEL_GEN;
		label.u.ml_gen = cb->label;
		break;
	default:
		MPLS_DEBUG("device %s unknown IfType(%08x)\n",
				dev->name, dev->type);
		goto mpls_rcv_err;
	}

	return mpls_input(skb, dev, &label, labelspace);

mpls_rcv_out:
	kfree_skb(skb);
	MPLS_EXIT;
	return NET_RX_DROP;
mpls_rcv_err:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
	goto mpls_rcv_out;
mpls_rcv_drop:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
	goto mpls_rcv_out;
}
