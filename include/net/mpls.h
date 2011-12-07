/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * File:  linux/include/net/mpls.h
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 * *****************************************************************************
 */
#ifndef __LINUX_NET_MPLS__H_
#define __LINUX_NET_MPLS__H_

#include <net/shim.h>
#include <net/dst.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <linux/module.h>

/*
 * Forward declarations
 */
extern int sysctl_mpls_debug;
extern int sysctl_mpls_default_ttl;
extern struct shim mpls_uc_shim;

/*
Debugging macros
*/
#define MPLS_DEBUG(f, a...) \
{ \
	if (sysctl_mpls_debug) {\
		printk(KERN_DEBUG "MPLS DEBUG %s:%d:%s: ", \
			__FILE__, __LINE__, __func__); \
		printk(f, ##a); \
	} \
}

#define MPLS_DEBUG_CALL(f) \
{ \
	if (sysctl_mpls_debug) {\
		f; \
	} \
}


#define MPLS_ENTER MPLS_DEBUG("enter\n")
#define MPLS_EXIT  MPLS_DEBUG("exit\n")

/*
 * SNMP statistics for MPLS
 */

#define MPLS_INC_STATS(net, field) SNMP_INC_STATS\
	((net)->mib.mpls_statistics, field)
#define MPLS_INC_STATS_BH(net, field) SNMP_INC_STATS_BH\
	((net)->mib.mpls_statistics, field)
#define MPLS_ADD_STATS(net, field, add) SNMP_ADD_STATS\
	((net)->mib.mpls_statistics, field, add)
#define MPLS_ADD_STATS_BH(net, field, add) SNMP_ADD_STATS_BH\
	((net)->mib.mpls_statistics, field, add)

/****************************************************************************
 * MPLS Interface "Extension"
 * In the current implementation the "all loved" net_device struct is
 * extended with one field struct mpls_interface (cast'd to void) called
 * mpls_ptr; This holds basically the "per interface" labelspace.
 ****************************************************************************/

struct mpls_interface {
	/*
	 * (any mif object)->list_out is a circular d-linked list. Each node
	 * of this list is a NHLFE. NHLFE's are added to this list when adding a
	 * OP_SET opcode to a nhlfe instruction array.
	 *
	 * list_add(&nhlfe->dev_entry, &mpls_if->list_out) : adds nhlfe to this
	 * list.
	 *
	 * "List of all NHLFEs that use this device (e.g. eth0) as output"
	 * cf. mpls_init.c
	 */
	struct list_head list_out;

	/*
	 * (any mif object)->list_in is a circular d-linked list. Each node
	 * of this list is a ILM. ILM's are added to this list when
	 */
	struct list_head list_in;

	/*
	 * Label Space for this interface
	 */
	int labelspace;
};

/****************************************************************************
 * Socket Buffer Mangement
 ****************************************************************************/

struct mpls_skb_cb {
	struct mpls_prot_driver *prot;
	unsigned int label:20;
	unsigned int ttl:8;
	unsigned int exp:3;
	unsigned int bos:1;
	unsigned char flag;
	unsigned char popped_bos;
	unsigned char *top_of_stack;
};

#define MPLSCB(skb) ((struct mpls_skb_cb *)((skb)->cb))

#define __MPLS_LABEL_TTL_MASK      0xFF
#define __MPLS_LABEL_S_BIT         0x100
#define __MPLS_LABEL_EXP_MASK      0xE00
#define __MPLS_SHIM_TTL(_mplsh)    (_mplsh & __MPLS_LABEL_TTL_MASK)
#define __MPLS_SHIM_S_BIT(_mplsh)  ((_mplsh >> 8) & 0x1)
#define __MPLS_SHIM_EXP(_mplsh)    ((_mplsh >> 9) & 0x7)
#define __MPLS_SHIM_LABEL(_mplsh)  ((_mplsh >> 12) & 0xFFFFF)

/****************************************************************************
 * Result codes for Input/Output Opcodes.
 * net/mpls/{mpls_opcode,mpls_opcode_all}.c
 ****************************************************************************/

#define MPLS_RESULT_SUCCESS	0
#define MPLS_RESULT_RECURSE	1
#define MPLS_RESULT_DROP	2
#define MPLS_RESULT_DLV		3
#define MPLS_RESULT_FWD		4


/**
 * mpls_instr - Struct to hold one instruction
 * @mi_opcode: Opcode. MPLS_OP_POP,etc...
 * @mi_data:   Opcode data.
 * @mi_next:   Next Instruction to execute.
 **/
struct mpls_instr {
	struct mpls_instr  *mi_next;
	unsigned short      mi_opcode;
	enum mpls_dir       mi_dir;
	void               *mi_data;
	void               *mi_parent;
};

#define for_each_instr(_instr, _mi)	\
	for (_mi = _instr; _mi; _mi = _mi->mi_next)


struct mpls_nfmark_fwd_info {
	struct mpls_nhlfe *nfi_nhlfe[MPLS_NFMARK_NUM];
	unsigned short     nfi_mask;
};

struct mpls_dsmark_fwd_info {
	struct mpls_nhlfe *dfi_nhlfe[MPLS_DSMARK_NUM];
	unsigned char      dfi_mask;
};

struct mpls_tcindex_fwd_info {
	struct mpls_nhlfe *tfi_nhlfe[MPLS_TCINDEX_NUM];
	unsigned short     tfi_mask;
};

struct mpls_exp_fwd_info {
	struct mpls_nhlfe *efi_nhlfe[MPLS_EXP_NUM];
};

struct mpls_exp2dsmark_info {
	unsigned char e2d[MPLS_EXP_NUM];
};

struct mpls_exp2tcindex_info {
	unsigned short e2t[MPLS_EXP_NUM];
};

struct mpls_tcindex2exp_info {
	unsigned char t2e_mask;
	unsigned char t2e[MPLS_TCINDEX_NUM];
};

struct mpls_dsmark2exp_info {
	unsigned char d2e_mask;
	unsigned char d2e[MPLS_DSMARK_NUM];
};

struct mpls_nfmark2exp_info {
	unsigned char n2e_mask;
	unsigned char n2e[MPLS_NFMARK_NUM];
};

/****************************************************************************
 * Instruction (OPCODEs) Management
 * net/mpls/mpls_instr.c
 ****************************************************************************/

void mpls_instrs_free(struct mpls_instr *list);
int  mpls_instrs_build(struct mpls_instr_elem *mie,
				struct mpls_instr **instr, int length,
				enum mpls_dir dir, void *parent);
void mpls_instrs_unbuild(struct mpls_instr *instr,
				struct mpls_instr_req *req);

/****************************************************************************
 * Layer 3 protocol driver
 *
 * most of this code is taken from DaveM&JHadi implementation
 ****************************************************************************/
#define MPLSPROTONAMSIZ 16
struct mpls_prot_driver {
	atomic_t __refcnt;
	struct list_head list;

	unsigned short family;
	unsigned short ethertype;
	char name[MPLSPROTONAMSIZ + 1];

	void (*cache_flush)(struct net *net);
	void (*set_ttl)(struct sk_buff *skb, int ttl);
	int  (*get_ttl)(struct sk_buff *skb);
	void (*change_dsfield)(struct sk_buff *skb, int ds);
	int	 (*get_dsfield)(struct sk_buff *skb);
	int	 (*ttl_expired)(struct sk_buff **skb);
	int	 (*mtu_exceeded)(struct sk_buff **skb, int mtu);
	int	 (*local_deliver)(struct sk_buff *skb);
	int	 (*nexthop_resolve)(struct dst_entry *,
		struct sockaddr *, struct net_device *);

	struct module *owner;
};

/****************************************************************************
 * Protocol driver Management
 * net/mpls/mpls_proto.c
 ****************************************************************************/

extern struct list_head mpls_proto_list;

int                      mpls_proto_add(struct mpls_prot_driver *);
int                      mpls_proto_remove(struct mpls_prot_driver *);
struct mpls_prot_driver *mpls_proto_find_by_family(unsigned short);
struct mpls_prot_driver *mpls_proto_find_by_ethertype(unsigned short);
void                     mpls_proto_cache_flush_all(struct net *);

static inline void mpls_proto_release(struct mpls_prot_driver *prot)
{
	if (!prot)
		return;
	atomic_dec(&prot->__refcnt);
	module_put(prot->owner);
	prot = NULL;
}

/****************************************************************************
 * MPLS INPUT INFO (ILM) OBJECT MANAGEMENT
 * net/mpls/mpls_ilm.c
 ****************************************************************************/

struct mpls_ilm {
	atomic_t				refcnt;
	struct kmem_cache		*kmem_cachep;
	struct list_head		global;
	/* To appear as an entry in the device ILM list */
	struct list_head		dev_entry;

	/* List of NHLFE */
	struct list_head        nhlfe_entry;
	/* Instructions to execute for this ILM  */
	struct mpls_instr      *ilm_instr;
	/* Incoming Label for this ILM */
	struct mpls_label        ilm_label;
	/* Key used to lookup this object in a data structure  */
	unsigned int             ilm_key;
	/* Jiffies */
	unsigned int             ilm_age;
	/* Incoming Labelspace (see doc) */
	unsigned short           ilm_labelspace;
	/* Routing protocol */
	unsigned char            ilm_owner;
};

extern struct list_head mpls_ilm_list;

/****************************************************************************
 * Input Radix Tree Management
 ****************************************************************************/

int               mpls_ilm_init(void);
void              mpls_ilm_exit(void);
struct mpls_ilm *mpls_get_ilm(unsigned int key);
struct mpls_ilm *mpls_get_ilm_by_label(struct mpls_label *label,
				int labelspace, char bos);
extern struct mpls_ilm *mpls_ilm_alloc(unsigned int key,
				struct mpls_label *ml,
				struct mpls_instr_elem *instr,
				int instr_len);



/****************************************************************************
 * MPLS OUTPUT INFO (NHLFE) OBJECT MANAGEMENT
 * net/mpls/mpls_nhlfe.c
 ****************************************************************************/

struct mpls_nhlfe {
	/* since most higher lay protocol operate on dst_entries, representing
	 * a NHLFE as a dst_entry make sense.  Higher layer protocols
	 * may hold references to the dst_entry.  The result is that
	 * a NHLFE may exist after the user deletes it from the RADIX tree.
	 */
	struct dst_entry	dst;

	struct list_head	global;

	/* List of notif*/
	struct notifier_block	*nhlfe_notifier_list;
	/* List of ILM that are linked to this NHLFE*/
	struct list_head        list_in;
	/* To be added into a device list_out if the NHLFE uses (SET) the dev */
	struct list_head        dev_entry;
	/* Array of instructions for this NHLFE*/
	struct mpls_instr      *nhlfe_instr;
	/* Key used to store/lookup a given NHLFE in the tree*/
	unsigned int            nhlfe_key;
	/* Age in jiffies*/
	unsigned int            nhlfe_age;
	/* MTU Limit (e.g. from device MTU + number of pushes*/
	unsigned short			nhlfe_mtu_limit;
	unsigned char           nhlfe_propagate_ttl;

	/* Routing protocol */
	unsigned char           nhlfe_owner;

	union {
		struct sockaddr			common;
		struct sockaddr_in		ipv4;
		struct sockaddr_in6		ipv6;
	} nhlfe_nexthop;

	/* L3 protocol driver for packets that use this NHLFE */
	struct mpls_prot_driver *nhlfe_proto;
};
#define nhlfe_nh nhlfe_nexthop.common

#define MPLS_INVALID_MTU 0xFFFF

extern struct list_head mpls_nhlfe_list;

struct mpls_fwd_block {
	struct notifier_block notifier_block;
	struct mpls_nhlfe *owner;
	struct mpls_nhlfe *fwd;
};

/****************************************************************************
 * Output Radix Tree Management
 ****************************************************************************/

int                 mpls_nhlfe_init(void);
void                mpls_nhlfe_exit(void);
struct mpls_nhlfe	*mpls_get_nhlfe(unsigned int);


/****************************************************************************
 * Helper Functions
 ****************************************************************************/

char                mpls_find_payload(struct sk_buff *skb);
unsigned int        mpls_label2key(const int, const struct mpls_label*);


/****************************************************************************
 * INCOMING (INPUT) LABELLED PACKET MANAGEMENT
 * net/mpls/mpls_input.c
 ****************************************************************************/

int  mpls_skb_recv(struct sk_buff *skb,
	struct net_device *dev, struct packet_type *ptype,
	struct net_device *orig);


/****************************************************************************
 * OUTGOING (OUTPUT) LABELLED PACKET MANAGEMENT
 * net/mpls/mpls_output.c
 ****************************************************************************/

int  mpls_set_nexthop2(struct mpls_nhlfe *nhlfe, struct dst_entry *dst);
int  mpls_output(struct sk_buff *skb);
int  mpls_switch(struct sk_buff *skb);

/****************************************************************************
 * INPUT/OUTPUT INSTRUCTION OPCODES
 * net/mpls/{mpls_opcode,mpls_opcode_in,mpls_opcode_out}.c
 *
 ****************************************************************************/

/*
 * pskb:       Socket buffer. May be modified [OUT]
 * ilm:       ILM entry object that owns this opcode.
 * nhlfe:       NHLFE entry to apply. May be modified (e.g. MTU) [OUT]
 * data:      opcode dependant data. Cast to NHLFEs, DS marks, etc.
 */
#define MPLS_OPCODE_PROTOTYPE(NAME) \
int (NAME) (struct sk_buff **pskb, struct mpls_ilm *ilm, \
	struct mpls_nhlfe **nhlfe, void *data)

/*
 * instr:     Instruction array.
 * direction: MPLS_IN (ILM) or MPLS_OUT(NHLFE)
 * parent:    ILM/NHLFE parent object for opcode.
 * data:      opcode dependant data. [OUT]
 * last_able: Nonzero if this can be the last opcode. [OUT]
 */
#define MPLS_BUILD_OPCODE_PROTOTYPE(NAME) \
int (NAME) (struct mpls_instr_elem *instr, \
	enum mpls_dir direction, void *parent,\
	void **data, int *last_able)

/*
 * instr:     Instruction array.
 * data:      opcode dependant data. [OUT]
 */
#define MPLS_UNBUILD_OPCODE_PROTOTYPE(NAME) \
void (NAME) (struct mpls_instr_elem *instr, void *data)

/*
 * data:      opcode dependant data.
 * parent:    ILM/NHLFE parent object for opcode.
 * direction: MPLS_IN (ILM) or MPLS_OUT(NHLFE)
 */
#define MPLS_CLEAN_OPCODE_PROTOTYPE(NAME) \
void (NAME) (void *data, void *parent, enum mpls_dir direction)

#define MPLS_IN_OPCODE_PROTOTYPE(NAME)  MPLS_OPCODE_PROTOTYPE(NAME)
#define MPLS_OUT_OPCODE_PROTOTYPE(NAME) MPLS_OPCODE_PROTOTYPE(NAME)

struct mpls_ops {
	MPLS_IN_OPCODE_PROTOTYPE(*in);
	MPLS_OUT_OPCODE_PROTOTYPE(*out);
	MPLS_BUILD_OPCODE_PROTOTYPE(*build);
	MPLS_UNBUILD_OPCODE_PROTOTYPE(*unbuild);
	MPLS_CLEAN_OPCODE_PROTOTYPE(*cleanup);
	int  extra;
	char *msg;
};

/* Array holding opcodes */
extern struct mpls_ops mpls_ops[];

/**
 * mpls_label_entry_peek - Peek the topmost label entry from the stack.
 *
 * @skb: Socket buffer.
 **/

static inline void mpls_label_entry_peek(struct sk_buff *skb)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	u32 shim;

	memcpy(&shim, skb_network_header(skb), MPLS_HDR_LEN);
	shim = ntohl(shim);

	if (!cb->flag) {
		cb->ttl  = __MPLS_SHIM_TTL(shim);
		cb->flag = 1;
	}
	cb->bos = __MPLS_SHIM_S_BIT(shim);
	cb->exp = __MPLS_SHIM_EXP(shim);
	cb->label = __MPLS_SHIM_LABEL(shim);
}

static inline void mpls_nhlfe_update_mtu(
	struct mpls_nhlfe *nhlfe, unsigned short mtu)
{
	dst_metric_set(&nhlfe->dst, RTAX_MTU,
		mtu - nhlfe->dst.header_len);
	nhlfe->nhlfe_mtu_limit = dst_mtu(&nhlfe->dst);
}

/* Query/Update Incoming Labels */
struct mpls_ilm *mpls_add_in_label(const struct mpls_in_label_req *in);
struct mpls_ilm *mpls_get_ilm_label(const struct mpls_in_label_req *in);
int  mpls_del_in_label(struct mpls_in_label_req *in,
	int seq, int pid);
int  mpls_add_reserved_label(int label, struct mpls_ilm *ilm);
struct mpls_ilm *mpls_del_reserved_label(int label);
int mpls_ilm_set_instrs(struct mpls_in_label_req *mil,
	struct mpls_instr_elem *mie, int length);
int _mpls_ilm_set_instrs(struct mpls_ilm *ilm,
	struct mpls_instr_elem *mie, int length);
int mpls_del_ilm(struct mpls_ilm *ilm,
	int seq, int pid);

/* Query/Update Outgoing Labels */
struct mpls_nhlfe *mpls_add_out_label(struct mpls_out_label_req *out);
struct mpls_nhlfe *mpls_get_nhlfe_label(struct mpls_out_label_req *out);
int mpls_del_out_label(struct mpls_out_label_req *out,
	int seq, int pid);
int mpls_set_out_label_mtu(struct mpls_out_label_req *out);
int mpls_nhlfe_set_instrs(struct mpls_out_label_req *mol,
	struct mpls_instr_elem *mie, int length);
int mpls_del_nhlfe(struct mpls_nhlfe *nhlfe,
	int seq, int pid);

/* Query/Update Crossconnects */
int mpls_attach_in2out(struct mpls_xconnect_req *req,
	int seq, int pid);
int mpls_detach_in2out(struct mpls_xconnect_req *req,
	int seq, int pid);

/* Instruction Management */
int mpls_set_out_label_propagate_ttl(struct mpls_out_label_req *mol);

void mpls_destroy_nhlfe_instrs(struct mpls_nhlfe *nhlfe);
void mpls_destroy_ilm_instrs(struct mpls_ilm  *ilm);
int  mpls_instr_init(void);
void mpls_instr_exit(void);

/* Return last instruction of a list */
static inline struct mpls_instr *mpls_instr_getlast(struct mpls_instr *instr)
{
	struct mpls_instr *mi;
	for (mi = instr; mi->mi_next; mi = mi->mi_next);/* noop */
	return mi;
}

/* return number of instructions */
static inline int mpls_no_instrs(struct mpls_instr *instr)
{
	struct mpls_instr *mi;
	int no = 0;
	MPLS_ENTER;
	for_each_instr(instr, mi) {
		no++;
	}
	MPLS_EXIT;
	return no;
}

/* Query/Update Labelspaces */
static inline int __mpls_get_labelspace(struct net_device *dev)
{
	struct mpls_interface *mif = dev->mpls_ptr;
	return mif ? mif->labelspace : -1;
}

int mpls_set_labelspace(struct mpls_labelspace_req *req,
	int seq, int pid);

/* Netlink event notification */
int mpls_ilm_event(char *grp_name, int event,
	struct mpls_ilm *ilm, int seq, int pid);
int mpls_nhlfe_event(char *grp_name, int event,
	struct mpls_nhlfe *nhlfe, int seq, int pid);
int mpls_labelspace_event(char *grp_name, int event,
	struct net_device *dev, int seq, int pid);
int mpls_xc_event(char *grp_name, int event,
	struct mpls_ilm *ilm, struct mpls_nhlfe *nhlfe,
	int seq, int pid);

/****************************************************************************
 * REFERENCE COUNT MANAGEMENT
 ****************************************************************************/

/* Hold */
static inline struct mpls_ilm *mpls_ilm_hold(struct mpls_ilm *ilm)
{
	BUG_ON(!ilm);
	atomic_inc(&ilm->refcnt);
	return ilm;
}


/* Release */
static inline void mpls_ilm_release(struct mpls_ilm *ilm)
{
	BUG_ON(!ilm);
	if (atomic_dec_and_test(&ilm->refcnt))
		kmem_cache_free(ilm->kmem_cachep, ilm);
}


/* Hold */
static inline struct mpls_nhlfe *mpls_nhlfe_hold(struct mpls_nhlfe *nhlfe)
{
	BUG_ON(!nhlfe);
	dst_hold(&nhlfe->dst);
	return nhlfe;
}

/* Release */
static inline void mpls_nhlfe_release(struct mpls_nhlfe *nhlfe)
{
	BUG_ON(!nhlfe);
	dst_release(&nhlfe->dst);
}

static inline void mpls_nhlfe_release_safe(struct mpls_nhlfe **nhlfe)
{
	if (*nhlfe)
		mpls_nhlfe_release(*nhlfe);
	*nhlfe = NULL;
}

/* Drop */
static inline void mpls_nhlfe_drop(struct mpls_nhlfe *nhlfe)
{
	mpls_nhlfe_release(nhlfe);
	call_rcu_bh(&nhlfe->dst.rcu_head, dst_rcu_free);
}

/****************************************************************************
 * sysctl Implementation
 * net/mpls/sysctl_net_mpls.c
 ****************************************************************************/

int   mpls_sysctl_init(void);
void  mpls_sysctl_exit(void);

/****************************************************************************
 * Proc Implementation
 * net/mpls/mpls_proc.c
 ****************************************************************************/

int   mpls_proc_init(struct net *net);
void  mpls_proc_exit(struct net *net);

/****************************************************************************
 * NetLink Implementation
 * net/mpls/mpls_netlink.c
 ****************************************************************************/

int  mpls_netlink_init(void);
void mpls_netlink_exit(void);

/****************************************************************************
 * net/mpls/mpls_shim.c
 *
****************************************************************************/

void mpls_shim_init(void);
void mpls_shim_exit(void);

/****************************************************************************
 * Virtual Intefaces (Tunnel) Management
 * (e.g. mpls0, mpls1, TXXethN, etc.)
 * net/mpls/mpls_tunnel.c
 ****************************************************************************/

struct mpls_tunnel_private {
	/* NHLFE Object to apply to this tunnel traffic */
	struct mpls_nhlfe             *mtp_nhlfe;
	/* Netdevice for this tunnel                  */
	struct net_device             *mtp_dev;
	/* Next tunnel in list                        */
	struct mpls_tunnel_private    *next;
	/* Netdevice (this tunnel) traffic stats      */
	struct net_device_stats        stat;
};


struct net_device *mpls_tunnel_get_by_name(const char *name);
struct net_device *mpls_tunnel_get(struct mpls_tunnel_req *mt);
void               mpls_tunnel_put(struct net_device *dev);
struct net_device *mpls_tunnel_create(struct mpls_tunnel_req *mt);
void               mpls_tunnel_destroy(struct mpls_tunnel_req *mt);

/* Casts */
#define _mpls_as_if(PTR)    ((struct mpls_interface *)(PTR))
#define _mpls_as_label(PTR) ((struct mpls_label *)(PTR))
#define _mpls_as_ilm(PTR)   ((struct mpls_ilm *)(PTR))
#define _mpls_as_nhlfe(PTR) ((struct mpls_nhlfe *)(PTR))
#define _mpls_as_dfi(PTR)   ((struct mpls_dsmark_fwd_info *)(PTR))
#define _mpls_as_nfi(PTR)   ((struct mpls_nfmark_fwd_info *)(PTR))
#define _mpls_as_efi(PTR)   ((struct mpls_exp_fwd_info *)(PTR))
#define _mpls_as_netdev(PTR)((struct net_device *)(PTR))

#endif
