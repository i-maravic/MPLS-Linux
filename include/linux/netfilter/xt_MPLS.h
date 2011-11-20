#ifndef _XT_MPLS_H_target
#define _XT_MPLS_H_target

struct xt_MPLS_target_info {
	u_int32_t key;

	/* only used by the netfilter kernel modules */
#ifdef __KERNEL__
	void *nhlfe;
	void *proto;
#endif
};

#endif /*_XT_MPLS_H_target */
