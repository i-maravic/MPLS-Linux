#ifndef _UAPI__LINUX_MPLS_H_
#define _UAPI__LINUX_MPLS_H_

#include <asm/byteorder.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#if !(defined _NET_IF_H)
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#define MPLS_LINUX_VERSION (0x02000002)

#define MPLS_MASTER_DEV "mpls0"

#define TC_MAX ((1 << 3) - 1)
#define DSCP_MAX ((1 << 8) - 1)
#define POP_ALL ((1 << 8) - 1)

enum mplsattr_type_t {
	MPLSA_UNSPEC,
	MPLSA_POP,
	MPLSA_DSCP,
	MPLSA_TC_INDEX,
	MPLSA_SWAP,
	MPLSA_PUSH,
	MPLSA_NEXTHOP_OIF,
	MPLSA_NEXTHOP_ADDR,
	__MPLS_ATTR_MAX,
};
#define MPLS_ATTR_MAX (__MPLS_ATTR_MAX - 1)

struct mpls_hdr {
	__be16	label_msb;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32	s:1;
	__u32	tc:3;
	__u32	label_lsb:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u32	label_lsb:4;
	__u32	tc:3;
	__u32	s:1;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	ttl;
};
#define MPLS_HDR_LEN	sizeof(struct mpls_hdr)

static inline __u32 mpls_hdr_label(const struct mpls_hdr *hdr)
{
	return (ntohs(hdr->label_msb) << 4) | hdr->label_lsb;
}

static inline void mpls_hdr_set_label(struct mpls_hdr *hdr, __u32 label)
{
	hdr->label_msb = htons(label >> 4);
	hdr->label_lsb = label & 0xf;
}

#endif
