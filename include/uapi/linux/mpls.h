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

#define MPLS_LINUX_VERSION (0x02000001)

#define MPLS_MASTER_DEV "mpls0"

#define MPLS_HDR_LEN (sizeof(u32))

#define TC_MAX ((1 << 3) - 1)
#define DSCP_MAX ((1 << 8) - 1)

enum {
	MPLS_ATTR_PUSH_UNSPEC,
	MPLS_PUSH_1,
	MPLS_PUSH_2,
	MPLS_PUSH_3,
	MPLS_PUSH_4,
	MPLS_PUSH_5,
	MPLS_PUSH_6,
	MPLS_NO_PUSHES,
#define MPLS_PUSH_MAX MPLS_NO_PUSHES
	__MPLS_ATTR_PUSH_MAX,
};
#define MPLS_ATTR_PUSH_MAX (__MPLS_ATTR_PUSH_MAX - 1)

enum {
	MPLS_ATTR_UNSPEC,
	MPLS_ATTR_POP,
	MPLS_ATTR_DSCP,
	MPLS_ATTR_TC_INDEX,
	MPLS_ATTR_SWAP,
	MPLS_ATTR_PUSH,
	MPLS_ATTR_PEEK, /* must be last instruction */
	MPLS_ATTR_SEND_IPv4, /* must be last instruction */
	MPLS_ATTR_SEND_IPv6, /* must be last instruction */
	MPLS_ATTR_INSTR_COUNT, /* not a instruction */
#define MPLS_ATTR_INSTR_MAX MPLS_ATTR_INSTR_COUNT
	__MPLS_ATTR_MAX,
};
#define MPLS_ATTR_MAX (__MPLS_ATTR_MAX - 1)

struct mpls_nh {
	__u32 iface;
	union {
		struct sockaddr addr;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};

struct mpls_key {
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			__u32 label_u:4;
			__u32 label_l:16;
#elif defined (__BIG_ENDIAN_BITFIELD)
			__u32 label_l:16;
			__u32 label_u:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
			__u8 tc:3;
			__u16 owner:8;
			__u8 __pad1:1;
		};
		struct {
			__u32 label:20;
			__u16 __pad2:12;
		};
	};
};

struct ilmsg {
	union {
		struct {
			__u8 family;
			__u8 tc;
			__u8 owner;   /* Routing protocol */
			struct mpls_key key;
		};
		/* padding to pass rtnetlink min_len check */
		struct rtmsg __pad;
	};
};

#endif
