#include <net/shim.h>

/**
 *	mpls_uc_shim - "SPECIAL" next hop Management for MPLS UC traffic.
 *	@name: name of the struct.
 *	@build: Callback used to build
 * 
 *	build is function is initialized 
 *	in mpls_shim_init(), and destroyed in mpls_shim_exit()
 *
 *	e.g. for a MPLS enabled iproute2:
 *	ip route add a.b.c.d/n via x.y.z.w shim mpls 0x2
 *	The key (0x2) is the "data" for NHLFE lookup.
 **/
struct shim mpls_uc_shim = {
	.name = "mpls",
	.build = NULL,
};
EXPORT_SYMBOL(mpls_uc_shim);
