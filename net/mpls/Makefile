#
# Makefile for the Linux MPLS layer.
#

mpls-y := af_mpls.o mpls_if.o mpls_ilm.o mpls_init.o mpls_input.o \
	mpls_opcode.o mpls_nhlfe.o mpls_output.o \
	mpls_utils.o mpls_netlink.o mpls_proto.o \
	mpls_instr.o mpls_shim.o
mpls-$(CONFIG_SYSCTL) += sysctl_net_mpls.o
mpls-$(CONFIG_PROC_FS) += mpls_proc.o

obj-$(CONFIG_MPLS) += mpls.o
obj-$(CONFIG_MPLS_TUNNEL) += mpls_tunnel.o
