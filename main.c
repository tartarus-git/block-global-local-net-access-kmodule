#include <linux/types.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

static struct simple_in6_addr_list {
	struct in6_addr addr;
	struct list_head list;
};

LIST_HEAD(iface_global_ipv6_cache);

static bool ipv6_has_same_prefix(const in6_addr *a_addr, const in6_addr *b_addr) {
	for (__u8 i = 0; i < 8; i++) {
		if (a_addr->in6_u.u6_addr8[i] != b_addr->in6_u.u6_addr8[i]) { return false; }
	}
	return true;
}

static unsigned int netfilter_ipv6_hook_callback(unsigned int hooknum,
					    struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	if (state->out == outiface) {
		const struct ipv6hdr *ipv6_header = ipv6_hdr(skb);

		struct simple_in6_addr_list *ipv6_iter_ptr;
		list_for_each_entry(ipv6_iter_ptr, &iface_global_ipv6_cache, list)
		{
			if (ipv6_has_same_prefix(&ipv6_header.saddr, &ipv6_iter_ptr.addr)) {
				return NF_DROP;
			}
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops netfilter_hook_options = {
	.hook = netfilter_ipv6_hook_callback,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = NFPROTO_IPV6,
	.priority = NF_IP6_PRI_LAST
};

int init_module(void) {
	if (nf_register_net_hook(&init_net, &netfilter_hook_options) < 0) {
		printk(KERN_ERR "%s can't register netfilter hook\n", __func__);
		return -1;
	}

	return 0;
}

void cleanup_module(void) {
	nf_unregister_net_hook(&init_net, &netfilter_hook_options);
}

MODULE_DESCRIPTION("IPv6 TCP/UDP netfilter hook to filter out packets aimed at global IPv6s of local network devices")
MODULE_LICENSE("GPL")
MODULE_VERSION("1.0.0")
