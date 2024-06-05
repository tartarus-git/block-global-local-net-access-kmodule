#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

// TODO: finish this thought.
//static struct in6_addr

static unsigned int netfilter_ipv6_hook_callback(unsigned int hooknum,
					    struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	if (state->out == outiface) {
		const struct ipv6hdr *ipv6_header = ipv6_hdr(skb);
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
