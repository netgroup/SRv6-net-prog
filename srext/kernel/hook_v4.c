/*
 *  SR-IPv6 implementation
 *
 *  Authors:
 *  Stefano Salsano <stefano.salsano@uniroma2.it>
 *  Ahmed Abdelsalam <ahmed.abdelsalam@gssi.it>
 *  Giuseppe Siracusano <giu.siracusano@gmail.com>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/netfilter_ipv4.h>
#include <net/ip6_route.h>
#include "../include/sr_hook.h"

#define AUTHOR "HOOK_V4"
#define DESC   "HOOK_V4"

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL");

static struct nf_hook_ops hook_v4_ops_pre;

/**
 * ip6_route_input()
 * used to input packets, after applying encap behavior, into the routing subsystem
 */
void ip6_route_input(struct sk_buff *skb)
{
    const struct ipv6hdr *iph = ipv6_hdr(skb);
    struct net *net = dev_net(skb->dev);
    int flags = RT6_LOOKUP_F_HAS_SADDR;
    struct flowi6 fl6 = {
        .flowi6_iif = skb->dev->ifindex,
        .daddr = iph->daddr,
        .saddr = iph->saddr,
        .flowlabel = ip6_flowinfo(iph),
        .flowi6_mark = skb->mark,
        .flowi6_proto = iph->nexthdr,
    };

    skb_dst_set(skb, ip6_route_input_lookup(net, skb->dev, &fl6, flags));
}

/**
 * hook_v4_pre_routing()
 * main packet processing function
 * called for every recieved IPv4 packet
 */

unsigned int hook_v4_pre_routing(void* priv, struct sk_buff * skb,
                                 const struct nf_hook_state * state)
{
    struct ipv6hdr* iph;
    struct sid6_info *s6;
    struct sdev_info *sdev;

    rcu_read_lock();
    sdev = sdev_lookup(skb->dev->name);
    if (sdev == NULL)
        goto exit_accept;

    sdev->func(skb, sdev);

lookup:
    iph = ipv6_hdr(skb);
    s6 = sid_lookup(iph->daddr);

    if (s6 == NULL) {
        ip6_route_input(skb);
        goto exit_accept;
    }
    if ((s6->func(skb, s6)) == 1)
        goto lookup;

    goto exit_stolen;

exit_accept:
    rcu_read_unlock();
    return NF_ACCEPT;

exit_stolen:
    rcu_read_unlock();
    return NF_STOLEN;
}

/***************************************************************************************************
****************************** INITIALIZATION AND EXIT FUNCTIONS  **********************************
***************************************************************************************************/

/**
 * hook_v4_register()
 * HOOK_V4 initialization function
 */

int hook_v4_register(void)
{
    int ret = 0;

    /* Register the filtering function */
    hook_v4_ops_pre.hook = hook_v4_pre_routing;
    hook_v4_ops_pre.pf = PF_INET;
    hook_v4_ops_pre.hooknum = NF_INET_PRE_ROUTING;
    hook_v4_ops_pre.priority = NF_IP_PRI_LAST;

    /* register NF_IP_PRE_ROUTING hook */
    ret = nf_register_net_hook(&init_net,&hook_v4_ops_pre);

    if (ret < 0) {
        printk(KERN_INFO "Sorry, registering %s failed with %d \n", DESC , ret);
        return ret;
    }
    printk(KERN_INFO "HOOK_V4 successfully registered (%d)!\n", ret);
    return 0;
}

/**
 * hook_v4_unregister()
 * HOOK_V4 exit function
 */

int hook_v4_unregister(void)
{
    /* Unregister the filtering function*/
    nf_unregister_net_hook(&init_net,&hook_v4_ops_pre);
    memset(&hook_v4_ops_pre, 0, sizeof(struct nf_hook_ops));
    printk(KERN_INFO "HOOK_V4 released.\n");
    return 0;
}

