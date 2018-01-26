/**
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
#include <linux/inet.h>
#include <linux/rwlock.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <linux/icmpv6.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <net/ip6_route.h>

#include "../include/seg6.h"
#include "../include/sr_genl.h"
#include "../include/sr_hook.h"
#include "../include/hook_v4.h"
#include "../include/sr_errno.h"

#define AUTHOR "SREXT"
#define DESC   "SREXT"

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL");

#define DEBUG

#ifdef DEBUG
#define debug(fmt, args) dmesg(fmt,args)
#define debug_err(fmt, args) dmesg_err(fmt,args)
#else
#define debug(fmt, args)     /* not debugging: nothing */
#define debug_err(fmt, args) /* not debugging: nothing */
#endif

#define TABLE_SIZE 5  // 32 entries

static DEFINE_HASHTABLE(sid_tbl, TABLE_SIZE);    /* localsid table */
static DEFINE_HASHTABLE(sdev_tbl, TABLE_SIZE);   /* srdev table    */
static struct nf_hook_ops sr_ops_pre;

rwlock_t sr_rwlock;

/***************************************************************************************************
********************************** SREXT helper functions ******************************************
***************************************************************************************************/

/**
 * dmesg()
 * Wrapping printk to add module name
 */
void dmesg( const char * format, ...)
{
    va_list ap;
    va_start(ap, format);
    printk("[SREXT]");
    vprintk(format, ap);
    va_end(ap);
}

/**
 * dmesg_err()
 * Wrapping printk to add module name and error string
 */
void dmesg_err( const char * format, ...)
{
    va_list ap;
    va_start(ap, format);
    printk("[SREXT][Error]");
    vprintk(format, ap);
    va_end(ap);
}

/**
 * print_mac()
 * Prints a MAC address to a string
 * @mac: MAC address to be printed
 * @out: output string
 */

static void print_mac(unsigned char *mac, char *out)
{
    sprintf(out + strlen(out), "%02x:%02x:%02x:%02x:%02x:%02x\n",
            (unsigned char) mac[0],
            (unsigned char) mac[1],
            (unsigned char) mac[2],
            (unsigned char) mac[3],
            (unsigned char) mac[4],
            (unsigned char) mac[5]);
}

/**
 * print_nh_mac()
 * Wrapping print_mac() to print next hop MAC address of a sid
 * @mac: MAC address to be printed
 * @out: output string
 */

static void print_nh_mac(unsigned char *mac, char *out)
{
    sprintf(out + strlen(out), "\t Next hop:        ");
    print_mac(mac, out);
}

/**
 * decap2()
 * Decapsulates outer IPv6 header and it's extensions for L2 traffic encapsulated with T.encaps.L2
 * @skb: packet buffer
 * @s6:  localsid table entry
 * @innoff: the offset of L2 frame
 * @srhoff: the offset of SRH
 * @save: Flag - decides whether to save the decapsulated headers or not
 */

int decap2(struct sk_buff * skb, struct sid6_info * s6, int innoff, int srhoff, int save)
{
    int ret = 0;

    if (!save)
        goto decap;

    if ((ret = sdev_add(s6->iif, s6->behavior, skb->data, innoff, srhoff)) != 0)
        goto end;
decap:
    pskb_pull(skb, innoff);
    skb_postpull_rcsum(skb, skb_network_header(skb), innoff);
end:
    return ret ;
}

/**
 * decap4()
 * Decapsulates outer IPv6 header and it's extensions for IPv4 traffic encapsulated with T.encaps
 * @skb: packet buffer
 * @s6 : localsid table entry
 * @innoff: the offset of innner packet
 * @srhoff: the offset of SRH
 * @save: Flag - decides whether to save the decapsulated headers or not
 */

int decap4(struct sk_buff * skb, struct sid6_info * s6, int innoff, int srhoff, int save)
{
    int ret = 0;
    struct iphdr *iph;
    char * err_msg = "decap4 - ";

    if (!save)
        goto decap;

    if ((ret = sdev_add(s6->iif, s6->behavior, skb->data, innoff, srhoff)) != 0)
        goto end;
decap:
    pskb_pull(skb, innoff);
    skb_postpull_rcsum(skb, skb_network_header(skb), innoff);
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);

    if (iph->ttl <= 1) {
        debug_err("%s inner packet can not be forwarded, ttl is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        return -1;
    }

    iph->ttl --;
    ip_send_check(iph);
    skb->protocol = htons(ETH_P_IP);
    skb_set_transport_header(skb, iph->ihl * 4);
end:
    return ret ;
}

/**
 * decap6()
 * Decapsulates outer IPv6 header and it's extensions for IPv6 traffic encapsulated with T.encaps
 * @skb: packet buffer
 * @s6 : localsid table entry
 * @innoff: the offset of innner packet
 * @srhoff: the offset of SRH
 * @save: Flag - decides whether to save the decapsulated headers or not
 */

int decap6(struct sk_buff * skb, struct sid6_info * s6, int innoff, int srhoff, int save)
{
    int ret = 0;
    struct ipv6hdr *ip6h;
    char * err_msg = "decap6 - ";

    if (!save)
        goto decap;

    if ((ret = sdev_add(s6->iif, s6->behavior, skb->data, innoff, srhoff)) != 0)
        goto end;
decap:
    pskb_pull(skb, innoff);
    skb_postpull_rcsum(skb, skb_network_header(skb), innoff);
    skb_reset_network_header(skb);

    ip6h = ipv6_hdr(skb);
    if (ip6h->hop_limit <= 1) {
        debug_err("%s inner packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        return -1;
    }

    ip6h->hop_limit --;
    skb_set_transport_header(skb, sizeof(struct ipv6hdr));
end:
    return ret ;
}

/**
 * encap()
 * Re-adds saved SRv6 encapsulation to packets coming from SR-unaware VNF
 * used by some SRv6 begaviors (e.g., End.AD4, End.EAD4, End.AD6, and End.EAD6)
 * @skb: packet buffer
 * @sdev: srdev table entry
 */

int encap(struct sk_buff * skb, struct sdev_info * sdev)
{
    int err;
    if (unlikely((err = pskb_expand_head(skb, sdev->len, 0, GFP_ATOMIC)))) {
        printk(KERN_INFO "%s \n", "SREXT cannot expand head - nomem ");
        return err;
    }

    skb_push(skb, sdev->len);
    memcpy(skb->data, sdev->data, sdev->len);
    skb_reset_network_header(skb);
    skb_mac_header_rebuild(skb);
    ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
    skb_set_transport_header(skb, sdev->srhoff);
    skb_postpush_rcsum(skb, skb->data, sdev->len);
    return 0;
}

/**
 * xcon2()
 * Cross-connects to a layer-2 adjacency
 * used by some SRv6 behaviors (e.g., End.DX2)
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int xcon2(struct sk_buff* skb, struct sid6_info *s6)
{
    struct net_device* dev;
    char * err_msg = "xcon2 - ";

    if (s6->oif == NULL) {
        debug_err("%s Can't send to NULL \n", err_msg);
        return -1;
    }

    dev = dev_get_by_name(&init_net, s6->oif);
    if (!dev) {
        debug_err("%s no such interface \n", err_msg);
        return -1;
    }

    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    update_counters(s6, skb->len, 1);
    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
        return -1;

    return 0;
}

/**
 * xcon4()
 * Cross-connects to a IPv4 layer-3 adjacency
 * used by some SRv6 behaviors (e.g., End.AD4, End.EDA4, End.DX4, etc.)
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int xcon4(struct sk_buff * skb, struct sid6_info * s6)
{
    struct net_device* dev;
    struct neighbour *neigh;
    const struct hh_cache *hh;
    u32 nexthop;
    char * err_msg = "xcon6 - ";

    if (s6->oif == NULL) {
        debug_err("%s Can't send to NULL \n", err_msg);
        return -1;
    }

    dev = dev_get_by_name(&init_net, s6->oif);
    if (!dev) {
        debug_err("%s no such interface \n", err_msg);
        return -1;
    }

    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    if (s6->mc)
        goto mac;

    nexthop = (__force u32) (s6->nh_ip.s_addr);
    neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
    if (unlikely(!neigh))
        neigh = __neigh_create(&arp_tbl, &s6->nh_ip, dev, false);

    if (!IS_ERR(neigh)) {
        update_counters(s6, skb->len, 1);
        hh = &neigh->hh;
        if ((neigh->nud_state & NUD_CONNECTED) && hh->hh_len)
            return neigh_hh_output(hh, skb);
        else
            return neigh->output(neigh, skb);
    }

mac:
    dev_hard_header(skb, skb->dev, ETH_P_IP, s6->nh_mac, NULL, skb->len);
    update_counters(s6, skb->len, 1);
    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
        return -1;

    return 0;
}

/**
* xcon6()
* Cross-connects to a IPv6 layer-3 adjacency
* used by some SRv6 behaviors (e.g., End.AD6, End.EAD6, End.AM, End.X, End.DX6, etc.)
* @skb: packet buffer
* @s6 : localsid table entry
*/

int xcon6(struct sk_buff * skb, struct sid6_info * s6)
{
    struct net_device* dev;
    struct neighbour *neigh;
    const struct hh_cache *hh;
    char * err_msg = "xcon6 - ";

    if (s6->oif == NULL) {
        debug_err("%s Can't send to NULL \n", err_msg);
        return -1;
    }

    dev = dev_get_by_name(&init_net, s6->oif);
    if (!dev) {
        debug_err("%s no such interface \n", err_msg);
        return -1;
    }
    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    if (s6->mc)
        goto mac;

    /*
     * using Linux Neighbouring Subsystem to get MAC address of the next hop
     * similar to ip6_finish_output2() in /net/ipv6/ip6_output.c
     */

    neigh = __ipv6_neigh_lookup_noref(dev, &s6->nh_ip6);
    if (unlikely(!neigh))
        neigh = __neigh_create(&nd_tbl, &s6->nh_ip6, dev, false);

    if (!IS_ERR(neigh)) {
        update_counters(s6, skb->len, 1);
        hh = &neigh->hh;
        if ((neigh->nud_state & NUD_CONNECTED) && hh->hh_len)
            return neigh_hh_output(hh, skb);
        else
            return neigh->output(neigh, skb);
    }

mac:
    dev_hard_header(skb, skb->dev, ETH_P_IPV6, s6->nh_mac, NULL, skb->len);
    update_counters(s6, skb->len, 1);
    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
        return -1;

    return 0;
}

/***************************************************************************************************
******************************** Operations on tables **********************************************
***************************************************************************************************/

/**
 * sid_lookup()
 * Lookup function into localsid table
 * @sid: SRv6 SID to be found
 * Returns a pointer to the sid6_info (NULL if SID not found)
 */

struct sid6_info *sid_lookup(struct in6_addr sid)
{
    u32 key;
    struct sid6_info *s6;

    key = ipv6_addr_hash(&sid);
    hash_for_each_possible_rcu(sid_tbl, s6, hnode, key) {
        if (ipv6_addr_cmp(&s6->sid, &sid) == 0) {
            return s6;
        }
    }
    return NULL;
}

/**
 * sdev_lookup()
 * Lookup function into srdev table
 * @ifname: interface to be found
 * Returns a pointer to sdev_info (NULL if interface not found)
 */

struct sdev_info * sdev_lookup(char* ifname)
{
    u32 key;
    struct sdev_info *sdev;

    key = jhash(ifname, strlen(ifname), 0) ;
    hash_for_each_possible_rcu(sdev_tbl, sdev, hnode, key) {
        if (strcmp(sdev->iif, ifname) == 0) {
            return sdev;
        }
    }
    return NULL;
}

/**
 * update_counters()
 * Updates counters of a localsid table entry
 * @s6: localsid table entry
 * @good: decides whether to update good or bad counters
 * @len: payload length of the packet triggered this update
 */

int update_counters(struct sid6_info * s6, int len, int good)
{
    write_lock_bh(&sr_rwlock);
    if (good) {
        s6->good_pkts ++;
        s6->good_bytes += len;
        goto end;
    }
    s6->bad_pkts  ++;
    s6->bad_bytes += len;
end:
    write_unlock_bh(&sr_rwlock);
    return 0;
}

/**
 * sdev_add()
 * Adds an entry to srdev table
 * used by some SRv6 functions (e.g., End.AD4, End.EAD4, End.AD6, End.EAD6, and End.AM)
 * @ifname: source interface
 * @behavior: SRv6 behavior
 * @buf: data buffer to be saved in memory
 * @size: number of bytes to be saved
 * @srhoff: offset of SRH in the buf
 */

int sdev_add(char* ifname, int behavior, void *buf , int size, int srhoff)
{
    int ret = 0;
    u32 hash_key;
    char * iif;
    void * data;
    struct sdev_info *sdev, *temp;
    char * err_msg = "sdev_add - ";

    temp = sdev_lookup(ifname) ;
    if (temp != NULL ) {
        if (behavior == END_AM_CODE)
            return 0;
        if (memcmp(temp->data, buf, size) == 0)
            return 0;
    }

    sdev = kmalloc(sizeof(*sdev), GFP_ATOMIC);
    if (!sdev) {
        debug_err("%s could not allocate memory \n", err_msg);
        return NOMEM;
    }

    data  = kmalloc(size, GFP_ATOMIC);
    if (!data) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret = NOMEM;
        goto err;
    }

    iif = kmalloc(strlen(ifname), GFP_ATOMIC);
    if (!iif) {
        debug_err("%s could not allocate memory \n", err_msg);
        kfree(data);
        ret =  NOMEM;
        goto err;
    }

    memcpy(data, buf, size);
    strcpy(iif, ifname);
    sdev->iif = iif;
    sdev->behavior = behavior;
    sdev->data = data;
    sdev->len = size;
    sdev->srhoff = srhoff;

    switch (behavior) {
    case END_AD6_CODE:
        sdev->func = encap;
        break;
    case END_AM_CODE:
        sdev->func = end_am_demasq;
        break;
    case END_EAD6_CODE:
        sdev->func = encap;
        break;
    case END_AD4_CODE:
        sdev->func = encap;
        break;
    case END_EAD4_CODE:
        sdev->func = encap;
        break;
    }

    hash_key = jhash(ifname, strlen(ifname), 0);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sdev_tbl, &sdev->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    goto end;
err:
    kfree(sdev);
end:
    return ret ;
}

/**
 * add_end()
 * Adds a localsid with End behavior to my localsid table
 * [CLI]... "srconf localsid add SID end"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 */

int add_end(const char *sid, const int behavior)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char * err_msg = "add_end - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err("%s sid exists in my localsid table \n", err_msg);
        return SIDEXIST;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err("%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = NULL;
    s6->iif = NULL;
    s6->good_pkts = 0;
    s6->good_bytes = 0;
    s6->bad_pkts = 0;
    s6->bad_bytes = 0;
    s6->func = end;

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    return ret;
}
EXPORT_SYMBOL(add_end);

/**
 * add_end_dx2()
 * Adds a localsid with End.DX2 behavior to my localsid table
 * {CLI]..."srconf localsid add SID end.dx2 TARGETIF"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 * @oif: target interface
 */

int add_end_dx2(const char *sid, const int behavior, const char *oif)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char *out_if;
    char * err_msg = "add_end_dx2 - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err("%s sid exists in my localsid table \n", err_msg);
        return SIDEXIST;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err("%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    out_if = kmalloc(strlen(oif), GFP_ATOMIC);
    if (!out_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        kfree(s6);
        return NOMEM;
    }

    strcpy(out_if, oif);
    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = out_if;
    s6->iif = NULL;
    s6->good_pkts  = 0;
    s6->good_bytes = 0;
    s6->bad_pkts   = 0;
    s6->bad_bytes  = 0;
    s6->func = end_dx2;

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    return ret;
}
EXPORT_SYMBOL(add_end_dx2);

/**
 * add_end_x()
 * Adds localsid with End.X or End.DX6 behavior to my localsid table
 * [CLI]..."srconf localsid add SID {end.x | end.dx6} NEXTHOP6 TARGETIF"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 * @nh_ip6: IPv6 address of next hop
 * @mac: MAC address of next hop
 * @oif: target interface
 */

int add_end_x(const char *sid, const int behavior, const char *nh_ip6, const unsigned char *mac,
              const char *oif)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char *out_if;
    char * err_msg = "add_end_x - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err("%s sid exists in my localsid table \n", err_msg);
        return SIDEXIST;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err("%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    if (nh_ip6 != NULL) {
        if (in6_pton(nh_ip6, strlen(nh_ip6), s6->nh_ip6.s6_addr, -1, NULL) != 1) {
            debug_err("%s next hop is not valid inet6 address \n", err_msg);
            ret = INVNEXTHOP6;
            goto err;
        }
        s6->mc = false;
    } else {
        memcpy(&s6->nh_mac, mac, 6);
        s6->mc = true ;
    }

    out_if = kmalloc(strlen(oif), GFP_ATOMIC);
    if (!out_if) {
        printk(KERN_INFO "%s could not allocate memory \n", err_msg);
        ret = NOMEM;
        goto err;
    }

    strcpy(out_if, oif);
    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = out_if;
    s6->iif = NULL;
    s6->good_pkts  = 0;
    s6->good_bytes = 0;
    s6->bad_pkts   = 0;
    s6->bad_bytes  = 0;

    switch (behavior) {
    case END_X_CODE:
        s6->func = end_x;
        break;
    case END_DX6_CODE:
        s6->func = end_dx6;
        break;
    }

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    goto end;

err:
    kfree(s6);

end:
    return ret;
}
EXPORT_SYMBOL(add_end_x);

/**
 * add_end_dx4()
 * Adds a localsid with End.DX4 behavior to my localsid table
 * [CLI]... "srconf localsid add SID end.dx4 NEXTHOP4 TARGETIF"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 * @nh_ip: IPv4 address of next hop
 * @mac: MAC address of next hop
 * @oif: target interface
 */

int add_end_dx4(const char *sid, const int behavior, const char *nh_ip,
                const unsigned char *mac, const char *oif)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char *out_if;
    char * err_msg = "add_end_dx4 - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err( "%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err( "%s sid exists in my localsid table \n", err_msg);
        return SIDEXIST;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err( "%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    if (nh_ip != NULL) {
        if (in4_pton(nh_ip, strlen(nh_ip), (u8 *) &s6->nh_ip.s_addr, -1, NULL) != 1) {
            debug_err( "%s next hop is not valid inet address \n", err_msg);
            ret = INVNEXTHOP4;
            goto err;
        }
        s6->mc = false ;
    } else {
        memcpy(&s6->nh_mac, mac, 6);
        s6->mc = true;
    }

    out_if = kmalloc(strlen(oif), GFP_ATOMIC);
    if (!out_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret =  NOMEM;
        goto err;
    }

    strcpy(out_if, oif);
    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = out_if;
    s6->iif = NULL;
    s6->good_pkts  = 0;
    s6->good_bytes = 0;
    s6->bad_pkts   = 0;
    s6->bad_bytes  = 0;
    s6->func = end_dx4;

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    goto end;

err:
    kfree(s6);

end:
    return ret;
}
EXPORT_SYMBOL(add_end_dx4);

/**
 * add_end_ad4()
 * Adds a localsid with End.AD4 or End.EAD4 behavior to my localsid table
 * CLI --> "srconf localsid add SID {end.ad4 | end.ead4} NEXHTHOP4 TARGETIF SOURCEIF"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 * @nh_ip: IPv4 address of next hop
 * @mac: MAC address of next hop
 * @oif: target interface
 * @iif: source interface
 */

int add_end_ad4(const char *sid, const int behavior, const char *nh_ip,
                const unsigned char *mac, const char *oif, const char* iif)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char *out_if, *in_if;
    char * err_msg = "add_end_ad4 - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err("%s sid exists in my localsid table \n", err_msg);
        return SIDEXIST;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err("%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    if (nh_ip != NULL) {
        if (in4_pton(nh_ip, strlen(nh_ip), (u8 *) &s6->nh_ip.s_addr, -1, NULL) != 1) {
            debug_err("%s next hop is not valid inet address \n", err_msg);
            ret =  INVNEXTHOP4;
            goto err;
        }
        s6->mc = false;
    } else {
        memcpy(&s6->nh_mac, mac, 6);
        s6->mc = true;
    }

    out_if = kmalloc(strlen(oif), GFP_ATOMIC);
    if (!out_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret =  NOMEM;
        goto err;
    }

    in_if = kmalloc(strlen(iif), GFP_ATOMIC);
    if (!in_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret =  NOMEM;
        kfree(out_if);
        goto err;
    }

    strcpy(in_if, iif);
    strcpy(out_if, oif);
    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = out_if;
    s6->iif = in_if;
    s6->good_pkts  = 0;
    s6->good_bytes = 0;
    s6->bad_pkts   = 0;
    s6->bad_bytes  = 0;

    switch (behavior) {
    case END_AD4_CODE:
        s6->func = end_ad4;
        break;
    case END_EAD4_CODE:
        s6->func = end_ead4;
        break;
    default:
        break;
    }

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    goto end;

err:
    kfree(s6);

end:
    return ret;
}
EXPORT_SYMBOL(add_end_ad4);

/**
 * add_end_ad6()
 * Adds a localsid with End.AD6, End.EAD6, or End.AM  behavior to my localsid table
 * [CLI]..."srconf localsid add SID {End.ad6 | End.ead6 | End.am } NEXHTHOP6 TARGETIF SOURCEIF"
 * @sid: SRv6 SID
 * @behavior: SRv6 behavior
 * @nh_ip: IPv4 address of next hop
 * @mac: MAC address of next hop
 * @oif: target interface
 * @iif: source interface
 */

int add_end_ad6(const char *sid, const int behavior, const char *nh_ip6,
                const unsigned char *mac, const char *oif, const char* iif)
{
    int ret = 0;
    u32 hash_key;
    struct in6_addr bsid;
    struct sid6_info *s6;
    char *out_if, *in_if;
    struct net_device *out, *in;

    char * err_msg = "add_end_ad6 - ";

    if (in6_pton(sid, strlen(sid), bsid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address \n", err_msg);
        return INVSID;
    }

    if (sid_lookup(bsid) != NULL) {
        debug_err("%s localsid already exists.", err_msg);
        return SIDEXIST;
    }

    out = dev_get_by_name(&init_net, oif);
    if (!out) {
        debug_err("%s invalid target interface\n", err_msg);
        return INVNEXTHOP6;
    }

    in = dev_get_by_name(&init_net, iif);
    if (!in) {
        debug_err("%s invalid source interface \n", err_msg);
        return INVNEXTHOP6;
    }

    s6 = kmalloc(sizeof(*s6), GFP_ATOMIC);
    if (!s6) {
        debug_err("%s could not allocate required memory \n", err_msg);
        return NOMEM;
    }

    if (nh_ip6 == NULL) {
        memcpy(&s6->nh_mac, mac, 6);
        s6->mc = true;
        goto loc_sid;
    }

    if (in6_pton(nh_ip6, strlen(nh_ip6), s6->nh_ip6.s6_addr, -1, NULL) != 1) {
        debug_err("%s next hop is not valid inet6 address \n", err_msg);
        ret = INVNEXTHOP6;
        goto err;
    }
    s6->mc = false;

loc_sid:
    out_if = kmalloc(strlen(oif), GFP_ATOMIC);
    if (!out_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret =  NOMEM;
        goto err;
    }

    in_if = kmalloc(strlen(iif), GFP_ATOMIC);
    if (!in_if) {
        debug_err("%s could not allocate memory \n", err_msg);
        ret =  NOMEM;
        kfree(out_if);
        goto err;
    }

    strcpy(in_if, iif);
    strcpy(out_if, oif);
    memcpy(&s6->sid, &bsid, sizeof(struct in6_addr));
    s6->behavior = behavior;
    s6->oif = out_if;
    s6->iif = in_if;
    s6->good_pkts  = 0;
    s6->good_bytes = 0;
    s6->bad_pkts  = 0;
    s6->bad_bytes = 0;

    switch (behavior) {
    case END_AD6_CODE:
        s6->func = end_ad6;
        break;
    case END_EAD6_CODE:
        s6->func = end_ead6;
        break;
    case END_AM_CODE:
        s6->func = end_am_masq;
        break;
    default:
        break;
    }

    hash_key = ipv6_addr_hash(&bsid);
    write_lock_bh(&sr_rwlock);
    hash_add_rcu(sid_tbl, &s6->hnode, hash_key);
    write_unlock_bh(&sr_rwlock);
    goto end;

err:
    kfree(s6);

end:
    return ret;
}
EXPORT_SYMBOL(add_end_ad6);

/**
 * del_sdev()
 * Deletes an entry from srdev table
 * used by del_sid() to for some SRv6 behavior
 * @ifname: Interface to be deleted
 */

int del_sdev(char * ifname)
{
    u32 key;
    struct sdev_info *sdev;

    if (hash_empty(sdev_tbl))
        goto end;

    key = jhash(ifname, strlen(ifname), 0);
    hash_for_each_possible_rcu(sdev_tbl, sdev, hnode, key) {
        if (strcmp(sdev->iif, ifname) == 0) {
            hash_del_rcu(&sdev->hnode);
            kfree(sdev->data);
            kfree(sdev->iif);
            kfree(sdev);
        }
    }

end:
    return 0;
}

/**
 * del_sid()
 * Deletes a localsid from my localsid table
 * [CLI]..."srconf localsid del SID"
 * @sid: SID to be deleted
 * it calls del_sdev(), for some SRv6 behaviors, to delete the associated srdev entry
 */

int del_sid(const char *sid)
{
    int ret = 0;
    struct in6_addr to_del;
    struct sid6_info *s6;
    char * err_msg = "del_sid - ";

    write_lock_bh(&sr_rwlock);

    if (in6_pton(sid, strlen(sid), to_del.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not valid inet6 address.\n", err_msg);
        ret = INVSID;
        goto end;
    }

    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        ret = EMPSIDTABLE;
        goto end;
    }

    s6 = sid_lookup(to_del);

    if (s6 == NULL ) {
        debug_err("%s sid not found in my localsid table. \n", err_msg);
        ret =  NOSID;
        goto end;
    }

    switch (s6->behavior) {
    case END_AM_CODE:
    case END_AD4_CODE:
    case END_AD6_CODE:
    case END_EAD4_CODE:
    case END_EAD6_CODE:
        del_sdev(s6->iif);
        break;
    default:
        break;
    }

    hash_del_rcu(&s6->hnode);
    kfree(s6->oif);
    kfree(s6->iif);
    kfree(s6);
end:
    write_unlock_bh(&sr_rwlock);
    return ret ;
}
EXPORT_SYMBOL (del_sid);

/**
 * flush_sdev_tbl()
 * Deletes all entries of srdev table
 * called by flush_sid_tbl()
 */

int flush_sdev_tbl(void)
{
    int ret = 0;
    int i;
    struct sdev_info *sdev;
    struct hlist_node *tmp;

    if (hash_empty(sdev_tbl))
        goto end;

    hash_for_each_safe(sdev_tbl, i, tmp, sdev, hnode) {
        hash_del(&sdev->hnode);
        kfree(sdev->iif);
        kfree(sdev->data);
        kfree(sdev);
    }

end:
    return ret ;
}

/**
 * flush_sid_tbl()
 * Deletes all entries of my localsid table
 * [CLI]... "srconf localsid flush"
 * called by the srext_exit() to free the hash tables before unregistering the kernel module
 * It calls flush_sdev_tbl() to delete all entires of the srdev table
 */

int flush_sid_tbl(void)
{
    int ret = 0;
    int i;
    struct sid6_info *s6;
    struct hlist_node *tmp;

    char * err_msg = "flush_sid_tbl - ";

    write_lock_bh(&sr_rwlock);
    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        ret = EMPSIDTABLE;
        goto end;
    }

    flush_sdev_tbl();

    hash_for_each_safe(sid_tbl, i, tmp, s6, hnode) {
        hash_del_rcu(&s6->hnode);
        kfree(s6->oif);
        kfree(s6->iif);
        kfree(s6);
    }

end:
    write_unlock_bh(&sr_rwlock);
    return ret;
}
EXPORT_SYMBOL(flush_sid_tbl);

/**
 * show_localsid_all()
 * Prints all entries of my localsid table
 * [CLI]..."srconf localsid show"
 * @dst : message to be sent back to userspace
 * @size: message size
 */

int show_localsid_all(char *dst, size_t size)
{
    int i;
    struct sid6_info *s6;
    char * err_msg = "show_localsid_all - ";

    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        return EMPSIDTABLE;
    }

    strcat(dst, "SRv6 - MY LOCALSID TABLE:\n");
    strcat(dst, "==================================================\n");

    rcu_read_lock();
    hash_for_each_rcu(sid_tbl, i, s6, hnode) {
        sprintf(dst + strlen(dst), "\t SID     :        %pI6c \n", s6->sid.s6_addr);

        switch (s6->behavior) {
        case END_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END);
            break;

        case END_DX2_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX2);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            break;

        case END_X_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_X);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            break;

        case END_DX6_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX6);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            break;

        case END_DX4_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX4);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            break;

        case END_AD6_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AD6);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
            break;

        case END_EAD6_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_EAD6);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
            break;

        case END_AM_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AM);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
            break;

        case END_AD4_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AD4);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
            break;

        case END_EAD4_CODE:
            sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_EAD4);
            if (!s6->mc)
                sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
            else
                print_nh_mac(s6->nh_mac, dst);
            sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
            sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
            break;
        }

        sprintf(dst + strlen(dst), "\t Good traffic:    [%lld packets : %lld  bytes]\n", \
                s6->good_pkts, s6->good_bytes);
        sprintf(dst + strlen(dst), "\t Bad traffic:     [%lld packets : %lld  bytes]\n", \
                s6->bad_pkts, s6->bad_bytes);
        sprintf(dst + strlen(dst), "------------------------------------------------------\n");
    }

    rcu_read_unlock();
    return 0 ;
}
EXPORT_SYMBOL (show_localsid_all);

/**
 * show_localsid_sid()
 * Prints a localsid entry from my localsid table
 * [CLI]... "srconf localsid show SID"
 * @dst: message to be sent back to userspace
 * @size: message size
 * @sid: SID to be shown.
 */

int show_localsid_sid(char *dst, size_t size, const char *sid)
{
    struct sid6_info *s6;
    struct in6_addr sid6;
    char * err_msg = "show_localsid_sid - ";

    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        return EMPSIDTABLE;
    }

    if (in6_pton(sid, strlen(sid), sid6.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not a valid inet6 address \n", err_msg);
        return INVSID;
    }

    rcu_read_lock();

    s6 = sid_lookup(sid6);

    if (s6 == NULL ) {
        debug_err("%s sid not found in my localsid table. \n", err_msg);
        rcu_read_unlock();
        return NOSID;
    }

    strcat(dst, "SRv6 - MY LOCALSID TABLE:\n");
    strcat(dst, "==================================================\n");

    sprintf(dst + strlen(dst), "\t SID     :        %pI6c \n", s6->sid.s6_addr);

    switch (s6->behavior) {
    case END_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END);
        break;

    case END_DX2_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX2);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        break;

    case END_X_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_X);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        break;

    case END_DX6_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX6);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        break;

    case END_DX4_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_DX4);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        break;

    case END_AD6_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AD6);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
        break;

    case END_EAD6_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_EAD6);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
        break;

    case END_AM_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AM);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI6c \n", s6->nh_ip6.s6_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
        break;

    case END_AD4_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_AD4);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
        break;

    case END_EAD4_CODE:
        sprintf(dst + strlen(dst), "\t Behavior:        %s \n", END_EAD4);
        if (!s6->mc)
            sprintf(dst + strlen(dst), "\t Next hop:        %pI4 \n", &s6->nh_ip.s_addr);
        else
            print_nh_mac(s6->nh_mac, dst);
        sprintf(dst + strlen(dst), "\t OIF     :        %s \n", s6->oif);
        sprintf(dst + strlen(dst), "\t IIF     :        %s \n", s6->iif);
        break;
    }

    sprintf(dst + strlen(dst), "\t Good traffic:    [%lld packets : %lld  bytes]\n", \
            s6->good_pkts, s6->good_bytes);
    sprintf(dst + strlen(dst), "\t Bad traffic :    [%lld packets : %lld  bytes]\n", \
            s6->bad_pkts, s6->bad_bytes);
    sprintf(dst + strlen(dst), "------------------------------------------------------\n");

    rcu_read_unlock();
    return 0 ;
}
EXPORT_SYMBOL (show_localsid_sid);

/**
 * clear_counters_all()
 * Clears counters of all sids in my localsid table
 * [CLI]..."srconf localsid clear-counters"
 */

int clear_counters_all(void)
{
    int ret = 0;
    unsigned int temp;
    struct sid6_info *s6;
    char * err_msg = "clear_all_counters - ";

    write_lock_bh(&sr_rwlock);
    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        ret = EMPSIDTABLE;
        goto end;
    }

    hash_for_each_rcu(sid_tbl, temp, s6, hnode) {
        s6->bad_pkts   = 0;
        s6->good_pkts  = 0;
        s6->bad_bytes  = 0;
        s6->good_bytes = 0;
    }

end:
    write_unlock_bh(&sr_rwlock);
    return ret ;
}
EXPORT_SYMBOL(clear_counters_all);

/**
 * clear_counters_sid()
 * Clears counters of sid from my localsid table
 * [CLI]... "srconf localsid clear-counters SID"
 * @sid: SID to get its counters cleared
 */

int clear_counters_sid(const char *sid)
{
    int ret = 0;
    struct sid6_info *s6;
    struct in6_addr clear_sid;
    char * err_msg = "clear_sid_counters - ";

    write_lock_bh(&sr_rwlock);
    if (in6_pton(sid, strlen(sid), clear_sid.s6_addr, -1, NULL) != 1) {
        debug_err("%s sid is not a valid inet6 address \n", err_msg);
        ret =  INVSID;
        goto end ;
    }

    if (hash_empty(sid_tbl)) {
        debug_err("%s localsid table is empty. \n", err_msg);
        ret = EMPSIDTABLE;
        goto end;
    }

    s6 = sid_lookup(clear_sid);

    if (s6 == NULL) {
        debug_err("%s sid not found in my localsid table. \n", err_msg);
        ret =  NOSID;
        goto end;
    }
    s6->bad_pkts   = 0;
    s6->good_pkts  = 0;
    s6->bad_bytes  = 0;
    s6->good_bytes = 0;

end:
    write_unlock_bh(&sr_rwlock);
    return ret ;
}
EXPORT_SYMBOL(clear_counters_sid);


/***************************************************************************************************
************************************** SRv6 Behaviors  *********************************************
***************************************************************************************************/

/**
 * end()
 * SRv6 Endpoint behavior
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end(struct sk_buff * skb, struct sid6_info * s6)
{
    int  srh_offset = 0, srh_proto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "End - ";

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    srh_proto = ipv6_find_hdr(skb, &srh_offset, NEXTHDR_ROUTING, NULL, NULL);
    if (srh_proto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srh_offset);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srh_offset);
    if ( srh->segments_left <= 0 ) {
        debug_err("%s End can not be the last sid, segments_left = 0, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    update_counters(s6, skb->len, 1);
    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);
    return 1;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_x()
 * SRv6 Endpoint with Layer-3 cross-connect behavior
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_x(struct sk_buff * skb, struct sid6_info * s6)
{
    int srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "End.X - ";

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left <= 0 ) {
        debug_err("%s End.X can not be the last SID, segments_left = 0, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);

    if (xcon6(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_dx2()
 * SRv6 Endpoint with decapsulation and Layer-2 cross-connect behavior
 * @skb: packet buffer buffer
 * @s6 : ocalsid table entry
 */

int end_dx2(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "End.DX2 - ";

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);

    if (innerproto != NEXTHDR_NONE) {
        debug_err("%s Packet is not a valid T.encaps.L2 format, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING)
        goto decap;

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left != 0 ) {
        debug_err("%s segments_left must be zero, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

decap:
    if (decap2(skb, s6, inneroff, srhoff, 0) != 0)
        goto drop;

    if (xcon2(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;
drop:
    kfree(skb);
    return -1;
}

/**
 * end_dx4()
 * SRv6 Endpoint with decapsulation and IPv4 cross-connect behavior
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_dx4(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* ip6h;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "End.DX4 - ";

    ip6h = ipv6_hdr(skb);
    if (ip6h->hop_limit <= 1) {
        debug_err("%s packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    ip6h->hop_limit --;

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    if (innerproto != IPPROTO_IPIP) {
        debug_err("%s Packet has no inner IPv4 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING)
        goto decap;

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left != 0 ) {
        debug_err("%s segments_left must be zero, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

decap:
    if (decap4(skb, s6, inneroff, srhoff, 0) != 0)
        goto drop;

    if (xcon4(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_dx6()
 * SRv6 Endpoint with decapsulation and IPv6 cross-connect behavior
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_dx6(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "End.DX6 - ";

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s packet can not be forwarded, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    if (innerproto != IPPROTO_IPV6) {
        debug_err("%s Packet has no inner IPv6 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING)
        goto decap;

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left != 0 ) {
        debug_err("%s segments_left must be zero, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

decap:
    if (decap6(skb, s6, inneroff, srhoff, 0) != 0)
        goto drop;

    if (xcon6(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_ad4()
 * SRv6 Endpoint to IPv4 SR-unaware APP via dynamic proxy behvior
 * Decapsulates (removes) SRv6 encapsulation from IPv6 packet before sending packets to a VNF
 * Creates an entry with the decapsulated headers into srdev table
 * Attach a callback function "encap()" to the interface where packets come back from the VNF,
 * The encap callback re-adds the saved headers again to packets back from the VNF
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_ad4(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* ip6h;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "end_ad4- ";

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    printk(" ip proto = %d \n ", innerproto);
    printk(" offset  = %d \n ", inneroff);

    if (innerproto != IPPROTO_IPIP) {
        debug_err("%s Packet has no inner IPv4 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left <= 0 ) {
        debug_err("%s End.AD4 can not be the last SID, segments_left = 0, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    srh->segments_left--;
    ip6h = ipv6_hdr(skb);

    if (ip6h->hop_limit <= 1) {
        debug_err("%s The packet can not be forwarded more, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    ip6h->hop_limit --;
    ip6h->daddr = *(srh->segments + srh->segments_left);

    if (decap4(skb, s6, inneroff, srhoff, 1) != 0)
        goto drop;

    if (xcon4(skb, s6) != 0)
        printk("%s %s \n", err_msg, "packet sent to the VNF !!!!! failed");
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_ead4()
 * SRv6 Endpoint to IPv4 SR-unaware APP via dynamic proxy behvior - Extended
 * An extended End.AD4 behavior that allow having SR-unaware VNFs as last VNF in SFC
 * Based on the sgement_left value it decides either to save the outer headers or not
 * If segment_left = 0, then a VNF is the last in chain and outer headers are not saved
 * Segment_left >0, then outer headers are saved and added back to packets coming back from the VNF
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_ead4(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "end_ead6 - ";
    int save = 0;

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s The packet can not be forwarded more, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    if (innerproto != IPPROTO_IPIP) {
        debug_err("%s Packet has no inner IPv4 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING)
        goto decap;

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left > 0 ) {
        save = 1;
        srh->segments_left--;
        iph->daddr = *(srh->segments + srh->segments_left);
    }

decap:
    if (decap4(skb, s6, inneroff, srhoff, save) != 0)
        goto drop;

    if (xcon4(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_ad6()
 * SRv6 Endpoint to IPv6 SR-unaware APP via dynamic proxy behvior
 * Decapsulates (removes) SRv6 encapsulation from IPv6 packet before sending packets to a VNF
 * Creates an entry with the decapsulated headers into srdev table
 * Attach a callback function "encap()" to the interface where packets come back from the VNF,
 * The encap callback re-adds the saved headers again to packets back from the VNF
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_ad6(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "end_ad6 - ";

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    if (innerproto != IPPROTO_IPV6) {
        debug_err("%s Packet has no inner IPv6 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left <= 0 ) {
        debug_err("%s End.AD6 can not be the last SID, segments_left = 0, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    srh->segments_left--;
    iph = ipv6_hdr(skb);

    if (iph->hop_limit <= 1) {
        debug_err("%s The packet can not be forwarded more, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;
    iph->daddr = *(srh->segments + srh->segments_left);

    if (decap6(skb, s6, inneroff, srhoff, 1) != 0)
        goto drop;

    if (xcon6(skb, s6) != 0)
        printk("%s %s \n", err_msg, "packet sent to the VNF !!!!! failed");

    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_ead6()
 * SRv6 Endpoint to IPv6 SR-unaware APP via dynamic proxy behvior - Extended
 * An extended End.AD6 behavior that allow having SR-unaware VNFs as last VNF in SFC
 * Based on the sgement_left value it decides either to save the outer headers or not
 * If segment_left = 0, then a VNF is the last in chain and outer headers are not saved
 * Segment_left >0, then outer headers are saved and added back to packets coming back from the VNF
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end_ead6(struct sk_buff * skb, struct sid6_info * s6)
{
    int  inneroff = 0, innerproto;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "end_ead6 - ";
    int save = 0;

    iph = ipv6_hdr(skb);
    if (iph->hop_limit <= 1) {
        debug_err("%s The packet can not be forwarded more, hop_limit is <= 1, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }
    iph->hop_limit --;

    innerproto = ipv6_find_hdr(skb, &inneroff, -1, NULL, NULL);
    if (innerproto != IPPROTO_IPV6) {
        debug_err("%s Packet has no inner IPv6 header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING)
        goto decap;

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left > 0 ) {
        save = 1;
        srh->segments_left--;
        iph->daddr = *(srh->segments + srh->segments_left);
    }

decap:
    if (decap6(skb, s6, inneroff, srhoff, save) != 0)
        goto drop;

    if (xcon6(skb, s6) != 0)
        debug_err("%s packet forwarding failed.\n", err_msg);
    return 0;

drop:
    kfree(skb);
    return -1;
}

/**
 * end_am_masq()
 * SRv6 Endpoint to SR-unaware APP via masquerading behavior
 * @skb: packet buffer
 * @s6: localsid table entry
 */

int end_am_masq(struct sk_buff * skb, struct sid6_info * s6)
{
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    char * err_msg = "end_am_masq - ";

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    if ( srh->segments_left <= 0 ) {
        debug_err("%s End.AM can not be the last SID, segments_left = 0, dropped.\n", err_msg);
        update_counters(s6, skb->len, 0);
        goto drop;
    }

    srh->segments_left--;
    iph = ipv6_hdr(skb);
    iph->hop_limit --;
    iph->daddr = *srh->segments;

    if ((sdev_add(s6->iif, s6->behavior, skb, 0, 0)) != 0)
        goto drop;

    if (xcon6(skb, s6) != 0)
        printk("%s %s \n", err_msg, "packet sent to the VNF !!!!! failed");

    return 0;
drop:
    kfree(skb);
    return -1;
}

/**
 * end_am_demasq()
 * Demasquerades packets coming from a VNF
 * @skb: packet buffer
 * @sdev: srdev table entry
 */

int end_am_demasq(struct sk_buff * skb, struct sdev_info * sdev)
{
    int  ret = 0;
    int  srhoff = 0, srhproto;
    struct ipv6hdr* iph;
    struct ipv6_sr_hdr* srh;
    struct ipv6_rt_hdr* rth_hdr;
    struct in6_addr* next_hop = NULL;
    char * err_msg = "end_am_demasq - ";

    srhproto = ipv6_find_hdr(skb, &srhoff, NEXTHDR_ROUTING, NULL, NULL);
    if (srhproto != NEXTHDR_ROUTING) {
        debug_err("%s Packet has no routing extension header, dropped.\n", err_msg);
        ret = 1;
        goto end;
    }

    rth_hdr = (struct ipv6_rt_hdr*) (skb->data + srhoff);
    if (rth_hdr->type != IPV6_SRCRT_TYPE_4) {
        debug_err("%s The routing extension header is not SRH, dropped.\n", err_msg);
        ret = 1;
        goto end;
    }

    srh = (struct ipv6_sr_hdr*) (skb->data + srhoff);
    iph = ipv6_hdr(skb);
    next_hop = srh->segments + srh->segments_left;
    iph->daddr = *next_hop;

end:
    return ret ;
}

/**
 * sr_pre_routing()
 * Main packet processing function
 * called for every recieved IPv6 packet
 * it calls the required function based on the SRv6 beahviour associated with the sid
 */

unsigned int sr_pre_routing(void* priv, struct sk_buff * skb,
                            const struct nf_hook_state * state)
{
    struct ipv6hdr* iph;
    struct icmp6hdr* icmpv6h;
    struct sid6_info *s6;
    struct sdev_info *sdev;

    rcu_read_lock();
    sdev = sdev_lookup(skb->dev->name);
    if (sdev == NULL)
        goto lookup;

    if (ipv6_hdr(skb)->nexthdr == NEXTHDR_ICMP) {
        icmpv6h = (struct icmp6hdr*) icmp6_hdr(skb);
        if (!((icmpv6h->icmp6_type == ICMPV6_ECHO_REQUEST) || (icmpv6h->icmp6_type == ICMPV6_ECHO_REPLY)))
            goto exit_accept;
    }

    sdev->func(skb, sdev);

lookup:
    iph = ipv6_hdr(skb);
    s6 = sid_lookup(iph->daddr);
    if (s6 == NULL)
        goto exit_accept;

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
 * srext_init()
 * SREXT initialization function
 */

int srext_init(void)
{
    int ret = 0;

    printk(KERN_INFO "Loading module %s.......\n", DESC);
    hash_init (sid_tbl);
    hash_init (sdev_tbl);

    /* Integration with netlink module */
    ret = sr_genl_register();
    if (ret < 0)
        return ret;

    ret = hook_v4_register();
    if (ret < 0) {
        sr_genl_unregister();
        return ret;
    }

    rwlock_init(&sr_rwlock);

    /* Register the filtering function */
    sr_ops_pre.hook = sr_pre_routing;
    sr_ops_pre.pf = PF_INET6;
    sr_ops_pre.hooknum = NF_INET_PRE_ROUTING;
    sr_ops_pre.priority = NF_IP_PRI_LAST;

    /* register NF_IP_PRE_ROUTING hook */
    ret = nf_register_hook(&sr_ops_pre);

    if (ret < 0) {
        printk(KERN_INFO "Sorry, registering %s failed with %d \n", DESC , ret);
        return ret;
    }
    printk(KERN_INFO "SREXT registered (%d)!\n", ret);
    return 0;
}

/**
 * srext_exit()
 * SREXT exit function
 */

void srext_exit(void)
{
    printk(KERN_INFO "Unloading module %s......\n", DESC);

    /* Integration with netlink and hook_v4 modules */
    sr_genl_unregister();
    hook_v4_unregister();

    /* Unregister the filtering function*/
    nf_unregister_hook(&sr_ops_pre);

    /* delete hash elements before unloading the module */
    flush_sid_tbl();
    memset(&sr_ops_pre, 0, sizeof(struct nf_hook_ops));
    printk(KERN_INFO "SREXT released.\n");
}

module_init (srext_init);
module_exit (srext_exit);
