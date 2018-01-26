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

#ifndef SRHOOK_H_
#define SRHOOK_H_

/**
 * struct sid6_info - localsid table entry
 * @sid: SRv6 sid
 * @behavior: SRv6 behavior
 * @nh_ip: IPv4 address of next hop
 * @nh_ip6: IPv6 address of next hop
 * @nh_mac: MAC address of next hop
 * @mc: Flag - indicates that nh_mac is known (no need for ARP or NDISC)
 * @oif: target interface
 * @iif: source interface
 * @good_pkts: counter for good traffic in packets
 * @good_bytes: counter for good traffic in bytes
 * @bad_pkts: counter for bad traffic in packets
 * @bad_bytes: counter for bad traffic in bytes
 * @func: pointer to an SRv6 function
 * @hnode: hlist_node variable
 */

struct sid6_info {
	struct in6_addr sid;
	__u8 behavior;
	union {
		struct in_addr  nh_ip;
		struct in6_addr nh_ip6;
		unsigned char nh_mac[6];
	};
	bool mc;
	char *oif;
	char *iif;
	uint64_t good_pkts;
	uint64_t good_bytes;
	uint64_t bad_pkts;
	uint64_t bad_bytes;
	int (*func)(struct sk_buff *skb, struct sid6_info * s6);
	struct hlist_node hnode;
};

/**
 * struct sdev_info - srdev table entry
 * @iif: source interface
 * @behavior: SRv6 behavior
 * @data: buuffer to save an arbitary number of bytes
 *		  used mostly to save a copy of outer IPv6 header and its extensions headers
 * @len: length of data in bytes
 * @srhoff: offset of SRH in the saved data
 * @func: pointer to an SRv6 function
 * @hnode: hlist_node variable
 */

struct sdev_info {
	char *iif;
	__u8 behavior;
	void *data;
	__u8 len;
	__u8 srhoff;
	int  (*func) (struct sk_buff * skb, struct sdev_info * sdev);
	struct hlist_node hnode;
};

/**
 * ADD FUNCTIONS
 */

/* End */
int add_end(const char *sid, const int behavior);

/* End.DX2 */
int add_end_dx2(const char *sid, const int behavior, const char *oif );

/* End.AD4 or End.EAD4 */
int add_end_ad4(const char *sid, const int behavior, const char *next,
                const unsigned char *mac, const char *oif, const char* iif);

/* End.AD6, End.EAD6, or End/AM */
int add_end_ad6(const char *sid, const int behavior, const char *next,
                const unsigned char *mac, const char *oif, const char* iif);

/* End.X or End.DX6*/
int add_end_x(const char *sid, const int behavior, const char *next,
              const unsigned char *mac, const char *oif);

/* End.DX4O*/
int add_end_dx4(const char *sid, const int behavior, const char *next,
                const unsigned char *mac, const char *oif);

/* ADD to SRDEV*/
int sdev_add(char* ifname, int behavior, void *buf , int size, int srhoff);

/**
 * DELETE FUNCTIONS
 */

int del_sid(const char *sid);
int del_sdev(char * ifname);
int flush_sid_tbl(void);

/**
 * SHOW FUNCTIONS
 */

int show_localsid_sid(char *dst, size_t size, const char *sid);
int show_localsid_all(char *dst, size_t size);

/**
 * CLEAR COUNTERS FUNCTIONS
 */

int clear_counters_all(void);
int clear_counters_sid(const char *sid);

/**
 * SRv6 END FUNCTIONS
 */

/* End*/
int end(struct sk_buff* skb, struct sid6_info *s6);

/* End.X */
int end_x(struct sk_buff* skb, struct sid6_info *s6);

/* End.DX2 */
int end_dx2(struct sk_buff* skb, struct sid6_info *s6);

/* End.DX6 */
int end_dx6(struct sk_buff* skb, struct sid6_info *s6);

/* End.DX4 */
int end_dx4(struct sk_buff* skb, struct sid6_info *s6);

/* End.AD6 */
int end_ad6(struct sk_buff* skb, struct sid6_info * s6);

/* End.EAD6 */
int end_ead6(struct sk_buff* skb, struct sid6_info * s6);

/* End.AD4 */
int end_ad4(struct sk_buff* skb, struct sid6_info * s6);

/* End.EAD4 */
int end_ead4(struct sk_buff* skb, struct sid6_info * s6);

/* End.AM */
int end_am_masq(struct sk_buff * skb, struct sid6_info *s6);
int end_am_demasq(struct sk_buff * skb, struct sdev_info *sdev);

/**
 * SREXT helper functions
 */

/* decap */
int decap6(struct sk_buff * skb, struct sid6_info *s6, int inner, int srhoff, int save);
int decap4(struct sk_buff * skb, struct sid6_info *s6, int inner, int srhoff, int save);

/**
 * Opertaions on tables (localsid and srdev )
 */

/* Lookup */
struct sid6_info *sid_lookup(struct in6_addr sid);
struct sdev_info * sdev_lookup(char* ifname);

/* counters update */
int update_counters(struct sid6_info *s6, int len, int good);

/* Debug */
void dmesg( const char * format, ...);
void dmesg_err( const char * format, ...);

#endif /* SRHOOK_H_ */

