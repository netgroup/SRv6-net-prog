/**
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_LINUX_SEG6_H
#define _UAPI_LINUX_SEG6_H

#define IPV6_SRCRT_TYPE_4       4       /* Segment Routing with IPv6 */

/**
 * SRH
 */
struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;
	__be16	flags;
	__u8	reserved;

	struct in6_addr segments[0];
} __attribute__((packed));

#define SR6_FLAG_CLEANUP	(1 << 15)
#define SR6_FLAG_PROTECTED	(1 << 14)
#define SR6_FLAG_OAM		(1 << 13)
#define SR6_FLAG_ALERT		(1 << 12)
#define SR6_FLAG_HMAC		(1 << 11)

#define SR6_TLV_INGRESS		1
#define SR6_TLV_EGRESS		2
#define SR6_TLV_OPAQUE		3
#define SR6_TLV_PADDING		4
#define SR6_TLV_HMAC		5

#define sr_get_flags(srh) (be16_to_cpu((srh)->flags))

#endif
