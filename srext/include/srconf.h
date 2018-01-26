
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

#ifndef NET_SRCONF_H_
#define NET_SRCONF_H_

#include "sr_genl.h"

struct genl_msg {
	struct nlmsghdr n;		//128 bit = 16 bytes
	struct genlmsghdr g;	//32  bit = 8  bytes

	//25 ---> ..
	char buf[MAX_BUF_LEN];
};

#define GENLMSG_DATA(glh) 			((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_DATALEN(glh) 		(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define GENLMSG_NLA_NEXT(na) 		(((void *)(na)) + NLA_ALIGN(na->nla_len))
#define GENLMSG_NLA_DATA(na) 		((void *)((char*)(na) + NLA_HDRLEN))
#define GENLMSG_NLA_DATALEN(na) 	(na->nla_len - NLA_HDRLEN - 1)

#endif /* NET_SRCONF_H_ */
