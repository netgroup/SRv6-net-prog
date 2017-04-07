//#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
//#include <linux/rwlock.h>
//#include <net/protocol.h>
#include <net/ipv6.h>
//#include <linux/icmpv6.h>
//#include "../include/seg6.h"
//#include "../include/sr_genl.h"
#include "../include/sr_helper.h"



/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
/*	const u_char *src;
	char *dst;
	size_t size;*/
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	if (SPRINTF((tmp, fmt, src[0], src[1], src[2], src[3])) > size) {
		/*errno = (ENOSPC);*/
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}
EXPORT_SYMBOL(inet_ntop4);

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
        /*
         * Note that int32_t and int16_t need only be "at least" large enough
         * to contain a value of the specified size.  On some systems, like
         * Crays, there is no such thing as an integer variable with 16 bits.
         * Keep this in mind if you think this function should have been coded
         * to use pointer overlays.  All the world's not a VAX.
         */
        char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
        struct { int base, len; } best, cur;

        u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
        int i;

        //printk("NS_IN6ADDRSZ %ld \n",NS_IN6ADDRSZ);
        //printk("NS_INT16SZ %ld \n",NS_INT16SZ);

        /*
         * Preprocess:
         *        Copy the input (bytewise) array into a wordwise array.
         *        Find the longest run of 0x00's in src[] for :: shorthanding.
         */
        memset(words, '\0', sizeof words);
        for (i = 0; i < NS_IN6ADDRSZ; i += 2)
                words[i / 2] = (src[i] << 8) | src[i + 1];
        best.base = -1;
        cur.base = -1;
        best.len = 0;
        cur.len = 0;
        for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                if (words[i] == 0) {
                        if (cur.base == -1)
                                cur.base = i, cur.len = 1;
                        else
                                cur.len++;
                } else {
                        if (cur.base != -1) {
                                if (best.base == -1 || cur.len > best.len)
                                        best = cur;
                                cur.base = -1;
                        }
                }
        }
        if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                        best = cur;
        }
        if (best.base != -1 && best.len < 2)
                best.base = -1;
        /*
         * Format the result.
         */
        tp = tmp;
        for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                /* Are we inside the best run of 0x00's? */
                if (best.base != -1 && i >= best.base &&
                    i < (best.base + best.len)) {
                        if (i == best.base)
                                *tp++ = ':';
                        continue;
                }
                /* Are we following an initial run of 0x00s or any real hex? */
                if (i != 0)
                        *tp++ = ':';
                /* Is this address an encapsulated IPv4? */
                if (i == 6 && best.base == 0 &&
                    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
                        if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
                                return (NULL);
                        tp += strlen(tp);
                        break;
                }
                tp += SPRINTF((tp, "%x", words[i]));
        }
        /* Was it a trailing run of 0x00's? */
        if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
                *tp++ = ':';
        *tp++ = '\0';
        /*
         * Check for overflow, copy, and we're done.
         */
        if ((size_t)(tp - tmp) > size) {
                /*__set_errno (ENOSPC);*/
                return (NULL);
        }
        return strcpy(dst, tmp);
}
EXPORT_SYMBOL(inet_ntop6);

