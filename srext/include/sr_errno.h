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

#ifndef _SREXT_ERRNO_H
#define _SREXT_ERRNO_Hgit 

/**
 * SREXT ERRNO
 */

#define NOMEM            1
#define INVSID           2
#define INVNEXTHOP6      3
#define INVNEXTHOP4      4
#define SIDEXIST         5
#define NOSID            6
#define EMPSIDTABLE      7
#define EMPSRDEV         8
#define XMIT_ERR         9
#define BEHAVIORERR      10
#define INVTABLE         11

extern char *err_str[];

#endif /* SREXT_ERRNOH_ */

