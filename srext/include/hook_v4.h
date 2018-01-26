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

#ifndef HOOK_V4_H_
#define HOOK_V4_H_

/* Register IPv4 traffic HOOK */
int hook_v4_register(void);
int hook_v4_unregister(void);

#endif /* HOOK_V4_H_ */

