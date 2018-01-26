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

#ifndef GENETLINK_H_
#define GENETLINK_H_

/**
 * TABLES
 */

#define LOCALSID 	"localsid"
#define SRDEV 		"srdev"

/**
 * COMMANDS
 */

#define ADD 	"add"
#define DEL		"del"
#define SHOW 	"show"
#define HELP 	"help"
#define FLUSH 	"flush"
#define CLEAR 	"clear-counters"

/**
 * BEHAVIORS
 */

#define END        		"end"
#define END_X       	"end.x"
#define END_DX2     	"end.dx2"
#define END_DX4     	"end.dx4"
#define END_DX6     	"end.dx6"
#define END_AD4      	"end.ad4"
#define END_AD6     	"end.ad6"
#define END_AM      	"end.am"
#define END_AS4      	"end.as4"
#define END_AS6      	"end.as6"
#define END_EAD4 		"end.ead4"
#define END_EAD6 		"end.ead6"

/**
 * BEHAVIORS CODE
 */

#define END_CODE 			1
#define END_X_CODE 			2
#define END_DX2_CODE 		3
#define END_DX4_CODE 		4
#define END_DX6_CODE 		5
#define END_AD4_CODE 		6
#define END_AD6_CODE 		7
#define END_AM_CODE 		8
#define END_AS4_CODE 		9
#define END_AS6_CODE 		10
#define END_EAD4_CODE 		13
#define END_EAD6_CODE 		14

enum SR_GNL_COMMANDS {
	SR_C_ECHO,
	SR_C_ADD,
	SR_C_DEL,
	SR_C_SHOW,
	SR_C_FLUSH,
	SR_C_CLEAR,
	_SR_C_MAX,
};

enum SR_GNL_ATTRIBUTES {
	SR_A_ZERO, //do not touch, this is for the attributes order
	SR_A_UNSPEC,

	SR_A_TABLE,
	SR_A_COMMAND,
	SR_A_SID,
	SR_A_FUNC,
	SR_A_NEXT,
	SR_A_MAC,
	SR_A_OIF,
	SR_A_IIF,
	SR_A_SOURCE,
	SR_A_ADDR,
	SR_A_SEGS,
	SR_A_SID_LST,
	SR_A_LEFT,
	SR_A_NUMBER,
	SR_A_FLAGS,

	SR_A_RESPONSE,
	SR_A_RESPONSE_LST,

	_SR_A_MAX,
};

#define SR_GNL_FAMILY_NAME "SR_GENL_FAMILY"
#define SR_GNL_FAMILY_VERSION 1
#define SR_A_MAX (_SR_A_MAX - 1)
#define SR_C_MAX (_SR_C_MAX - 1)
#define MAX_BUF_LEN 1024*5

struct genl_msg_data {
	int		atype;
	void	*data;
	int		len;
};

struct sr_mac {
	char oct[6];
};

struct sr_param {
	char *table;
	char *command;
	char *sid;
	char *func;
	char *next;
	struct sr_mac *mac;
	char *oif;
	char *iif;

	char *source;
	char *addr;
	char *segs ;
	char *sid_lst;
	char *left;
	char *number;
	char *flags;
};

int sr_genl_register(void);
int sr_genl_unregister(void);

#endif /* GENETLINK_H_ */

