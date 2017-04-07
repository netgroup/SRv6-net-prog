/*
 * sr_genl.h
 *
 *  Created on: 06 mar 2017
 *      Author: fabbox
 */

#ifndef GENETLINK_H_
#define GENETLINK_H_

//tables
#define NORTH "north"
#define SOUTH "south"

//commands
#define ADD		"add"
#define DEL		"del"
#define SHOW	"show"

//operations
#define OP_FW		"fw"
#define OP_MASQFW	"masqfw"

#define OP_DECAPFW	"decapfw"
#define CODE_DECAPFW	2

#define OP_DEINSFW	"deinsfw"

#define OP_DEMASQ	"demasq"
#define OP_ENCAP	"encap"

//operation mode
#define AUTO		"auto"
#define CODE_AUTO 1 

enum SR_GNL_COMMANDS{
	SR_C_ECHO,
	SR_C_ADD,
	SR_C_DEL,
	SR_C_SHOW,
	_SR_C_MAX,
};

enum SR_GNL_ATTRIBUTES {
	SR_A_ZERO, //do not touch, this is for the attributes order
	SR_A_UNSPEC,

	SR_A_TABLE,
	SR_A_COMMAND,
	SR_A_SID,
	SR_A_OP1,
	SR_A_OP2,
	SR_A_MODE,
	SR_A_IFACE,
	SR_A_MAC,

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
	char *op1;
	char *op2;
	char *mode;
	char *iface;
	//char *mac;
	struct sr_mac *mac;

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

void dmesg(const char *, ...);
void dmesge(const char *, ...);

/*
void print_mac(struct sr_mac *);
void print_mac(struct sr_mac *mac){
	//printf("Mac : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
	//printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
#ifdef __KERNEL__
	printk("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
#else
	printf("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
#endif
			(unsigned char) mac->oct[0],
			(unsigned char) mac->oct[1],
			(unsigned char) mac->oct[2],
			(unsigned char) mac->oct[3],
			(unsigned char) mac->oct[4],
			(unsigned char) mac->oct[5]);
}*/

#endif /* GENETLINK_H_ */

