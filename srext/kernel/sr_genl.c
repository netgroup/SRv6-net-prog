/*
 * sr_genl.c
 *
 *  Created on: 06 mar 2017
 *      Author: fabbox
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "../include/sr_genl.h"
#include "../include/sr_hook.h"

#define RESPONSE_OK "Operation successfully executed."
#define RESPONSE_ER "Error from kernel space."

#define FIXED_NORTH_OPERATION 3
#define FIXED_SOUTH_OPERATION 3


static struct genl_family sr_gnl_family = {
	//.id = GENL_ID_GENERATE,
	//.id = 0,
	.hdrsize = 0,
	.name = SR_GNL_FAMILY_NAME,
	.version = SR_GNL_FAMILY_VERSION,
	.maxattr = SR_A_MAX,
};

static struct nla_policy sr_genl_policy[_SR_A_MAX + 1] = {
	[SR_A_UNSPEC]		=	{ .type = NLA_STRING },
	[SR_A_TABLE]		=	{ .type = NLA_STRING },
	[SR_A_COMMAND] 		=	{ .type = NLA_STRING },
	[SR_A_SID]			=	{ .type = NLA_STRING },
	[SR_A_OP1]			=	{ .type = NLA_STRING },
	[SR_A_OP2]			=	{ .type = NLA_STRING },
	[SR_A_MODE]			=	{ .type = NLA_STRING },
	[SR_A_IFACE]		=	{ .type = NLA_STRING },
	[SR_A_MAC]			=	{ .type = NLA_BINARY },
	[SR_A_RESPONSE]		=	{ .type = NLA_STRING },
	[SR_A_RESPONSE_LST]	=	{ .type = NLA_STRING }
};

static void set_msg_data(struct genl_msg_data *msg_data, int type, void *data, int len){
	msg_data->atype = type;
	msg_data->data 	= data;
	msg_data->len 	= len + 1;
}

static void *extract_nl_attr(const struct genl_info *info, const int atype){
	struct nlattr *na;
	void *data = NULL;
	na = info->attrs[atype];
	if(na) data = nla_data(na);
	return data;
}

static void extract_sr_attrs(const struct genl_info *info, struct sr_param *a){
	a->table	= (char *) extract_nl_attr(info, SR_A_TABLE);
	a->sid		= (char *) extract_nl_attr(info, SR_A_SID);
	a->op1		= (char *) extract_nl_attr(info, SR_A_OP1);
	a->op2		= (char *) extract_nl_attr(info, SR_A_OP2);
	a->mode		= (char *) extract_nl_attr(info, SR_A_MODE);
	a->iface	= (char *) extract_nl_attr(info, SR_A_IFACE);
	a->mac		= (struct sr_mac *) extract_nl_attr(info, SR_A_MAC);

	a->source	= (char *) extract_nl_attr(info, SR_A_SOURCE);
	a->addr		= (char *) extract_nl_attr(info, SR_A_ADDR);
	a->segs		= (char *) extract_nl_attr(info, SR_A_SEGS);
	a->sid_lst	= (char *) extract_nl_attr(info, SR_A_SID_LST);
	a->left		= (char *) extract_nl_attr(info, SR_A_LEFT);
	a->number	= (char *) extract_nl_attr(info, SR_A_NUMBER);
	a->flags	= (char *) extract_nl_attr(info, SR_A_FLAGS);
}

static void print_mac(struct sr_mac *mac){
	printk("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) mac->oct[0],
			(unsigned char) mac->oct[1],
			(unsigned char) mac->oct[2],
			(unsigned char) mac->oct[3],
			(unsigned char) mac->oct[4],
			(unsigned char) mac->oct[5]);
}

static void print_attributes(struct sr_param *sr_attr){

	if(sr_attr->table != NULL)	printk("Table:		%s\n", sr_attr->table);
	if(sr_attr->sid != NULL)	printk("Sid:		%s\n", sr_attr->sid);
	if(sr_attr->op1 != NULL)	printk("Op1:		%s\n", sr_attr->op1);
	if(sr_attr->op2 != NULL)	printk("Op2:		%s\n", sr_attr->op2);
	if(sr_attr->mode != NULL)	printk("Mode:		%s\n", sr_attr->mode);
	if(sr_attr->iface != NULL)	printk("Iface:		%s\n", sr_attr->iface);

	if(sr_attr->mac != NULL)	print_mac(sr_attr->mac);

	if(sr_attr->source != NULL)		printk("Source:		%s\n", sr_attr->source);
	if(sr_attr->addr != NULL)		printk("Addr:		%s\n", sr_attr->addr);
	if(sr_attr->segs != NULL)		printk("Segs:		%s\n", sr_attr->segs);
	if(sr_attr->sid_lst != NULL)	printk("Sid-lst:		%s\n", sr_attr->sid_lst);
	if(sr_attr->left != NULL)		printk("Left:		%s\n", sr_attr->left);
	if(sr_attr->number != NULL)		printk("Number:		%s\n", sr_attr->number);
	if(sr_attr->flags != NULL)		printk("Flags:		%s\n", sr_attr->flags);
}


static int send_response(struct genl_info *info, unsigned int n_data, struct genl_msg_data *msg_data){
	struct sk_buff *skb;
	void *skb_head;
	int i, ret;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL){
		dmesge("send_response - unable to allocate skb");
		return -1;
	}

	skb_head = genlmsg_put(skb, 0, info->snd_seq+1, &sr_gnl_family, 0, info->genlhdr->cmd);
	if (skb_head == NULL) {
		dmesge("send_response - unable to allocate skb_head");
		return -ENOMEM;
	}

	for(i=0; i<n_data; i++){
		if((ret = nla_put(skb, msg_data[i].atype, msg_data[i].len, msg_data[i].data)) < 0){
			dmesge("send_response - unable to put attribute %d for elem %d/%d: %d", msg_data[i].atype, i, n_data, ret);
			return -1;
		}
	}

	genlmsg_end(skb, skb_head);

	if(genlmsg_unicast(genl_info_net(info), skb, info->snd_portid ) != 0){
		dmesge("send_response - unable to send response - info->snd_portid = %u", info->snd_portid);
		return -1;
	}

	return 0;
}

static int sr_genl_echo(struct sk_buff *skb, struct genl_info *info){
	char *message;
	struct genl_msg_data data[1];

	char *response = "Hello from kernel space!";

	message = (char *) extract_nl_attr(info, SR_A_UNSPEC);

	if(message == NULL)
		dmesg("Message from user space: NULL");
	else
		dmesg("Message from user space: %s", message);

	set_msg_data(data, SR_A_RESPONSE, response, strlen(response));
	return send_response(info, 1, data);
}

/* handle add commands */
static int sr_genl_add(struct sk_buff *skb, struct genl_info *info){
	int ret = -1;
	struct genl_msg_data data[1];
	int operation = 0;

	/*
	 * These lines extract all the attributes and print them to the dmesg
	 */
	struct sr_param attr;
	extract_sr_attrs(info, &attr);
	print_attributes(&attr);
	/**/

	if ( attr.iface != NULL && attr.sid != NULL && attr.table !=NULL){

		if ( strncmp(attr.table, NORTH, strlen(attr.table)) == 0 ) {

			//TODO operation should be evaluated by srconf.c and passed in the netlink message
			if ( attr.mode !=NULL && strncmp(attr.mode, AUTO, strlen(attr.mode)) == 0 ) {
				operation = operation | CODE_AUTO;
			}
			if ( attr.op1 !=NULL ) {
				if ( strncmp(attr.op1, OP_DECAPFW, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_DECAPFW;
				}
				if ( strncmp(attr.op1, OP_MASQFW, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_MASQFW;
				}
				if ( strncmp(attr.op1, OP_DEINSFW, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_DEINSFW;
				}
			}
			
			ret = bind_sid_north(attr.sid, operation, attr.iface, attr.mac->oct);
		}
		if ( strncmp(attr.table, SOUTH, strlen(attr.table)) == 0 ) {
			//TODO operation should be evaluated by srconf.c and passed in the netlink message
			if ( attr.mode !=NULL && strncmp(attr.mode, AUTO, strlen(attr.mode)) == 0 ) {
				operation = operation | CODE_AUTO;
			}
			if ( attr.op1 !=NULL ) {
				if ( strncmp(attr.op1, OP_ENCAP, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_ENCAP;
				}
				if ( strncmp(attr.op1, OP_DEMASQ, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_DEMASQ;
				}
				if ( strncmp(attr.op1, OP_INS, strlen(attr.op1)) == 0 ) {
					operation = operation | CODE_INS;
				}
			}

			
			ret = bind_nic_south(attr.iface, FIXED_SOUTH_OPERATION, attr.sid);
		}
	}
	
	if(ret >= 0)
		set_msg_data(data, SR_A_RESPONSE, RESPONSE_OK, strlen(RESPONSE_OK));
	else
		set_msg_data(data, SR_A_RESPONSE, RESPONSE_ER, strlen(RESPONSE_ER));

	return send_response(info, 1, data);
}

/* handle del commands */
static int sr_genl_del(struct sk_buff *skb, struct genl_info *info){
	int ret = -1;
	struct genl_msg_data data[1];

	/*
	 * These lines extract all the attributes and print them to the dmesg
	 */
	struct sr_param attr;
	extract_sr_attrs(info, &attr);
	print_attributes(&attr);
	/**/

	if (attr.sid != NULL && attr.table !=NULL){
		if ( strncmp(attr.table, NORTH, strlen(attr.table)) == 0 )
			ret = unbind_sid_north(attr.sid);
	}
	if (attr.iface != NULL && attr.table !=NULL){
		if ( strncmp(attr.table, SOUTH, strlen(attr.table)) == 0 )
			ret = unbind_nic_south(attr.iface);

	}
	//ret = 0;
	if(ret >= 0)
		set_msg_data(data, SR_A_RESPONSE, RESPONSE_OK, strlen(RESPONSE_OK));
	else
		set_msg_data(data, SR_A_RESPONSE, RESPONSE_ER, strlen(RESPONSE_ER));

	return send_response(info, 1, data);
}

static int sr_genl_show(struct sk_buff *skb, struct genl_info *info){
	int ret;
	struct genl_msg_data data[1];

	int len, i;
	char *message;

	/*
	 * These lines extract all the attributes and print them do the dmesg
	 */
	struct sr_param attr;
	extract_sr_attrs(info, &attr);
	print_attributes(&attr);
	/**/

	//TODO here the code to handle SHOW command
	// ...
	// ...
        len = 1024 * 4;
        message = (char *) kzalloc(len, GFP_ATOMIC);

        if(strcmp(attr.table,NORTH)==0) {
        	strcpy(message, NORTH);
        	strcpy(message+strlen(message),"\n");
		//strcpy(message+strlen(message),NORTH);
		//printk("%pI6c",vnf_ip.s6_addr);
			show_north(message+strlen(message),40);
        } else {

        if(strcmp(attr.table,SOUTH)==0) {
            strcpy(message, SOUTH);
        	strcpy(message+strlen(message),"\n");

   			show_south(message+strlen(message),40);

        } else {


	/**************/
	//Example of a list string response, it is possible to insert '\n' and '\t'
//	len = 1024 * 4;
//	message = (char *) kzalloc(len, GFP_ATOMIC);
	for(i=0; i<len; i++){
		message[i] = (i % 57) + 65;
		if(i % 100 == 0) message[i] = '\n';
	}
	}
	}
	if(strlen(message) > 4096){ //the maximum lenght of the string
		set_msg_data(data, SR_A_RESPONSE, RESPONSE_ER, strlen(RESPONSE_ER));
	}
	else set_msg_data(data, SR_A_RESPONSE_LST, message, strlen(message));
	/**************/

	ret = send_response(info, 1, data);
	kfree(message);

	return ret;
}

static int sr_genl_dispatcher(struct sk_buff *skb, struct genl_info *info){
	int command;

	command = info->genlhdr->cmd;

	//TODO put here the lock routine

	switch (command) {
		case SR_C_ECHO:
			dmesg("NVF_C_ECHO genl command received");
			sr_genl_echo(skb, info);
			break;
		case SR_C_ADD:
			dmesg("NVF_C_ADD genl command received");
			sr_genl_add(skb, info);
			break;
		case SR_C_DEL:
			dmesg("NVF_C_DEL genl command received");
			sr_genl_del(skb, info);
			break;
		case SR_C_SHOW:
			dmesg("NVF_C_SHOW genl command received");
			sr_genl_show(skb, info);
			break;
		default:
			break;
	}

	//TODO put here the unlock routine

	return 0;
}
/***********************/
static struct genl_ops nvf_genl_ops[] = {
		{
			.cmd = SR_C_ECHO,
			.flags = 0,
			.policy = sr_genl_policy,
			.doit = sr_genl_dispatcher,
			.dumpit = NULL,
		},
		{
			.cmd = SR_C_ADD,
			.flags = 0,
			.policy = sr_genl_policy,
			.doit = sr_genl_dispatcher,
			.dumpit = NULL,
		},
		{
			.cmd = SR_C_DEL,
			.flags = 0,
			.policy = sr_genl_policy,
			.doit = sr_genl_dispatcher,
			.dumpit = NULL,
		},
		{
			.cmd = SR_C_SHOW,
			.flags = 0,
			.policy = sr_genl_policy,
			.doit = sr_genl_dispatcher,
			.dumpit = NULL,
		}
};

int sr_genl_register(){
	int rc;

	sr_gnl_family.module	= THIS_MODULE;
	sr_gnl_family.ops		= nvf_genl_ops;
	sr_gnl_family.n_ops		= ARRAY_SIZE(nvf_genl_ops);
	sr_gnl_family.mcgrps	= NULL;
	sr_gnl_family.n_mcgrps	= 0;

	rc = genl_register_family(&sr_gnl_family);

	if (rc != 0){
		dmesge("Unable to register %s genetlink family", sr_gnl_family.name);
		return -1;
	}
	dmesg("%s genetlink family successfully registered", sr_gnl_family.name);

	return 0;
}

int sr_genl_unregister(){
	int rc;
	rc = genl_unregister_family(&sr_gnl_family);
	if (rc != 0){
		dmesge("Unable to unregister %s genetlink family", sr_gnl_family.name);
		return -1;
	}
	dmesg("%s genetlink family successfully unregistered", sr_gnl_family.name);
	return 0;
}

// Wrapping printk to add module name
void dmesg( const char * format, ...){
    va_list ap;
    va_start(ap, format);
    printk("[SR module] ");
    vprintk(format, ap);
    printk("\n");
    va_end(ap);
}

// Wrapping printk to add module name and error string
void dmesge( const char * format, ...){
	va_list ap;
	va_start(ap, format);
	printk("[SR module][Error] ");
	vprintk(format, ap);
	printk("\n");
	va_end(ap);
}

/*
int sr_init(void)
{
    printk(KERN_ALERT "Loading SR-genetlink module...\n");
    sr_genl_register();
    return 0;
}

void sr_exit(void)
{
    printk(KERN_ALERT "Unloading Sr-genetlink module...\n");
    sr_genl_unregister();
}

module_init(sr_init);
module_exit(sr_exit);
*/
