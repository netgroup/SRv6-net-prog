/*
 * srconf.c
 *
 *  Created on: 07 mar 2017
 *      Author: fabbox
 */

//#define DEBUG_SRCONF

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <errno.h>

#include "../include/srconf.h"

int sd;
int nvf_fam_id;
struct genl_msg req, ans;
struct 	nlattr *nl_attr[SR_A_MAX + 1];

struct sr_param params;

void reset_parameters(){
	params.table	= NULL;
	params.command	= NULL;
	params.sid		= NULL;
	params.op1		= NULL;
	params.op2		= NULL;
	params.mode		= NULL;
	params.iface	= NULL;

	params.source	= NULL;
	params.addr		= NULL;
	params.segs 	= NULL;
	params.sid_lst	= NULL;
	params.left 	= NULL;
	params.number	= NULL;
	params.flags 	= NULL;

	free(params.mac);
	params.mac		= NULL;
}

static char * get_attr_name(int index){
	switch (index) {
		case SR_A_UNSPEC:
			return "SR_A_UNSPEC";
		case SR_A_RESPONSE:
			return "SR_A_RESPONSE";
		case SR_A_RESPONSE_LST:
			return "SR_A_RESPONSE_LST";
		default:
			break;
	}
	return NULL;
}

static void print_nl_attrs(){
	int i;
	char *name;
	void *data;

	for(i=0; i<=SR_A_MAX; i++){
		if(nl_attr[i] == NULL) continue;
		data = GENLMSG_NLA_DATA(nl_attr[i]);
		name = get_attr_name(i);
		printf("%s: %s\n", name, (char *) data);
	}
}

static void reset_nl_attrs(void){
	int i;
	for(i=0; i<=SR_A_MAX; i++){
		nl_attr[i] = NULL;
	}
}

void parse_nl_attrs(){
	unsigned int n_attrs = 0;
	struct nlattr *na;
	unsigned int data_len = GENLMSG_DATALEN(&ans.n);

	reset_nl_attrs();

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	nl_attr[na->nla_type] = na;
	data_len -= NLA_ALIGN(na->nla_len);

	while(data_len > 0){
		n_attrs++;
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		nl_attr[na->nla_type] = na;
		data_len -= NLA_ALIGN(na->nla_len);
	}
	//printf("NVF_A_MAX: %d\n", NVF_A_MAX);
	//if(n_attrs > NVF_A_MAX) printf("parse_nl_attrs - too much attributes\n");
}

int do_receive_response(){
	memset(ans.buf, 0, MAX_BUF_LEN);
	int rep_len = recv(sd, &ans, sizeof(ans), 0);

	if (ans.n.nlmsg_type == NLMSG_ERROR) {
		printf("do_receive_response - received nack - leaving.\n");
		exit(-1);
	}
	if (rep_len < 0) {
		printf("do_receive_response - error receiving reply message.\n");
		exit(-1);
	}
	if (!NLMSG_OK((&ans.n), rep_len)) {
		printf("do_receive_response - invalid reply message received.\n");
		exit(-1);
	}

	parse_nl_attrs();

	return 0;
}

int receive_response() {
	while (do_receive_response());
	print_nl_attrs();
	return 0;
}

static int sendto_fd(int s, const char *buf, int bufLen){
	int r;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(struct sockaddr_nl));
	nladdr.nl_family = AF_NETLINK;

	while ((r = sendto(s, buf, bufLen, 0, (struct sockaddr *) &nladdr, sizeof(struct sockaddr_nl))) < bufLen){
		if (r > 0) {
			buf += r;
			bufLen -= r;
		} else if (errno != EAGAIN) return -1;
	}
	return 0;
}

static void set_nl_attr(struct nlattr *na, const unsigned int type, const void *data, const unsigned int len){
	int length;

	length = len + 1;
	na->nla_type = type;
	na->nla_len = length + NLA_HDRLEN;
	memcpy(GENLMSG_NLA_DATA(na), data, length);
}

int create_nl_socket(void){
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0){
		perror("create_nl_socket - unable to create netlink socket.");
		exit(0);
	}

	sd = fd;

	return 0;
}

void set_nl_header(int command){
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= nvf_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 60;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= command;
}

int get_family_id(){
	int id;
	struct nlattr *na;

	if (strlen(SR_GNL_FAMILY_NAME) > 16){
		printf("get_family_id - hostname too long.");
		exit(0);
	}

	set_nl_header(CTRL_CMD_GETFAMILY);

	req.n.nlmsg_type	= GENL_ID_CTRL;
	req.n.nlmsg_seq 	= 0;
	req.g.version 		= 0x1;

	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, CTRL_ATTR_FAMILY_NAME, SR_GNL_FAMILY_NAME, strlen(SR_GNL_FAMILY_NAME));

	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;

	while (do_receive_response());

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) GENLMSG_NLA_DATA(na);
	}

	nvf_fam_id = id;
	return 0;
}

int genl_client_init(){
	reset_nl_attrs();
	create_nl_socket();
	get_family_id();
	return 0;
}

int send_echo_command(){
	struct nlattr *na;
	char message[] = "Hello from user space!";

	set_nl_header(SR_C_ECHO);

	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, SR_A_UNSPEC, message, strlen(message));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
	receive_response();
	return 0;
}

void set_attributes(){
	struct nlattr *na;

	if(params.table == NULL){
		printf("set_attributes: table is null.\n");
		exit(0);
	}

	if(params.table != NULL){
		na = (struct nlattr *) GENLMSG_DATA(&req);
		set_nl_attr(na, SR_A_TABLE, params.table, strlen(params.table));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	/*
	 * NORTH
	 */
	if(params.sid != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_SID, params.sid, strlen(params.sid));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.op1 != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_OP1, params.op1, strlen(params.op1));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.op2 != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_OP2, params.op2, strlen(params.op2));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.mode != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_MODE, params.mode, strlen(params.mode));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.iface != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_IFACE, params.iface, strlen(params.iface));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.mac != 0){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		//set_nl_attr(na, SR_A_MAC, params.mac, strlen(params.mac));
		set_nl_attr(na, SR_A_MAC, params.mac, sizeof(struct sr_mac));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	/*
	 * SOUTH
	 */
	if(params.source != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_SOURCE, params.source, strlen(params.source));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.addr != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_ADDR, params.addr, strlen(params.addr));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.segs != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_SEGS, params.segs, strlen(params.segs));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.sid_lst != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_SID_LST, params.sid_lst, strlen(params.sid_lst));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.left != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_LEFT, params.left, strlen(params.left));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.number != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_NUMBER, params.number, strlen(params.number));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

	if(params.flags != NULL){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		set_nl_attr(na, SR_A_FLAGS, params.flags, strlen(params.flags));
		req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
	}

}

int send_add_command(){
	set_nl_header(SR_C_ADD);
	set_attributes();
	if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
	receive_response();
	return 0;
}

int send_del_command(){
	set_nl_header(SR_C_DEL);
	set_attributes();
	if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
	receive_response();
	return 0;
}

int send_show_command(){
	set_nl_header(SR_C_SHOW);
	set_attributes();
	if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
	receive_response();
	return 0;
}

void check_operation(char *op){
	if(op == NULL) goto error;

	if(strcmp(op, OP_FW) == 0)		return;
	if(strcmp(op, OP_DECAPFW) == 0)	return;
	if(strcmp(op, OP_MASQFW) == 0)	return;
	if(strcmp(op, OP_DEINSFW) == 0)	return;

	if(strcmp(op, OP_ENCAP) == 0)	return;
	if(strcmp(op, OP_DEMASQ) == 0)	return;

	error:
	printf("Operation is not valid.\n");
	exit(-1);
}

void print_mac(struct sr_mac *mac){
	printf("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) mac->oct[0],
			(unsigned char) mac->oct[1],
			(unsigned char) mac->oct[2],
			(unsigned char) mac->oct[3],
			(unsigned char) mac->oct[4],
			(unsigned char) mac->oct[5]);
}

int is_esadecimal(char c){
	int i;
	char numbers[] = {'0','1','2','3','4','5','6','7','8','9'};
	char lettersUp[] = {'a','b','c','d','e','f'};
	char lettersDw[] = {'A','B','C','D','E','F'};

	for(i=0; i<strlen(numbers); i++)
		if(c == numbers[i]) return 0;

	for(i=0; i<strlen(lettersUp); i++)
		if(c == lettersUp[i]) return 0;

	for(i=0; i<strlen(lettersDw); i++)
		if(c == lettersDw[i]) return 0;

	return -1;
}

int validate_mac_token(char *token){
	if(strlen(token) != 2) return -1;
	if(is_esadecimal(token[0]) < 0) return -1;
	if(is_esadecimal(token[1]) < 0) return -1;
	return 0;
}

void parse_mac(char *string){
	int index;
	char *token;
	char string_copy[strlen(string)];
	unsigned long N;

	params.mac = (struct sr_mac *) malloc(sizeof(struct sr_mac));

	strcpy(string_copy, string);

	index = 0;
	token = strtok(string_copy, ":");
	while( token != NULL ){
		//printf( "TOKEN %d: %s\n", index, token);
		if(validate_mac_token(token) < 0){
			printf("Mac address is not valid.\n");
			exit(0);
		}
		N = strtoul(token, NULL, 16);
		params.mac->oct[index] = N;

		token = strtok(NULL, ":");
		index++;
	}
	if(index != 6){
  	  printf("Mac address is not valid.\n");
  	  exit(0);
    }

	//sscanf(string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &params.mac->oct[0], &params.mac->oct[1],
			//&params.mac->oct[2], &params.mac->oct[3], &params.mac->oct[4], &params.mac->oct[5]);
	print_mac(params.mac);
}

void inc(int argc, int *index){
	*index = *index + 1;
	if(*index >= argc){
		printf("Too few parameters.\n");
		exit(0);
	}
}

void print_command_line(int argc, char **argv){
	int i = 0;
	printf("-----------------------\n");
	printf("argc: %d\n", argc);
	for (i=0; i<argc; i++) {
		printf("argv[%d]: %s\n", i, argv[i]);
	}
	printf("-----------------------\n");
}

void print_parameters(){
	printf("\n--- Parsed parameters\n");
	if(params.table != NULL)	printf("Table:		%s\n", params.table);
	if(params.command != NULL)	printf("Command:	%s\n", params.command);
	if(params.sid != NULL)		printf("Sid:		%s\n", params.sid);
	if(params.op1 != NULL)		printf("Op1:		%s\n", params.op1);
	if(params.op2 != NULL)		printf("Op2:		%s\n", params.op2);
	if(params.mode != NULL)		printf("Mode:		%s\n", params.mode);
	if(params.iface != NULL)	printf("Iface:		%s\n", params.iface);

	if(params.mac != NULL)		print_mac(params.mac);

	if(params.source != NULL)	printf("Source:		%s\n", params.source);
	if(params.addr != NULL)		printf("Addr:		%s\n", params.addr);
	if(params.segs != NULL)		printf("Segs:		%s\n", params.segs);
	if(params.sid_lst != NULL)	printf("Sid-lst:	%s\n", params.sid_lst);
	if(params.left != NULL)		printf("Left:		%s\n", params.left);
	if(params.number != NULL)	printf("Number:		%s\n", params.number);
	if(params.flags != NULL)	printf("Flags:		%s\n", params.flags);
	printf("\n---------------------\n");
}

/*
 * Supported commands
 */

//srconf hello

//srconf north add cccc::2 fw veth3 00:AA:00:62:C6:09
//srconf north add cccc::2 masqfw veth3 00:AA:00:62:C6:09

//srconf north add cccc::2 decapfw veth3 00:AA:00:62:C6:09
//srconf north add cccc::2 decapfw auto veth5 00:AA:00:62:C6:09

//srconf south add veth5 demasq
//srconf south add veth5 encap auto dddd::2
//srconf south add veth3 encap params.source cccc::2 params.segs bbbb::2,dddd::2,aa::5 params.left 1

//srconf north del SID
//srconf south del INTERFACE

//srconf north show
//srconf south show


int main(int argc, char **argv){

	int i, index;

	printf("\n");
	reset_parameters();

	#ifdef DEBUG_SRCONF
	print_command_line(argc, argv);
	#endif

	genl_client_init();

	if(argc == 2){
		if(strcmp(argv[1], "hello") == 0){
			send_echo_command();
			return 0;
		}
	}

	if(argc <= 2){
		printf("Too few parameters\n");
		exit(0);
	}

	for (i=1; i<argc; i++) {
		if(i == 1) params.table = argv[i];
		if(i == 2) params.command = argv[i];
	}

	if((strcmp(params.table, NORTH) != 0)&&(strcmp(params.table, SOUTH) != 0)){
		printf("table %s is not valid.\n", params.table);
		return -1;
	}
	if((strcmp(params.command, ADD) != 0)&&(strcmp(params.command, DEL) != 0)&&(strcmp(params.command, SHOW) != 0)){
		printf("command %s is not valid.\n", params.command);
		return -1;
	}

	index = 3;

	/*
	 * NORTH params.table
	 */
	if(strcmp(params.table, NORTH) == 0){

		if(strcmp(params.command, ADD) == 0){
			if(argc > 3) params.sid = argv[3];
			if(argc > 4) params.op1 = argv[4];
			if((params.sid == NULL)||(params.op1 == NULL)){
				printf("Sid or operation are not valid.\n");
				return -1;
			}
			check_operation(params.op1);

			index = 4;

			if(strcmp(params.op1, OP_FW) == 0){
				inc(argc, &index);
				params.iface = argv[index];
				inc(argc, &index);
				parse_mac(argv[index]);
			}

			if(strcmp(params.op1, OP_MASQFW) == 0){
				inc(argc, &index);
				params.iface = argv[index];
				inc(argc, &index);
				parse_mac(argv[index]);
			}

			if(strcmp(params.op1, OP_DECAPFW) == 0){
				inc(argc, &index);
				if(strcmp(argv[index], AUTO) == 0){
					params.mode = argv[index];
					inc(argc, &index);
				}

				params.iface = argv[index];
				inc(argc, &index);
				parse_mac(argv[index]);
			}
			send_add_command();
			goto end;
		}

		if(strcmp(params.command, DEL) == 0){
			if(argc > 3) params.sid = argv[3];
			if(params.sid == NULL){
				printf("Sid is not valid.\n");
				return -1;
			}
			send_del_command();
			goto end;
		}

		if(strcmp(params.command, SHOW) == 0){
			send_show_command();
			goto end;
		}
	}

	/*
	 * SOUTH params.table
	 */
	if(strcmp(params.table, SOUTH) == 0){

		if(strcmp(params.command, ADD) == 0){
			if(argc > 3) params.iface = argv[3];
			if(argc > 4) params.op1 = argv[4];
			if((params.iface == NULL)||(params.op1 == NULL)){
				printf("Iface or operation are not valid.\n");
				return -1;
			}
			check_operation(params.op1);

			index = 4;

			if(strcmp(params.op1, OP_DEMASQ) == 0){
				send_add_command();
				goto end;
			}

			if(strcmp(params.op1, OP_ENCAP) == 0){
				inc(argc, &index);
				if(strcmp(argv[index], AUTO) == 0){
					params.mode = argv[index];
					inc(argc, &index);
					params.sid = argv[index];
					send_add_command();
					goto end;
				}

				params.source = argv[index];
				inc(argc, &index);
				params.addr = argv[index];
				inc(argc, &index);
				params.segs = argv[index];
				inc(argc, &index);
				params.sid_lst = argv[index];
				inc(argc, &index);
				params.left = argv[index];
				inc(argc, &index);
				params.number = argv[index];
				if((index + 1) < argc){
					inc(argc, &index);
					params.flags = argv[index];
				}
				send_add_command();
				goto end;
			}

			if(strcmp(params.op1, OP_INS) == 0){
				send_add_command();
				//TODO srconf south add veth5 ins segs bbbb::2,dddd::2 left 1
				goto end;
			}
		}

		if(strcmp(params.command, DEL) == 0){
			if(argc > 3) params.iface = argv[3];
			if(params.iface == NULL){
				printf("Iface is not valid.\n");
				return -1;
			}
			send_del_command();
			goto end;
		}

		if(strcmp(params.command, SHOW) == 0){
			send_show_command();
			goto end;
		}
	}

end:
	#ifdef DEBUG_SRCONF
	print_parameters();
	#endif

	return 0;
}
