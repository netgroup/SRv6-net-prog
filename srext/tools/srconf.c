/*
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <errno.h>
#include <net/if.h>
#include "../include/srconf.h"

int sd;
int srext_fam_id;
struct genl_msg req, ans;
struct  nlattr *nl_attr[SR_A_MAX + 1];

struct sr_param params;

void reset_parameters() {
    params.table    = NULL;
    params.command  = NULL;
    params.sid      = NULL;
    params.func     = NULL;
    params.next     = NULL;
    params.oif      = NULL;
    params.iif      = NULL;

    params.source   = NULL;
    params.addr     = NULL;
    params.segs     = NULL;
    params.sid_lst  = NULL;
    params.left     = NULL;
    params.number   = NULL;
    params.flags    = NULL;

    free(params.mac);
    params.mac      = NULL;
}

static void print_nl_attrs()
{
    int i;
    void *data;

    for (i = 0; i <= SR_A_MAX; i++) {
        if (nl_attr[i] == NULL) continue;
        data = GENLMSG_NLA_DATA(nl_attr[i]);
        printf("%s\n", (char *) data);
    }
}

static void reset_nl_attrs(void)
{
    int i;
    for (i = 0; i <= SR_A_MAX; i++) {
        nl_attr[i] = NULL;
    }
}

void parse_nl_attrs()
{
    unsigned int n_attrs = 0;
    struct nlattr *na;
    unsigned int data_len = GENLMSG_DATALEN(&ans.n);

    reset_nl_attrs();

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    nl_attr[na->nla_type] = na;
    data_len -= NLA_ALIGN(na->nla_len);

    while (data_len > 0) {
        n_attrs++;
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        nl_attr[na->nla_type] = na;
        data_len -= NLA_ALIGN(na->nla_len);
    }
}

int do_receive_response()
{
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

int receive_response()
{
    while (do_receive_response());
    print_nl_attrs();
    return 0;
}

static int sendto_fd(int s, const char *buf, int bufLen)
{
    int r;
    struct sockaddr_nl nladdr;

    memset(&nladdr, 0, sizeof(struct sockaddr_nl));
    nladdr.nl_family = AF_NETLINK;

    while ((r = sendto(s, buf, bufLen, 0, (struct sockaddr *) &nladdr,
                       sizeof(struct sockaddr_nl))) < bufLen) {
        if (r > 0) {
            buf += r;
            bufLen -= r;
        } else if (errno != EAGAIN) return -1;
    }
    return 0;
}

static void set_nl_attr(struct nlattr *na, const unsigned int type,
                        const void *data, const unsigned int len)
{
    int length;

    length = len + 1;
    na->nla_type = type;
    na->nla_len = length + NLA_HDRLEN;
    memcpy(GENLMSG_NLA_DATA(na), data, length);
}

int create_nl_socket(void)
{
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        perror("create_nl_socket - unable to create netlink socket.");
        exit(0);
    }

    sd = fd;
    return 0;
}

void set_nl_header(int command)
{
    req.n.nlmsg_len     = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type    = srext_fam_id;
    req.n.nlmsg_flags   = NLM_F_REQUEST;
    req.n.nlmsg_seq     = 60;
    req.n.nlmsg_pid     = getpid();
    req.g.cmd           = command;
}

int get_family_id()
{
    int id;
    struct nlattr *na;

    if (strlen(SR_GNL_FAMILY_NAME) > 16) {
        printf("get_family_id - hostname too long.");
        exit(0);
    }

    set_nl_header(CTRL_CMD_GETFAMILY);

    req.n.nlmsg_type    = GENL_ID_CTRL;
    req.n.nlmsg_seq     = 0;
    req.g.version       = 0x1;

    na = (struct nlattr *) GENLMSG_DATA(&req);
    set_nl_attr(na, CTRL_ATTR_FAMILY_NAME, SR_GNL_FAMILY_NAME,
                strlen(SR_GNL_FAMILY_NAME));

    req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;

    while (do_receive_response());

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) GENLMSG_NLA_DATA(na);
    }

    srext_fam_id = id;
    return 0;
}

int genl_client_init()
{
    reset_nl_attrs();
    create_nl_socket();
    get_family_id();
    return 0;
}

void set_attributes()
{
    struct nlattr *na;

    if (params.table == NULL) {
        printf("set_attributes: table is null.\n");
        exit(0);
    }

    if (params.table != NULL) {
        na = (struct nlattr *) GENLMSG_DATA(&req);
        set_nl_attr(na, SR_A_TABLE, params.table, strlen(params.table));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.sid != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_SID, params.sid, strlen(params.sid));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.func != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_FUNC, params.func, strlen(params.func));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.next != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_NEXT, params.next, strlen(params.next));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.mac != 0) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_MAC, params.mac, sizeof(struct sr_mac));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.oif != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_OIF, params.oif, strlen(params.oif));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.iif != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_IIF, params.iif, strlen(params.iif));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.source != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_SOURCE, params.source, strlen(params.source));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.addr != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_ADDR, params.addr, strlen(params.addr));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.segs != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_SEGS, params.segs, strlen(params.segs));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.sid_lst != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_SID_LST, params.sid_lst, strlen(params.sid_lst));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.left != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_LEFT, params.left, strlen(params.left));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.number != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_NUMBER, params.number, strlen(params.number));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.flags != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, SR_A_FLAGS, params.flags, strlen(params.flags));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

}

int send_add_command()
{
    set_nl_header(SR_C_ADD);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

int send_del_command()
{
    set_nl_header(SR_C_DEL);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

int send_show_command()
{
    set_nl_header(SR_C_SHOW);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

int send_flush_command()
{
    set_nl_header(SR_C_FLUSH);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

int send_clear_command()
{
    set_nl_header(SR_C_CLEAR);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

void print_mac(struct sr_mac *mac)
{
    printf("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           (unsigned char) mac->oct[0],
           (unsigned char) mac->oct[1],
           (unsigned char) mac->oct[2],
           (unsigned char) mac->oct[3],
           (unsigned char) mac->oct[4],
           (unsigned char) mac->oct[5]);
}

int is_esadecimal(char c)
{
    int i, ret = 0;
    char numbers[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    char lettersUp[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    char lettersDw[] = {'A', 'B', 'C', 'D', 'E', 'F'};

    for (i = 0; i < strlen(numbers); i++)
        if (c == numbers[i])
            goto end;

    for (i = 0; i < strlen(lettersUp); i++)
        if (c == lettersUp[i])
            goto end;

    for (i = 0; i < strlen(lettersDw); i++)
        if (c == lettersDw[i])
            goto end;

    ret = -1;

end:
    return ret ;
}

int validate_mac_token(char *token)
{
    int ret = -1;
    if (strlen(token) != 2)
        goto end;

    if (is_esadecimal(token[0]) < 0)
        goto end;

    if (is_esadecimal(token[1]) < 0)
        goto end;

    ret =  0;

end:
    return ret ;
}

int parse_mac(char *string)
{
    int index, ret = -1;
    char *token;
    char string_copy[strlen(string)];
    unsigned long N;

    params.mac = (struct sr_mac *) malloc(sizeof(struct sr_mac));

    strcpy(string_copy, string);

    index = 0;
    token = strtok(string_copy, ":");
    while ( token != NULL ) {
        if (validate_mac_token(token) < 0) {
            printf("MAC address is not valid.\n");
            goto end;
        }

        N = strtoul(token, NULL, 16);
        params.mac->oct[index] = N;

        token = strtok(NULL, ":");
        index++;
    }
    if (index != 6) {
        printf("MAC address is not valid.\n");
        goto end;
    }

    ret = 0;
end:
    return ret;
}

void print_command_line(int argc, char **argv)
{
    int i = 0;
    printf("-----------------------\n");
    printf("argc: %d\n", argc);
    for (i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    printf("-----------------------\n");
}

void print_parameters()
{
    printf("\n--- Parsed parameters\n");
    if (params.table   != NULL)  printf("Table:		%s\n", params.table);
    if (params.command != NULL)  printf("Command:	%s\n", params.command);
    if (params.sid     != NULL)  printf("Sid:		%s\n", params.sid);
    if (params.func    != NULL)  printf("Func:		%s\n", params.func);
    if (params.next    != NULL)  printf("next:		%s\n", params.next);

    if (params.mac     != NULL)  print_mac(params.mac);

    if (params.oif     != NULL)  printf("Oif:		%s\n", params.oif);
    if (params.iif     != NULL)  printf("Iif:		%s\n", params.iif);

    if (params.source  != NULL)  printf("Source:	%s\n", params.source);
    if (params.addr    != NULL)  printf("Addr:		%s\n", params.addr);
    if (params.segs    != NULL)  printf("Segs:		%s\n", params.segs);
    if (params.sid_lst != NULL)  printf("Sid-lst:	%s\n", params.sid_lst);
    if (params.left    != NULL)  printf("Left:		%s\n", params.left);
    if (params.number  != NULL)  printf("Number:	%s\n", params.number);
    if (params.flags   != NULL)  printf("Flags:		%s\n", params.flags);
    printf("\n---------------------\n");
}

static int usage(void)
{
    fprintf(stderr,
            "Usage: srconf TABLE { COMMAND | help} \n"
            "TABLE := { localsid | srdev } \n");
    return 0;
}

static int usage_localsid(void)
{
    fprintf(stderr,
            "Usage: srconf localsid { help | flush } \n"
            "       srconf localsid { show | clear-counters } [SID] \n"
            "       srconf localsid del SID \n"
            "       srconf localsid add SID BEHAVIOUR \n"
            "BEHAVIOUR:= { end | \n"
            "              end.dx2 TARGETIF | \n"
            "              end.dx4 NEXTHOP4 TARGETIF | \n"
            "              { end.x | end.dx6 } NEXTHOP6 TARGETIF | \n"
            "              { end.ad4 | end.ead4 } NEXTHOP4 TARGETIF SOURCEIF | \n"
            "              { end.am | end.ad6 | end.ead6 } NEXTHOP6 TARGETIF SOURCEIF | \n"
            "              end.as4 NEXTHOP4 TARGETIF SOURCEIF src ADDR segs SIDLIST left SEGMENTLEFT }\n"
            "              end.as6 NEXTHOP6 TARGETIF SOURCEIF src ADDR segs SIDLIST left SEGMENTLEFT |\n"
            "NEXTHOP4:= { ip IPv4-ADDR | mac MAC-ADDR }\n"
            "NEXTHOP6:= { ip IPv6-ADDR | mac MAC-ADDR }\n");
    return 0;
}

static int usage_srdev(void)
{
    fprintf(stderr,
            "Usage: srconf srdev { help | flush } \n\n" );
    return 0;
}

/**
 * add_end(): used by srconf to add a new SID with End behavior
 * End behavior doesn't require any arguments
*/

int add_end(int argc, char **argv)
{
    int ret = -1;
    if (argc > 5) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    ret = send_add_command();

end:
    return ret;
}

/**
 * add_end_dx2(): used by srconf to add a new SID with End.DX2 behavior
 * End.DX2 behavior requires a target interface as an argument
*/

int add_end_dx2(int argc, char **argv)
{
    int ret = -1;
    if (argc > 6) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc < 6) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (if_nametoindex(argv[5]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[5]);
        goto end;
    }

    params.oif = argv[5];
    ret = send_add_command();

end:
    return ret;
}

/**
 * add_end_dx4(): used by srconf to add a new SID with End.DX4 behavior
 * End.DX4 behavior requires an IPv4 address of the next_hop and a target
   interface as arguments
*/

int add_end_dx4(int argc, char **argv)
{
    int ret = -1 ;
    struct in_addr next_hop;

    if (argc > 8) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc < 8) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (strcmp(argv[5], "ip") != 0 && strcmp(argv[5], "mac") != 0  ) {
        printf(" invalid token \"%s\"\n", argv[5]);
        goto end;
    }

    if (if_nametoindex(argv[7]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[7]);
        goto end;
    }

    params.oif = argv[7];

    if ( strcmp(argv[5], "mac") == 0) {
        ret = parse_mac(argv[6]);
        if (!ret)
            goto send_add;

        goto end;
    }

    if (inet_pton(AF_INET, argv[6], &next_hop) != 1) {
        printf("Error: inet prefix is expected rather than \"%s\".\n", argv[6]);
        goto end;
    }

    params.next = argv[6];

send_add:
    ret = send_add_command();

end:
    return ret;
}

/**
 * add_end_x(): used by srconf to add a new SID with End.X behavior
 * End.X behavior requires as arguments:
   - IPv6 address of the next_hop
   - Target interfac
 * used also for END.DX6 behavior
 */

int add_end_x(int argc, char **argv)
{
    int ret = -1;
    struct in6_addr next_hop;

    if (argc > 8) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc < 8) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (strcmp(argv[5], "ip") != 0 && strcmp(argv[5], "mac") != 0  ) {
        printf(" invalid token \"%s\"\n", argv[5]);
        goto end;
    }

    if (if_nametoindex(argv[7]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[7]);
        goto end;
    }

    params.oif = argv[7];

    if ( strcmp(argv[5], "mac") == 0) {
        ret = parse_mac(argv[6]);
        if (!ret)
            goto send_add;

        goto end;
    }

    if (inet_pton(AF_INET6, argv[6], &next_hop) != 1) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[6]);
        goto end;
    }

    params.next = argv[6];

send_add:
    ret = send_add_command();

end:
    return ret ;
}

/**
 * add_end_ad6(): used by srconf to add a new SID with End.AD6 behavior
 * End.AD6 behavior requires as arguments:
   - IPv6 address of the next_hop
   - Target interfac
   - Source interfac
 * The next hop can be mac address of the VNF
 * used also for END.AM and End.EAD6 behaviors
 */

int add_end_ad6(int argc, char **argv)
{
    int ret = -1;
    struct in6_addr next_hop;

    if (argc > 9) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc < 9) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (strcmp(argv[5], "ip") != 0 && strcmp(argv[5], "mac") != 0  ) {
        printf(" invalid token \"%s\"\n", argv[5]);
        goto end;
    }

    if (if_nametoindex(argv[7]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[7]);
        goto end;
    }

    params.oif = argv[7];

    if (if_nametoindex(argv[8]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[8]);
        goto end;
    }

    params.iif = argv[8];

    if ( strcmp(argv[5], "mac") == 0) {
        ret = parse_mac(argv[6]);
        if (!ret)
            goto send_add;

        goto end;
    }

    if (inet_pton(AF_INET6, argv[6], &next_hop) != 1) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[6]);
        goto end;
    }

    params.next = argv[6];

send_add:
    ret = send_add_command();

end:
    return ret;
}

/**
 * add_end_ad4(): used by srconf to add a new SID with End.AD4 behavior
 * End.AD4 behavior requires as arguments:
   - IPv4 address of the next_hop
   - Target interfac
   - Source interfac
 * The next hop can be mac address of the VNF
 * used also for End.EAD4 behavior
 */

int add_end_ad4(int argc, char **argv)
{
    int ret = -1;
    struct in_addr next_hop;

    if (argc > 9) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc < 9) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (strcmp(argv[5], "ip") != 0 && strcmp(argv[5], "mac") != 0  ) {
        printf(" invalid token \"%s\"\n", argv[5]);
        goto end;
    }

    if (if_nametoindex(argv[7]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[7]);
        goto end;
    }

    params.oif = argv[7];

    if (if_nametoindex(argv[8]) == 0) {
        printf("Error: interface \"%s\" doesn't exist .\n", argv[8]);
        goto end;
    }

    params.iif = argv[8];

    if ( strcmp(argv[5], "mac") == 0) {
        ret = parse_mac(argv[6]);
        if (!ret)
            goto send_add;

        goto end;
    }

    if (inet_pton(AF_INET, argv[6], &next_hop) != 1) {
        printf("Error: inet prefix is expected rather than \"%s\".\n", argv[6]);
        goto end;
    }

    params.next = argv[6];

send_add:
    ret = send_add_command();

end:
    return ret;
}

/**
 * END.AS4 and End.AS6 behaviors are not supported in the current implementation
*/

int add_end_as6(int argc, char **argv)
{
    printf("The behaviour  %s is not supported yet. \n" , argv[4] );
    return 0 ;
}

int add_end_as4(int argc, char **argv)
{
    printf("The behaviour  %s is not supported yet. \n" , argv[4] );
    return 0;
}

/**
 * do_add(): handles "srconf localsid add SID BEHAVIOR ... " command
 * Based on the behavior a different call is invoked
*/

int do_add(int argc, char **argv)
{
    int ret = -1;
    struct in6_addr sid;

    if (argc < 5 ) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (inet_pton(AF_INET6, argv[3], &sid) != 1) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[3]);
        goto end;
    }

    params.sid  = argv[3];
    params.func = argv[4];

    if (strcmp(argv[4], END) == 0)
        ret =  add_end(argc, argv);

    else if (strcmp(argv[4], END_DX2) == 0)
        ret = add_end_dx2(argc, argv);

    else if ((strcmp(argv[4], END_X) == 0) || (strcmp(argv[4], END_DX6) == 0))
        ret = add_end_x(argc, argv);

    else if (strcmp(argv[4], END_DX4) == 0)
        ret = add_end_dx4(argc, argv);

    else if ((strcmp(argv[4], END_AD4) == 0) || (strcmp(argv[4], END_EAD4) == 0))
        ret = add_end_ad4(argc, argv);

    else if ((strcmp(argv[4], END_AM) == 0) || (strcmp(argv[4], END_AD6) == 0) ||
             (strcmp(argv[4], END_EAD6) == 0) )
        ret = add_end_ad6(argc, argv);

    else if (strcmp(argv[4], END_AS4) == 0)
        ret = add_end_as4(argc, argv);

    else if (strcmp(argv[4], END_AS6) == 0)
        ret = add_end_as6(argc, argv);


    else
        printf("SRv6 behavior \"%s\" is not supported\n" , argv[4] );

end:
    return ret;
}

/**
 * do_del(): handles "srconf localsid del SID " command
*/

int do_del(int argc, char **argv)
{
    int ret = -1;
    struct in6_addr sid;

    if (argc < 4 ) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (argc > 4) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (inet_pton(AF_INET6, argv[3], &sid) != 1) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[3]);
        goto end;
    }

    params.sid  = argv[3];
    ret = send_del_command();

end:
    return ret;
}

/**
 * do_clear(): handles "srconf localsid clear-counters [SID] " command
*/

int do_clear(int argc, char **argv)
{
    int ret = -1;
    struct in6_addr sid;

    if (argc > 4) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc == 3)
        goto send_clear;

    if ( inet_pton(AF_INET6, argv[3], &sid) != 1 ) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[3]);
        goto end;
    }

    params.sid = argv[3];

send_clear:
    ret = send_clear_command();

end:
    return ret ;
}

/**
 * do_show(): handles "srconf localsid show [SID] " command
*/

int do_show(int argc, char **argv)
{
    int ret = -1 ;
    struct in6_addr sid;

    if (argc > 4) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    if (argc == 3)
        goto send_show;

    if (inet_pton(AF_INET6, argv[3], &sid) != 1) {
        printf("Error: inet6 prefix is expected rather than \"%s\".\n", argv[3]);
        goto end;
    }

    params.sid = argv[3];

send_show:
    ret = send_show_command();

end:
    return ret;
}

/**
 * do_flush(): handles "srconf localsid flush " command
*/

int do_flush(int argc, char **argv)
{
    int ret = -1;

    if (argc > 3) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    ret = send_flush_command();

end:
    return ret;
}

/**
 * do_help(): handles "srconf localsid help " command
*/

int do_help(int argc, char **argv)
{
    int ret = -1;

    if (argc > 3) {
        printf("Too many parameters. Please try \"srconf localsid help\" \n");
        goto end;
    }

    ret = usage_localsid();

end:
    return ret ;
}

/**
 * main(): main method
 */

int main(int argc, char **argv)
{
    int ret = -1 ;

    reset_parameters();
    genl_client_init();

    if (argc < 2 ) {
        ret = usage();
        goto end;
    }

    if (strcmp(argv[1], HELP) == 0 ) {
        ret = usage();
        goto end;
    }

    if ((strcmp(argv[1], LOCALSID) != 0) && (strcmp(argv[1], SRDEV) != 0) ) {
        printf("Unrecognized table. Please try \"srconf help\". \n");
        goto end;
    }

    params.table = argv[1];

    if (strcmp(argv[1], LOCALSID) == 0) {

        if (argc == 2) {
            ret = usage_localsid();
            goto end;
        }

        params.command = argv[2];

        if (strcmp(argv[2], HELP) == 0)
            ret = do_help(argc, argv);

        else if (strcmp(argv[2], FLUSH) == 0)
            ret = do_flush(argc, argv);

        else if (strcmp(argv[2], CLEAR) == 0)
            ret = do_clear(argc, argv);

        else if (strcmp(argv[2], SHOW) == 0)
            ret = do_show(argc, argv);

        else if (strcmp(argv[2], DEL) == 0)
            ret = do_del(argc, argv);

        else if (strcmp(argv[2], ADD) == 0)
            ret = do_add(argc, argv);

        else
            printf("Unrecognized command. Please try \"srconf localsid help\".\n");
    }
    else {
        printf("srconf srdev commands are not supported yet. \n");
        usage_srdev();
    }

end:
    return ret;
}
