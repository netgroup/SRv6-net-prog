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

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/rwlock.h>
#include "../include/sr_genl.h"
#include "../include/sr_hook.h"
#include "../include/sr_errno.h"


#define RESPONSE_ER "Error from kernel space."

rwlock_t srgenl_rwlock;

char *err_str[] = {"SREXT answers: OK.",
                   "SREXT answers: [ERROR]: SREXT could not allocate memory.",
                   "SREXT answers: [ERROR]: Localsid is not a valid inet6 address.",
                   "SREXT answers: [ERROR]: Next_hop is not a valid IPv4 address.",
                   "SREXT answers: [ERROR]: Next_hop is not a valid IPv6 address.",
                   "SREXT answers: [ERROR]: Identical localsid already exists.",
                   "SREXT answers: [EROOR]: Localsid not found",
                   "SREXT answers: [ERROR]: Localsid table has no entries.",
                   "SREXT answers: [ERROR]: SRDEV table has no entries.",
                   "SREXT answers: [ERROR]: xmit packet failed.",
                   "SREXT answers: [ERROR]: unknown SRv6 behavior.",
                   "SREXT answers: [ERROR]: Table doesn't exist."
                  };

static struct nla_policy sr_genl_policy[_SR_A_MAX + 1] = {
    [SR_A_UNSPEC]       =   { .type = NLA_STRING },
    [SR_A_TABLE]        =   { .type = NLA_STRING },
    [SR_A_COMMAND]      =   { .type = NLA_STRING },
    [SR_A_SID]          =   { .type = NLA_STRING },
    [SR_A_FUNC]         =   { .type = NLA_STRING },
    [SR_A_NEXT]         =   { .type = NLA_STRING },
    [SR_A_MAC]          =   { .type = NLA_BINARY },
    [SR_A_OIF]          =   { .type = NLA_STRING },
    [SR_A_OIF]          =   { .type = NLA_STRING },
    [SR_A_RESPONSE]     =   { .type = NLA_STRING },
    [SR_A_RESPONSE_LST] =   { .type = NLA_STRING }
};

static struct genl_family sr_gnl_family = {
    //.id = GENL_ID_GENERATE,
    //.id = 0,
    .hdrsize = 0,
    .name = SR_GNL_FAMILY_NAME,
    .version = SR_GNL_FAMILY_VERSION,
    .maxattr = SR_A_MAX,
    .policy = sr_genl_policy,
};

static void set_msg_data(struct genl_msg_data *msg_data, int type,
                         void *data, int len)
{
    msg_data->atype = type;
    msg_data->data  = data;
    msg_data->len   = len + 1;
}

static void *extract_nl_attr(const struct genl_info *info, const int atype)
{
    struct nlattr *na;
    void *data = NULL;
    na = info->attrs[atype];
    if (na) data = nla_data(na);
    return data;
}

static void extract_sr_attrs(const struct genl_info *info, struct sr_param *a)
{
    a->table    = (char *) extract_nl_attr(info, SR_A_TABLE);
    a->command  = (char *) extract_nl_attr(info, SR_A_COMMAND);
    a->sid      = (char *) extract_nl_attr(info, SR_A_SID);
    a->func     = (char *) extract_nl_attr(info, SR_A_FUNC);
    a->next     = (char *) extract_nl_attr(info, SR_A_NEXT);
    a->mac      = (struct sr_mac *) extract_nl_attr(info, SR_A_MAC);
    a->oif      = (char *) extract_nl_attr(info, SR_A_OIF);
    a->iif      = (char *) extract_nl_attr(info, SR_A_IIF);

    a->source   = (char *) extract_nl_attr(info, SR_A_SOURCE);
    a->addr     = (char *) extract_nl_attr(info, SR_A_ADDR);
    a->segs     = (char *) extract_nl_attr(info, SR_A_SEGS);
    a->sid_lst  = (char *) extract_nl_attr(info, SR_A_SID_LST);
    a->left     = (char *) extract_nl_attr(info, SR_A_LEFT);
    a->number   = (char *) extract_nl_attr(info, SR_A_NUMBER);
    a->flags    = (char *) extract_nl_attr(info, SR_A_FLAGS);
}

static void print_mac(struct sr_mac *mac)
{
    printk("Mac:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           (unsigned char) mac->oct[0],
           (unsigned char) mac->oct[1],
           (unsigned char) mac->oct[2],
           (unsigned char) mac->oct[3],
           (unsigned char) mac->oct[4],
           (unsigned char) mac->oct[5]);
}

static void print_attributes(struct sr_param *sr_attr)
{
    if (sr_attr->table  != NULL) printk("Table:		%s\n", sr_attr->table);
    if (sr_attr->sid    != NULL) printk("Sid:		%s\n", sr_attr->sid);
    if (sr_attr->func   != NULL) printk("Func:		%s\n", sr_attr->func);
    if (sr_attr->next   != NULL) printk("NEXT:		%s\n", sr_attr->next);
    if (sr_attr->mac    != NULL) print_mac(sr_attr->mac);
    if (sr_attr->oif    != NULL) printk("OIF:		%s\n", sr_attr->oif);
    if (sr_attr->iif    != NULL) printk("IIF:		%s\n", sr_attr->iif);

    if (sr_attr->source != NULL) printk("Source:	%s\n", sr_attr->source);
    if (sr_attr->addr   != NULL) printk("Addr:		%s\n", sr_attr->addr);
    if (sr_attr->segs   != NULL) printk("Segs:		%s\n", sr_attr->segs);
    if (sr_attr->sid_lst != NULL) printk("Sid-lst:	%s\n", sr_attr->sid_lst);
    if (sr_attr->left   != NULL) printk("Left:		%s\n", sr_attr->left);
    if (sr_attr->number != NULL) printk("Number:	%s\n", sr_attr->number);
    if (sr_attr->flags  != NULL) printk("Flags:		%s\n", sr_attr->flags);
}

static int send_response(struct genl_info *info, unsigned int n_data,
                         struct genl_msg_data *msg_data)
{
    struct sk_buff *skb;
    void *skb_head;
    int i, ret;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (skb == NULL) {
        dmesg_err("send_response - unable to allocate skb");
        return -1;
    }

    skb_head = genlmsg_put(skb, 0, info->snd_seq + 1, &sr_gnl_family, 0, info->genlhdr->cmd);
    if (skb_head == NULL) {
        dmesg_err("send_response - unable to allocate skb_head");
        return -ENOMEM;
    }

    for (i = 0; i < n_data; i++) {
        if ((ret = nla_put(skb, msg_data[i].atype, msg_data[i].len, msg_data[i].data)) < 0) {
            dmesg_err("send_response - unable to put attribute %d for elem %d/%d: %d", msg_data[i].atype, i, n_data, ret);
            return -1;
        }
    }

    genlmsg_end(skb, skb_head);

    if (genlmsg_unicast(genl_info_net(info), skb, info->snd_portid ) != 0) {
        dmesg_err("send_response - unable to send response - info->snd_portid = %u", info->snd_portid);
        return -1;
    }

    return 0;
}

/**
  * add_localsid() - handles adding a localsid to my localsid table
  * called from sr_genl_add()
  */

static int add_localsid(struct sr_param attr, struct genl_info *info)
{
    int ret = 0;
    struct genl_msg_data data[1];
    int behavior = BEHAVIORERR;

    if (attr.sid != NULL && attr.func != NULL) {

        if ( strncmp(attr.func, END, strlen(attr.func)) == 0)
            behavior = END_CODE;

        else if (strncmp(attr.func, END_DX2, strlen(attr.func)) == 0)
            behavior = END_DX2_CODE;

        else if (strncmp(attr.func, END_X, strlen(attr.func)) == 0)
            behavior = END_X_CODE;

        else if (strncmp(attr.func, END_DX4, strlen(attr.func)) == 0)
            behavior = END_DX4_CODE;

        else if (strncmp(attr.func, END_DX6, strlen(attr.func)) == 0)
            behavior = END_DX6_CODE;

        else if (strncmp(attr.func, END_AD4, strlen(attr.func)) == 0)
            behavior = END_AD4_CODE;

        else if (strncmp(attr.func, END_EAD4, strlen(attr.func)) == 0)
            behavior = END_EAD4_CODE;

        else if (strncmp(attr.func, END_AD6, strlen(attr.func)) == 0)
            behavior = END_AD6_CODE;

        else if (strncmp(attr.func, END_EAD6, strlen(attr.func)) == 0)
            behavior = END_EAD6_CODE;

        else if (strncmp(attr.func, END_AM, strlen(attr.func)) == 0)
            behavior = END_AM_CODE;

        else if (strncmp(attr.func, END_AS4, strlen(attr.func)) == 0)
            behavior = END_AS4_CODE;

        else if (strncmp(attr.func, END_AS6, strlen(attr.func)) == 0)
            behavior = END_AS6_CODE;

        switch (behavior) {
        case END_CODE:
            ret = add_end(attr.sid, behavior);
            break;

        case END_DX2_CODE:
            if (attr.oif != NULL)
                ret = add_end_dx2(attr.sid, behavior, attr.oif);
            break;

        case END_X_CODE:
        case END_DX6_CODE:
            if (attr.oif != NULL)
                ret = add_end_x(attr.sid, behavior, attr.next, attr.mac->oct, attr.oif);
            break;

        case END_DX4_CODE:
            if (attr.oif != NULL)
                ret = add_end_dx4(attr.sid, behavior, attr.next, attr.mac->oct, attr.oif);
            break;

        case END_AM_CODE:
        case END_AD6_CODE:
        case END_EAD6_CODE:
            if (attr.iif != NULL && attr.oif != NULL && (attr.mac != NULL || attr.next != NULL))
                ret = add_end_ad6(attr.sid, behavior, attr.next, attr.mac->oct, attr.oif, attr.iif);
            break;

        case END_AD4_CODE:
        case END_EAD4_CODE:
            if (attr.iif != NULL && attr.oif != NULL)
                ret = add_end_ad4(attr.sid, behavior, attr.next, attr.mac->oct, attr.oif, attr.iif);
            break;
        default:
            ret = behavior;
            break;
        }
    }

    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);
    return ret;

}

/**
  * add_srdev() - handles adding an entry to srdev table
  * called from sr_genl_add()
  */

static int add_srdev( struct sr_param attr, struct genl_info *info)
{

    /* TODO - SRDEV ADD COMMANDS */
    return 0 ;
}

/**
 * sr_genl_add() - handles srconf add commands
 */

static int sr_genl_add(struct sk_buff *skb, struct genl_info *info)
{
    int ret = 0;
    struct sr_param attr;
    struct genl_msg_data data[1];
    extract_sr_attrs(info, &attr);
    print_attributes(&attr);

    /* srconf localsid add ... */
    if ((attr.table != NULL) && (strncmp(attr.table, LOCALSID, strlen(attr.table)) == 0))
        return add_localsid(attr, info);

    /* srconf srdev add ... */
    else if ((attr.table != NULL) && (strncmp(attr.table, SRDEV, strlen(attr.table)) == 0))
        return add_srdev(attr, info);

    ret = INVTABLE;
    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);

    return ret;
}

/**
 * del_localsid() - handles deleting a localsid from my localsid table
 * called from sr_genl_del()
 */

static int del_localsid(struct sr_param attr, struct genl_info *info)
{
    int ret = 0;
    struct genl_msg_data data[1];

    ret = del_sid(attr.sid);

    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);
    return ret;
}

/**
 * del_srdev() - handles deleting an interface from srdev table
 * called from sr_genl_del()
 */

static int del_srdev (struct sr_param attr, struct genl_info *info)
{

    /* TODO - SRDEV DEL COMMANDS */
    return 0 ;
}

/**
 * sr_genl_del() - handles srconf del commands
 */

static int sr_genl_del(struct sk_buff *skb, struct genl_info *info)
{
    int ret = 0;
    struct sr_param attr;
    struct genl_msg_data data[1];
    extract_sr_attrs(info, &attr);
    print_attributes(&attr);

    /* srconf localsid del ... */
    if ((attr.table != NULL) && ( strncmp(attr.table, LOCALSID, strlen(attr.table)) == 0))
        return del_localsid (attr, info);

    /* srconf srdev del ... */
    else if ((attr.table != NULL) && ( strncmp(attr.table, SRDEV, strlen(attr.table)) == 0))
        return del_srdev(attr, info);

    ret = INVTABLE;
    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);

    return ret;
}

/**
 * show_localsid - handles printing my localsid table
 * called from sr_genl_show()
 */

static int show_localsid(struct sr_param attr, struct genl_info *info)
{
    int ret = 0 ;
    int len;
    char *message;
    struct genl_msg_data data[1];

    len = 1024 * 4;
    message = (char *) kzalloc(len, GFP_ATOMIC);

    if (attr.sid == NULL)
        ret = show_localsid_all(message + strlen(message), 40);
    else
        ret = show_localsid_sid(message + strlen(message), 40, attr.sid);

    if (ret == 0)
        if (strlen(message) > 4096)  //the maximum lenght of the string
            set_msg_data(data, SR_A_RESPONSE, RESPONSE_ER, strlen(RESPONSE_ER));
        else
            set_msg_data(data, SR_A_RESPONSE_LST, message, strlen(message));
    else
        set_msg_data(data, SR_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));

    ret = send_response(info, 1, data);

    kfree(message);
    return ret;
}

/**
 * show_localsid - handles printing srdev table
 * called from sr_genl_show()
 */

static int show_srdev(struct sr_param attr, struct genl_info * info)
{
    /* TODO - SRDEV SHOW COMMANDS */
    return 0;
}

/**
 * sr_genl_show - handle srconf show commands
 */

static int sr_genl_show(struct sk_buff * skb, struct genl_info * info)
{
    int ret = 0;
    struct sr_param attr;
    struct genl_msg_data data[1];
    extract_sr_attrs(info, &attr);
    print_attributes(&attr);

    /* srconf localsid show ... */
    if ((attr.table != NULL) && ( strncmp(attr.table, LOCALSID, strlen(attr.table)) == 0))
        return show_localsid (attr, info);

    /* srconf srdev show ... */
    else if ((attr.table != NULL) && ( strncmp(attr.table, SRDEV, strlen(attr.table)) == 0))
        return show_srdev(attr, info);

    ret = INVTABLE;
    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);

    return ret;
}

/**
 * flush_localsid - handles flushing my localsid table
 * called from sr_genl_flush()
 */

static int flush_localsid(struct sr_param attr, struct genl_info *info)
{
    int ret = 0 ;
    struct genl_msg_data data[1];
    ret = flush_sid_tbl();

    set_msg_data(data, SR_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));

    ret = send_response(info, 1, data);
    return ret;
}

/**
 * flush_srdev- handles flushing srdev table
 * called from sr_genl_flush()
 */

static int flush_srdev(struct sr_param attr, struct genl_info * info)
{
    /* TODO - SRDEV FLUSH COMMANDS */
    return 0;
}

/**
 * sr_genl_flush - handle srconf flush commands
 */

static int sr_genl_flush(struct sk_buff * skb, struct genl_info * info)
{
    int ret = 0;
    struct sr_param attr;
    struct genl_msg_data data[1];
    extract_sr_attrs(info, &attr);
    print_attributes(&attr);

    /* srconf localsid flush */
    if ((attr.table != NULL) && ( strncmp(attr.table, LOCALSID, strlen(attr.table)) == 0))
        return flush_localsid (attr, info);

    /* srconf srdev flush */
    else if ((attr.table != NULL) && ( strncmp(attr.table, SRDEV, strlen(attr.table)) == 0))
        return flush_srdev(attr, info);

    ret = INVTABLE;
    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);

    return ret;
}

/**
 * clear_localsid - handles clearing counters of  my localsid table entries
 * called from sr_genl_clear()
 */

static int clear_localsid(struct sr_param attr, struct genl_info *info)
{
    int ret = 0 ;
    struct genl_msg_data data[1];

    if (attr.sid == NULL)
        ret = clear_counters_all();
    else
        ret = clear_counters_sid(attr.sid);

    set_msg_data(data, SR_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));

    ret = send_response(info, 1, data);
    return ret;
}

/**
 * clear_srdev - handles flushing srdev table
 * called from sr_genl_clear()
 */

static int clear_srdev(struct sr_param attr, struct genl_info * info)
{
    /* TODO - SRDEV CLEAR COMMANDS */
    return 0;
}

/**
 * sr_genl_clear - handle srconf clear-counters commands
 */

static int sr_genl_clear(struct sk_buff * skb, struct genl_info * info)
{
    int ret = 0;
    struct sr_param attr;
    struct genl_msg_data data[1];
    extract_sr_attrs(info, &attr);
    print_attributes(&attr);

    /* srconf localsid clear-counters .... */
    if ((attr.table != NULL) && ( strncmp(attr.table, LOCALSID, strlen(attr.table)) == 0))
        return clear_localsid (attr, info);

    /* srconf srdev clear-counters ....*/
    else if ((attr.table != NULL) && ( strncmp(attr.table, SRDEV, strlen(attr.table)) == 0))
        return clear_srdev(attr, info);

    ret = INVTABLE;
    set_msg_data(data, SR_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);

    return ret;
}

static int sr_genl_dispatcher(struct sk_buff * skb, struct genl_info * info)
{
    int command;

    command = info->genlhdr->cmd;

    write_lock_bh(&srgenl_rwlock);

    switch (command) {
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
    case SR_C_FLUSH:
        dmesg("NVF_C_FLUSH genl command received");
        sr_genl_flush(skb, info);
        break;
    case SR_C_CLEAR:
        dmesg("NVF_C_CLEAR genl command received");
        sr_genl_clear(skb, info);
        break;
    default:
        break;
    }

    write_unlock_bh(&srgenl_rwlock);

    return 0;
}
/***********************/
static struct genl_ops nvf_genl_ops[] = {
    {
        .cmd = SR_C_ADD,
        .flags = 0,
        .doit = sr_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = SR_C_DEL,
        .flags = 0,
        .doit = sr_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = SR_C_SHOW,
        .flags = 0,
        .doit = sr_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = SR_C_FLUSH,
        .flags = 0,
        .doit = sr_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = SR_C_CLEAR,
        .flags = 0,
        .doit = sr_genl_dispatcher,
        .dumpit = NULL,
    }
};

int sr_genl_register()
{
    int rc;

    sr_gnl_family.module    = THIS_MODULE;
    sr_gnl_family.ops       = nvf_genl_ops;
    sr_gnl_family.n_ops     = ARRAY_SIZE(nvf_genl_ops);
    sr_gnl_family.mcgrps    = NULL;
    sr_gnl_family.n_mcgrps  = 0;

    rc = genl_register_family(&sr_gnl_family);

    if (rc != 0) {
        printk(KERN_INFO "Unable to register %s genetlink family", sr_gnl_family.name);
        return -1;
    }
    printk(KERN_INFO "%s genetlink family successfully registered", sr_gnl_family.name);

    return 0;
}

int sr_genl_unregister()
{
    int rc;
    rc = genl_unregister_family(&sr_gnl_family);
    if (rc != 0) {
        printk(KERN_INFO "Unable to unregister %s genetlink family", sr_gnl_family.name);
        return -1;
    }
    printk(KERN_INFO "%s genetlink family successfully unregistered", sr_gnl_family.name);
    return 0;
}
