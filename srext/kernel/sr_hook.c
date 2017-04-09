#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/rwlock.h>
#include <net/protocol.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>
#include "../include/seg6.h"
#include "../include/sr_genl.h"
#include "../include/sr_helper.h"
#include "../include/sr_hook.h"

#define AUTHOR "SREXT"
#define DESC   "SREXT"

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL");

#define DEBUG
#ifdef DEBUG
	#define debug_printk(fmt, args) printk(KERN_DEBUG fmt,args)
	//print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);
#else
	#define debug_printk(fmt, args) /* not debugging: nothing */
#endif

//#define ALL_PACKET_DETAILS
//#define PER_PACKET_INFO

#define NT_MAXSIZE 4
#define ST_MAXSIZE 4

#define LAZY_NO_LOCK

/* north table entry (including the key) */
struct nt_entry {
	int is_set;
	struct in6_addr vnf_ip;
	struct net_device * if_struct;
	int n_operation;
	unsigned char d_mac[6];
	#ifdef LAZY_NO_LOCK
	struct ipv6_sr_hdr *sr_header_auto ;
	#endif

};

/* south table entry (including the key) */
struct st_entry {
	int is_set;
	struct net_device* if_struct;  /*south table key ... it was called vnf*/
	int s_operation;
	struct in6_addr south_sid;
};

static int nt_size = 0;
static int st_size = 0;

static int nt_current = 0; /*a pointer to cycle trhough the north table */
static int st_current = 0; /*a pointer to cycle trhough the south table */

static struct nt_entry north_table [NT_MAXSIZE];
static struct st_entry south_table [NT_MAXSIZE];

static struct nf_hook_ops sr_ops_pre;
//static struct net_device* if_struct;  /*south table key ... it was called vnf*/
//static int s_operation;               /*south table operation*/
//static struct in6_addr south_sid;     /*south table sid for auto*/

static struct ipv6hdr outer_iph;
//static struct ipv6_sr_hdr *sr_header_auto;
//int learn_sr = 1;
//static struct in6_addr vnf_ip;  /*north table key*/
//static int n_operation;         /*north table operation*/

//struct in6_addr *vnf_sid = NULL; //FOR QUICK AND DIRY NULL CHECK
unsigned char d_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22};

rwlock_t sr_rwlock;


static void print_mac(char * mac){
	printk("%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) mac[0],
			(unsigned char) mac[1],
			(unsigned char) mac[2],
			(unsigned char) mac[3],
			(unsigned char) mac[4],
			(unsigned char) mac[5]);
};


/*
*******************************************************************************
* OPERATIONS ON THE TABLES (MATCH, ADD)
*******************************************************************************
*/

//TODO improve the matching efficiency with housekeeping: keep only the first nt_size entries
int check_match_north (struct in6_addr * sid_addr) {
	/* we already got the lock */
	/* check if there is a matching entry*/
	/*returns -1 if there is no match*/
	int ret = -1;
	int i = 0;
	int ii = 0;
	for (ii = 0; ii < NT_MAXSIZE; ii++) {
		i = (nt_current + ii ) % NT_MAXSIZE;
		if (north_table[i].is_set!=0 && ipv6_addr_cmp(&north_table[i].vnf_ip, sid_addr) == 0 ) {
			ret = i;
			break;
		}
	}	
	return ret;
};

int check_empty_north (struct in6_addr * sid_addr) {
	/* we already got the lock */
	/* check if there is an empty slot */
	int ret = -1;
	int i = 0;
	int ii = 0;
	for (ii = 0; ii < NT_MAXSIZE; ii++) {
		i = (nt_current + 1 + ii ) % NT_MAXSIZE;
		if (north_table[i].is_set == 0) {
			ret = i;
			break;
		}
	}
	return ret;
};

int slot_to_add_north (struct in6_addr * sid_addr) {
	/* we already got the lock */
	/* returns -1 if it is not possible to add (or modify) the sid*/
	/* returns the slot number (>=0) if there is a match or an empty slot */
	int ret = -1;

	/* check if there is a matching entry*/
	ret = check_match_north (sid_addr);

	if (ret == -1 ) {
		/* check if there is an empty slot */
		ret = check_empty_north (sid_addr);
	}
	return ret;
};

//TODO improve the matching efficiency with housekeeping: keep only the first nt_size entries
int check_match_south (struct net_device * if_struct) {
	/* we already got the lock */
	/* check if there is a matching entry*/
	/*returns -1 if there is no match*/
	int ret = -1;
	int i = 0;
	int ii = 0;
	for (ii = 0; ii < ST_MAXSIZE; ii++) {
		i = (st_current + ii ) % ST_MAXSIZE;
		//the match is currently based on the interface index: is it correct and safe ???
		if (south_table[i].is_set!=0 && south_table[i].if_struct->ifindex == if_struct->ifindex ) {
			ret = i;
			break;
		}
	}	
	return ret;
};

int check_empty_south (struct net_device * if_struct) {
	/* we already got the lock */
	/* check if there is an empty slot */
	int ret = -1;
	int i = 0;
	int ii = 0;
	for (ii = 0; ii < ST_MAXSIZE; ii++) {
		i = (st_current + 1 + ii ) % ST_MAXSIZE;
		if (south_table[i].is_set == 0) {
			ret = i;
			break;
		}
	}
	return ret;
};

int slot_to_add_south (struct net_device * if_struct) {
	/* we already got the lock */
	/* returns -1 if it is not possible to add (or modify) the sid*/
	/* returns the slot number (>=0) if there is a match or an empty slot */
	int ret = -1;

	/* check if there is a matching entry*/
	ret = check_match_south (if_struct);

	if (ret == -1 ) {
		/* check if there is an empty slot */
		ret = check_empty_south (if_struct);
	}
	return ret;
};

/*
*******************************************************************************
* PACKET PROCESSING FUNCTIONS
*******************************************************************************
*/


/* rencap function */
int rencap(struct sk_buff* skb, struct ipv6_sr_hdr* osrh) {
	struct ipv6hdr *hdr;
	struct ipv6_sr_hdr *isrh;
	int hdrlen, tot_len, err;
	hdrlen = (osrh->hdrlen + 1) << 3;
	tot_len = hdrlen + sizeof(*hdr);

	if (unlikely((err = pskb_expand_head(skb, tot_len, 0, GFP_ATOMIC)))) {
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n","SREXT module cannot expand head");
		#endif
		return err;
	}

	skb_push(skb, tot_len);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	hdr = ipv6_hdr(skb);
	memcpy(hdr, &outer_iph, sizeof(struct ipv6hdr));
	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, osrh, hdrlen);
	#ifdef PER_PACKET_INFO
	debug_printk("%s \n","Packet coming from the VNF is rencapsulated correctly");
	#endif
	return 0;
}



/* Remove SR encapsulation in case of encap mode */
struct sk_buff* trim_encap(struct sk_buff* skb, struct ipv6_sr_hdr* sr_h)
{
	int trim_size;
 	trim_size = sizeof(struct ipv6hdr) + ((sr_h->hdrlen * 8) + 8);
	pskb_pull(skb, trim_size);
	skb_postpull_rcsum(skb, skb_transport_header(skb), trim_size);
	#ifdef PER_PACKET_INFO
	debug_printk("%s \n","Packet is decapsulated correctly before being sent to the VNF"); 
	#endif
	return skb;
}


/* send_to_VNF function */
int send_to_vnf(struct sk_buff* skb, struct net_device* interf_struct, unsigned char *dest_mac) {

	//read_lock_bh(&sr_rwlock); //no need to lock as we have copied interf_struct and dest_mac
	dev_hard_header(skb, skb->dev, ETH_P_IPV6, dest_mac, NULL, skb->len);
	//read_unlock_bh(&sr_rwlock);

	skb->dev = interf_struct;
	skb->pkt_type = PACKET_OUTGOING;

	if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS) {
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "dev_queue_xmit error");
		#endif
		return 1;
	} else {
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "dev_queue_xmit OK");
		#endif
		return 0;
	}

}


/* Main packet processing fucntion : Pre-Routing function */
unsigned int sr_pre_routing(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {

	struct ipv6hdr* iph;
	struct ipv6_sr_hdr* srh;
	struct ipv6_rt_hdr* routing_header;
    int srhlen ;
	struct in6_addr* next_hop = NULL;
	int ret = -1;
	struct net_device * local_if_struct;
	unsigned char local_d_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct ipv6_sr_hdr * local_sr_header_auto = NULL;
	int local_operation = 0;


//	printk ("size of net_device struct %zu\n", sizeof(*local_if_struct));
//  net_device struct size = 2624

	// should't we check if it is an IPv6 packet before casting?
	// or we registered only for IPv6 packets???
	iph = (struct ipv6hdr*) skb_network_header(skb);

	/* TODO filter neighbor discovery and other undesired traffic  */

	#ifdef ALL_PACKET_DETAILS
	debug_printk("%s \n", "IPv6 header fields of packet captured by SR-ext module");
	debug_printk("ifname      = %s \n", skb->dev->name);
	debug_printk("payload_len = %u \n", ntohs(iph->payload_len));
	debug_printk("hop limit   = %u \n", iph->hop_limit);
	debug_printk("saddr       = %pI6c \n", iph->saddr.s6_addr);
	debug_printk("daddr       = %pI6c \n", iph->daddr.s6_addr);
	#endif

	if (iph->nexthdr == NEXTHDR_ICMP) {
		struct icmp6hdr* icmpv6h;
		icmpv6h = (struct icmp6hdr*) icmp6_hdr(skb);
		if (!( (icmpv6h->icmp6_type == ICMPV6_ECHO_REQUEST) || (icmpv6h->icmp6_type == ICMPV6_ECHO_REPLY) ) )
			goto exit_accept;  
	} 
	/* ingress section  */

//now it first checks for SIDs in the north table 	 
//SS: I think we should first check for interfaces in the south table

//ingress:
	if (iph->nexthdr != NEXTHDR_ROUTING)
		goto egress;
	

	routing_header = (struct ipv6_rt_hdr*) skb_transport_header(skb);
	if (routing_header->type != 4 ) { 
		/*not a SR packet TODO : should we remove this check ???? */
		goto exit_accept;
	}


	read_lock_bh(&sr_rwlock);
	ret = check_match_north (&iph->daddr);
	if (ret<0) {
		/* we did not find a matching sid */
		read_unlock_bh(&sr_rwlock);
		goto exit_accept;

	}


	local_if_struct = north_table[ret].if_struct;
	//memcpy(&local_if_struct, &north_table[ret].if_struct, sizeof(local_if_struct));
	memcpy(&local_d_mac, &north_table[ret].d_mac, sizeof(local_d_mac));
	local_sr_header_auto = north_table[ret].sr_header_auto;


	read_unlock_bh(&sr_rwlock);

	srh = (struct ipv6_sr_hdr*) skb_transport_header(skb);
	
	#ifdef ALL_PACKET_DETAILS
	debug_printk("%s \n", "SRH of IPv6 packet captured by SR-ext module"); 
	debug_printk("nexthdr       =  %u \n", srh->nexthdr);
	debug_printk("hdrlen        =  %u \n", srh->hdrlen);
	debug_printk("type          =  %u \n", srh->type);
	debug_printk("segments_left =  %u \n", srh->segments_left);
	debug_printk("first_segment =  %u \n", srh->first_segment);
	#endif

	srhlen = (srh->hdrlen + 1) << 3;
	
	if (srh->nexthdr != NEXTHDR_IPV6){
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "Next header is not IPv6: no SR encap mode)");
		#endif
		goto exit_accept;
	}

	srh->segments_left--;
	next_hop = srh->segments + srh->segments_left;
	iph->daddr = *next_hop;
	iph->hop_limit -=2;
	memcpy(&outer_iph, iph, sizeof(outer_iph));

//autolearning : now it is done per SID !!
//	write_lock(&sr_rwlock);
	/* TODO fix me: lazy way to avoid write lock */
	#ifdef LAZY_NO_LOCK
	if ( local_sr_header_auto != NULL)
		kfree(local_sr_header_auto);
	local_sr_header_auto = kmalloc(srhlen, GFP_ATOMIC);
	memcpy(local_sr_header_auto, srh, srhlen);
	#endif
//	learn_sr = 0;
//	write_unlock(&sr_rwlock);
//end autolearning 



	trim_encap(skb, srh);

//	if (send_to_vnf(skb, if_struct, d_mac) == 0) 
	if (send_to_vnf(skb, local_if_struct, local_d_mac) == 0) {
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "OK : packet sent to the VNF ");
		#endif
	} else {
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "FAILED sending packet the VNF");
		#endif		
	}
		
	goto exit_stolen;


egress:
	read_lock_bh(&sr_rwlock);
	if (st_size == 0){
		read_unlock_bh(&sr_rwlock);
		goto exit_accept;
	}
//  if (skb->dev->ifindex != if_struct->ifindex /*|| memcmp(iph->flow_lbl,outer_iph.flow_lbl, 3) != 0*/ ){
	ret = check_match_south (skb->dev);
	if (ret<0) {
		/* we did not find a matching interface */
		read_unlock_bh(&sr_rwlock);
		#ifdef PER_PACKET_INFO
		debug_printk("%s \n", "Packet NOT from a registered interface ");
		#endif
		goto exit_accept;
	}
	local_operation=south_table[ret].s_operation;
	read_unlock_bh(&sr_rwlock);
	#ifdef PER_PACKET_INFO
	debug_printk("%s \n", "Packet coming from a registered interface");
	#endif

	if ( (local_operation & CODE_AUTO) != 0 ) {
		if (local_sr_header_auto != NULL)
			rencap(skb, local_sr_header_auto);
	}

exit_accept:
	return NF_ACCEPT;
exit_stolen:
	return NF_STOLEN;

}

/*
*******************************************************************************
* CLI OPERATIONS CALLED BY SR_GENL.C 
*******************************************************************************
*/

int bind_sid_north(const char *sid, const int set_operation, const char *vnf_eth, const unsigned char *mac){
	int ret = -1; /* returns <0 if the operation did not succeed, otherwise the slot added is returned*/
	struct in6_addr sid_addr;
    struct net_device * local_if_struct = NULL;

	if (in6_pton(sid, strlen(sid), sid_addr.s6_addr, -1, NULL) != 1) {
		ret = -2; /*-2: error in the SID address */
		goto end;
	} 
	//may be for other operations the vnf_eth is not used, so we check for ! NULL
	if (vnf_eth != NULL) {
		local_if_struct = dev_get_by_name(&init_net, vnf_eth);
		if (local_if_struct == NULL) {
			ret = -3; /*-3: error in the interface name */
			goto end;
		}
	}

	write_lock_bh(&sr_rwlock);

	ret = slot_to_add_north(&sid_addr); 
	debug_printk("slot_to_add_north returns: %d\n", ret);
	if (ret >= 0) {
		nt_current = ret;
		if (north_table[ret].is_set == 0) { /*we are adding a new entry*/
			nt_size++;
		}
		north_table[ret].is_set = 1;
		memcpy(&north_table[ret].vnf_ip,&sid_addr,sizeof(sid_addr));
		north_table[ret].n_operation = set_operation;
		if (local_if_struct!=NULL) {
			north_table[ret].if_struct = local_if_struct;
		}

		if (mac!=NULL) {
			memcpy(&north_table[ret].d_mac,mac,6);
			#ifdef DEBUG
				printk("New mac:\t");
				print_mac(&north_table[ret].d_mac[0]);
			#endif
		}

		debug_printk("north table size : %d\n",nt_size);
	}

	//old operations to be deleted
//			memcpy(&vnf_ip,&sid_addr,sizeof(sid_addr));
//			//vnf_sid = &vnf_ip;
//
//			n_operation = set_operation;
//
//			#ifdef DEBUG
//			//printk("old mac: %x %x %x %x %x %x \n",d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5] );
//			printk("Old mac:\t");
//			print_mac(&d_mac[0]);
//			#endif
//			if (mac!=NULL)
//				memcpy(&d_mac,mac,6);
//			#ifdef DEBUG
//			//printk("new mac: %x %x %x %x %x %x \n",d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5] );
//			printk("New mac:\t");
//			print_mac(&d_mac[0]);
//			#endif
	//end of old operations to be deleted
	
	write_unlock_bh(&sr_rwlock);

end:
	debug_printk("bind north returns: %d\n", ret);	

	return ret;
}
EXPORT_SYMBOL(bind_sid_north);

int bind_nic_south(const char *vnf_eth, const int set_operation, const char *sid){
	int ret = -1;
	struct in6_addr sid_addr;
    struct net_device * local_if_struct = NULL;

	local_if_struct = dev_get_by_name(&init_net, vnf_eth);
	
	if (local_if_struct == NULL) {
		ret = -3; /*-3: error in the interface name */
		goto end;
	} 

	//may be for other operations the sid is not used, so we check for ! NULL
	if (sid != NULL) {
		if (in6_pton(sid, strlen(sid), sid_addr.s6_addr, -1, NULL) != 1) {
			ret = -2; /*-2: error in the SID address */
			goto end;
			//if_struct = NULL;
		} 
	}


	//s_operation = set_operation;
	write_lock_bh(&sr_rwlock);

	ret = slot_to_add_south(local_if_struct); 
	debug_printk("slot_to_add_south returns: %d\n", ret);
	if (ret >= 0) {
		st_current = ret;
		if (south_table[ret].is_set == 0) { /*we are adding a new entry*/
			st_size++;
		}
		south_table[ret].is_set = 1;
		south_table[ret].if_struct = local_if_struct;
		south_table[ret].s_operation = set_operation;

		//may be for other operations the sid is not used, so we check for ! NULL
		if (sid != NULL) {
			memcpy(&south_table[ret].south_sid,&sid_addr,sizeof(sid_addr));
		}
	}
	
	write_unlock_bh(&sr_rwlock);

end:
	debug_printk("bind south returns: %d\n", ret);	

	return ret;
}
EXPORT_SYMBOL(bind_nic_south);

int unbind_sid_north(const char *sid){
	int ret = -1; /* returns -1 if the operation was not successfull, otherwise the slot removed is returned*/
	struct in6_addr sid_addr;

	if (in6_pton(sid, strlen(sid), sid_addr.s6_addr, -1, NULL) != 1) {
		ret = -2; /*-2: error in the address */
		goto end;
	} 

	write_lock_bh(&sr_rwlock);

	ret = check_match_north (&sid_addr);
	if (ret >= 0) {
		north_table[ret].is_set = 0;
		#ifdef LAZY_NO_LOCK
		if (north_table[ret].sr_header_auto != NULL) {
			kfree(north_table[ret].sr_header_auto);
			north_table[ret].sr_header_auto = NULL;
		}
		#endif
		nt_size --;
		// I'm NOT cleaning all data
		debug_printk("north table size : %d\n",nt_size);
	}

//		if (in6_pton(sid, strlen(sid), to_del.s6_addr, -1, NULL) == 1){	
//			if (ipv6_addr_cmp(&to_del, &vnf_ip) == 0){
//				/* TODO quick and dirty, implement the real one  */
//				vnf_sid = NULL;
//				ret = 0;
//			}
//		}
	
	write_unlock_bh(&sr_rwlock);

end:
	debug_printk("unbind north returns: %d\n", ret);	

	return ret;
}
EXPORT_SYMBOL(unbind_sid_north);

int unbind_nic_south(const char *vnf_eth){
	int ret = -1;
	struct net_device* to_del;
	
	
	to_del = dev_get_by_name(&init_net, vnf_eth);
	//TODO ???? The returned handle has the usage count incremented and the caller
	//must use dev_put() to release it when it is no longer needed.

	if (to_del == NULL) {
		ret = -3; /*-3: error in the interface name */
		goto end;
	} 

	write_lock_bh(&sr_rwlock);

	ret = check_match_south (to_del);
	if (ret >= 0) {
		south_table[ret].is_set = 0;
		st_size --;
		// I'm NOT cleaning the data
		debug_printk("south table size : %d\n",st_size);
	}
	write_unlock_bh(&sr_rwlock);

end:
	debug_printk("unbind south returns: %d\n", ret);	

	return ret;
}
EXPORT_SYMBOL(unbind_nic_south);

int unbind_sid_vnf(const char* sid, const char *vnf_eth){

	return -1;
}

int show_north (char *dst, size_t size) {
	//TODO IMPLEMENT CHECK ON SIZE
	int char_used = 0;
	int i = 0;
	int ii = 0;
	char * chr_p;

	read_lock_bh(&sr_rwlock);

	if (nt_size == 0){
		read_unlock_bh(&sr_rwlock);
		return 1;
	}

	for (ii = 0; ii < NT_MAXSIZE; ii++) {
		i = (nt_current + 1 + ii ) % NT_MAXSIZE;
		if ( north_table[i].is_set != 0) {
			debug_printk("SID: %pI6c\n",&north_table[i].vnf_ip.s6_addr);
			inet_ntop6((u_char *)&north_table[i].vnf_ip.s6_addr, dst, size);
			char_used = strlen (dst);
			dst += char_used;
			dst += SPRINTF((dst, "\t%d", north_table[i].n_operation));
			chr_p = &north_table[i].d_mac[0];
			dst += SPRINTF((dst, "\t%02x:%02x:%02x:%02x:%02x:%02x\n",chr_p[0],chr_p[1],chr_p[2],chr_p[3],chr_p[4],chr_p[5] ));

		}
	}

	// debug_printk("SID: %pI6c\n",&vnf_ip.s6_addr);
	// inet_ntop6((u_char *)&vnf_ip.s6_addr, dst, size);
	// char_used = strlen (dst);
	// debug_printk("char_used: %d\n",char_used);
	// dst += char_used;

	// dst += SPRINTF((dst, "\t%d", n_operation));
	// dst += SPRINTF((dst, "\t%02x:%02x:%02x:%02x:%02x:%02x\n",d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5] ));


	read_unlock_bh(&sr_rwlock);


	return 1;
}

int show_south (char *dst, size_t size) {
	//TODO IMPLEMENT CHECK ON SIZE
	//int char_used = 0;
	int i = 0;
	int ii = 0;

	read_lock_bh(&sr_rwlock);

	if (st_size == 0){
		read_unlock_bh(&sr_rwlock);
		return 1;
	}

	//debug_printk("SID: %pI6c\n",&vnf_ip.s6_addr);
	//inet_ntop6((u_char *)&vnf_ip.s6_addr, dst, size);
	//char_used = strlen (dst);
	//debug_printk("char_used: %d\n",char_used);
	//dst += char_used;

	for (ii = 0; ii < ST_MAXSIZE; ii++) {
		i = (st_current + 1 + ii ) % ST_MAXSIZE;
		if ( south_table[i].is_set != 0) {
			dst += SPRINTF((dst, south_table[i].if_struct->name ));
			dst += SPRINTF((dst, "\t%d\t", south_table[i].s_operation));
			inet_ntop6((u_char *)&south_table[i].south_sid.s6_addr, dst, size);
			dst += strlen (dst);
			dst += SPRINTF((dst, "\n"));
		}
	}


	read_unlock_bh(&sr_rwlock);


	return 1;
}



/*
*******************************************************************************
* INITIALIZATION AND EXIT FUNCTIONS
*******************************************************************************
*/


/* Initialization function */
int sr_vnf_init(void) {
	int ret = 0;

	printk(KERN_ALERT "Loading module %s.......\n", DESC);

	memset(&north_table , 0, sizeof(north_table));
	memset(&south_table , 0, sizeof(south_table));
	
	/*printk("mac: %x\n", north_table[0].d_mac[0]);*/


	/* Integration with netlink module */
	ret = sr_genl_register();
	if (ret < 0)
		return ret;
	rwlock_init(&sr_rwlock);
	/* Register the filtering function */
	sr_ops_pre.hook = sr_pre_routing;
	sr_ops_pre.pf = PF_INET6;
	sr_ops_pre.hooknum = NF_INET_PRE_ROUTING;
	sr_ops_pre.priority = NF_IP_PRI_LAST;

	/* register NF_IP_PRE_ROUTING hook */
	ret = nf_register_hook(&sr_ops_pre);

	if (ret < 0) {
		printk(KERN_INFO "Sorry, registering %s failed with %d \n", DESC , ret);
        return ret;
	}
	printk(KERN_INFO "SREXT module registered (%d)!\n", ret);
	 return 0;
}

#ifdef LAZY_NO_LOCK
void kfree_all_sr_header_auto (void) {
	int i = 0;
	int ii = 0;
	write_lock_bh(&sr_rwlock);
	for (ii = 0; ii < ST_MAXSIZE; ii++) {
		i = (st_current + ii ) % ST_MAXSIZE;
		if (north_table[i].is_set!=0 && north_table[i].sr_header_auto != NULL) {
			kfree(north_table[i].sr_header_auto);
			debug_printk("%s \n","kfreed sr_header_auto");
		}
	}	
	write_unlock_bh(&sr_rwlock);
}
#endif

/* Exit function */
void sr_vnf_exit(void) {
	printk(KERN_ALERT "Unloading module %s......\n", DESC);

	/* Integration with netlink module */
	sr_genl_unregister();

	/* Unregister the filtering function*/
	nf_unregister_hook(&sr_ops_pre);
	
	#ifdef LAZY_NO_LOCK
	kfree_all_sr_header_auto();
//	if (sr_header_auto != NULL)
//		kfree(sr_header_auto);
	#endif

	memset(&sr_ops_pre, 0, sizeof(struct nf_hook_ops));
	printk(KERN_INFO "SREXT module released.\n");
}



module_init (sr_vnf_init);
module_exit (sr_vnf_exit);
