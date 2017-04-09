#!/bin/bash

# this script setups the nfv-node
# it needs to be called from the srext folder as follows:
# sudo scripts/nfv-node-setup.sh
# sudo scripts/nfv-node-setup.sh clean

# it uses the script scripts/add-vnf.sh to add the VNF

# NB srext the module is not compiled nor inserted 


IP_NODE_LEFT=AAAA::1/64
IP_NODE_RIGHT=CCCC::1/64

IP_NODE_NFV1=BBBB::1/64
MAC_NODE_NFV1=00:00:00:00:00:11
IP_NFV1_NODE=BBBB::2/64
MAC_NFV1_NODE=00:00:00:00:00:22

if [ $# -gt 0 ] && [ $1 = "clean" ]
then
   echo "CLEANING"
   ip -6 addr del $IP_NODE_LEFT dev eth1
   ip -6 addr del $IP_NODE_RIGHT dev eth2
   /bin/bash scripts/add-vnf.sh clean vnf1 
#   ip link del node-vnf1-ve0
#   ip netns del vnf1
   exit
fi


#enble IPv6 forwarding in NFV node 
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# configuration of NFV node interfaces

ifconfig lo up

ifconfig eth1 up
echo "adding ip left"
ip -6 addr add $IP_NODE_LEFT dev eth1

ifconfig eth2 up
echo "adding ip right"
ip -6 addr add $IP_NODE_RIGHT dev eth2

/bin/bash scripts/add-vnf.sh add vnf1 $IP_NODE_NFV1 $MAC_NODE_NFV1 $IP_NFV1_NODE $MAC_NFV1_NODE

exit

#create namespace for VNF
ip netns add vnf1

#create the link between NFV node and VNF
#ip link add veth0-vnf1 type veth peer name veth0-nfv-node
ip link add vnf1-ve0 type veth peer name node-vnf1-ve0


#assign virtual interface to VNF
#ip link set veth0-vnf1 netns vnf1
ip link set vnf1-ve0 netns vnf1

#enable IPv6 forwarding in VNF1 
ip netns exec vnf1 sysctl -w net.ipv6.conf.all.forwarding=1


#configure the node part of the link
echo "configure the node part of the link"
ip -6 addr add $IP_NODE_NFV1 dev node-vnf1-ve0
ifconfig node-vnf1-ve0 hw ether $MAC_NODE_NFV1
ifconfig node-vnf1-ve0 up


# configuration of VNF1 interfaces
echo "configuration of VNF1 interfaces"
ip netns exec vnf1 ip -6 addr add $IP_NFV1_NODE dev vnf1-ve0
ip netns exec vnf1 ifconfig vnf1-ve0 hw ether $MAC_NFV1_NODE
ip netns exec vnf1 ifconfig vnf1-ve0 up
 
# static routing configuration in VNF1
echo "static routing configuration in vnf2"
ip netns exec vnf1 ip -6 route add AAAA::/64 via BBBB::1
ip netns exec vnf1 ip -6 route add CCCC::/64 via BBBB::1

exit
