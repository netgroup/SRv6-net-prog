#!/bin/bash

# the module is not inserted
# please do make and sudo make install

NS_NAME=$2
IP_NODE_NFV1=$3
MAC_NODE_NFV1=$4
IP_NFV1_NODE=$5
MAC_NFV1_NODE=$6

# name of device on node, example: node-vnf1-ve0
DEV_NODE_NAME=node-$NS_NAME-ve0

# name of device on vnf, example: vnf1-ve0
DEV_VNF_NAME=$NS_NAME-ve0

echo "DEV_NODE_NAME: $DEV_NODE_NAME" 
echo "DEV_VNF_NAME: $DEV_VNF_NAME" 

if [ $# -gt 0 ] && [ $1 = "clean" ]
then
   echo "CLEANING $NS_NAME"
   ip link del $DEV_NODE_NAME
   ip netns del $NS_NAME
   exit
fi

if [ $# -gt 0 ] && [ $1 = "add" ]
then

echo "ADDING: $NS_NAME" 

#create namespace for VNF
ip netns add $NS_NAME

#create the link between NFV node and VNF
#ip link add veth0-vnf1 type veth peer name veth0-nfv-node
ip link add $DEV_VNF_NAME type veth peer name $DEV_NODE_NAME


#assign virtual interface to VNF
#ip link set veth0-vnf1 netns vnf1
ip link set $DEV_VNF_NAME netns $NS_NAME

#enable IPv6 forwarding in VNF1 
ip netns exec $NS_NAME sysctl -w net.ipv6.conf.all.forwarding=1


#configure the node part of the link
echo "configure the node part of the link"
ip -6 addr add $IP_NODE_NFV1 dev $DEV_NODE_NAME
ifconfig $DEV_NODE_NAME hw ether $MAC_NODE_NFV1
ifconfig $DEV_NODE_NAME up


# configuration of VNF1 interfaces
echo "configuration of VNF1 interfaces"
ip netns exec $NS_NAME ip -6 addr add $IP_NFV1_NODE dev $DEV_VNF_NAME
ip netns exec $NS_NAME ifconfig $DEV_VNF_NAME hw ether $MAC_NFV1_NODE
ip netns exec $NS_NAME ifconfig $DEV_VNF_NAME up
 
# static routing configuration in VNF1
echo "static routing configuration in $NS_NAME (TO BE FIXED!!!)"
ip netns exec $NS_NAME ip -6 route add AAAA::/64 via BBBB::1
ip netns exec $NS_NAME ip -6 route add CCCC::/64 via BBBB::1

fi



exit
