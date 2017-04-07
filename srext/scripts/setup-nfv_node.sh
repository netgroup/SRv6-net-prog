#!/bin/bash

#enble IPv6 forwarding in NFV node 
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

#create namespace for VNF
ip netns add vnf1

#create the link between NFV node and VNF
ip link add veth0-vnf1 type veth peer name veth0-nfv-node


#assign virtual interface to VNF
ip link set veth0-vnf1 netns vnf1


# configuration of NFV node interfaces

ifconfig lo up

ifconfig eth1 up
ip -6 addr add AAAA::1/64 dev eth1

ifconfig eth2 up
ip -6 addr add CCCC::1/64 dev eth2

ip -6 addr add BBBB::1/64 dev veth0-nfv-node
ifconfig veth0-nfv-node hw ether 00:00:00:00:00:11
ifconfig veth0-nfv-node up


#enble IPv6 forwarding in VNF1 
ip netns exec vnf1 sysctl -w net.ipv6.conf.all.forwarding=1


# configuration of VNF1 interfaces
ip netns exec vnf1 ip -6 addr add BBBB::2/64 dev veth0-vnf1
ip netns exec vnf1 ifconfig veth0-vnf1 hw ether 00:00:00:00:00:22
ip netns exec vnf1 ifconfig veth0-vnf1 up
 
# static routing configuration in VNF1
ip netns exec vnf1 ip -6 route add AAAA::/64 via BBBB::1
ip netns exec vnf1 ip -6 route add CCCC::/64 via BBBB::1


# Insert the SR-NFV_connector kernel module 
cd /vagrant/hook/
touch *
make 
insmod hook.ko 

exit
