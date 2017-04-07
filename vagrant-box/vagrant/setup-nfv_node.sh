#!/bin/bash

#enble IPv6 forwarding in NFV node 
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

#create namespace for VNF
ip netns add vnf1

#create the link between NFV node and VNF
ip link add veth0-vnf1 type veth peer name veth0-nfv


#assign virtual interface to VNF
ip link set veth0-vnf1 netns vnf1


# configuration of NFV node interfaces

ifconfig lo up

ifconfig eth1 up
ip -6 addr add A::1/64 dev eth1

ifconfig eth2 up
ip -6 addr add C::1/64 dev eth2

ip -6 addr add B::1/64 dev veth0-nvf-node
ifconfig veth0-nvf-node hw ether 00:00:00:00:00:11
ifconfig veth0-nvf-node up


#enble IPv6 forwarding in VNF1 
ip netns exec vnf1 sysctl -w net.ipv6.conf.all.forwarding=1


# configuration of VNF1 interfaces
ip netns exec vnf1 ip -6 addr add B::2/64 dev veth0-vnf1
ip netns exec vnf1 ifconfig veth0-vnf1 hw ether 00:00:00:00:00:22
ip netns exec vnf1 ifconfig veth0-vnf1 up
 
# static routing configuration in VNF1
ip netns exec vnf1 ip -6 route add A::/64 via B::1
ip netns exec vnf1 ip -6 route add C::/64 via B::1


# Insert the SR-NFV_connector kernel module 
cd /vagrant/hook/
touch *
make 
insmod hook.ko 

exit
