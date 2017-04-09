#!/bin/bash

# original script to setup the egress node

#configuration of egress node interfaces 
ifconfig lo up
ifconfig eth1 up
ip -6 addr add CCCC::2/64 dev eth1

# segment routing encapsulation of egress node
#ip -6 route add AAAA::2/128 via CCCC::1 encap seg6 mode encap segs BBBB::2,AAAA::2

# static routing configuration of ingress node
ip -6 route add BBBB::/64 via CCCC::1
ip -6 route add AAAA::/64 via CCCC::1
exit
