#!/bin/bash

#configuration of egress node interfaces 
ifconfig lo up
ifconfig eth1 up
ip -6 addr add C::2/64 dev eth1

# segment routing encapsulation of egress node
#ip -6 route add A::2/128 via C::1 encap seg6 mode encap segs B::2,A::2

# static routing configuration of ingress node
ip -6 route add B::/64 via C::1
ip -6 route add A::/64 via C::1
exit
