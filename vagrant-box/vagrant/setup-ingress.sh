#!/bin/bash

#configuration of ingress node interfaces 
ifconfig eth1 up
ip -6 addr add A::2/64 dev eth1

# segment routing encapsulation of ingress node
ip -6 route add C::2/128 via A::1 encap seg6 mode encap segs B::2,C::2

# static routing configuration of ingress node
ip -6 route add B::/64 via A::1

exit
