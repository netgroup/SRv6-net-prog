#!/bin/bash

# This script configures the egress node for testbed1
# Testbed1 represents the use-case of chaining of SR-unaware SFs
# This script deos the following
### Creates a network namespace which is used as a server
### Adds an SFC SRv6 policy for traffic to be sent to the client
### Uses srext to add an End.DX6 localsid which decapsulate...
### ... traffic sent by client before being sent to the server

# Create server
sudo ./vnf-single_iface.sh add server veth1_3 inet6 b::1/64 b::2/64

# Configure SFC SRv6 policy
sudo ip -6 route add a::/64 via 2:3::2 encap seg6 mode encap segs 2::,1::D6

# Configure localsids
sudo modprobe srext 
sudo srconf localsid add 3::d6 end.dx6 ip b::2 veth1_3

exit 
