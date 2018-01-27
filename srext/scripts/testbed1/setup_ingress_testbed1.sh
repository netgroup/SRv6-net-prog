#!/bin/bash

# This script configures the ingress node for testbed1
# Testbed1 represents the use-case of chaining of SR-unaware SFs
# This script deos the following 
### Creates a network namespace which is used as a client 
### Adds an SFC SRv6 policy for traffic to be sent to the server 
### Uses srext to add an End.DX6 localsid which decapsulate...
### ... traffic sent by server before being sent to the client 

# Create client
./vnf-single_iface.sh add client veth1_1 inet6 a::1/64 a::2/64

# Configure Routing 
sudo ip -6 route add 2::/64 via 1:2::2

# Configure SFC SRv6 policy
sudo ip -6 route add b::/64 via 1:2::2 encap seg6 mode encap segs 2::AD6:F1,2::AD6:F2,2::AD6:F3,3::D6

# Configure localsids
sudo modprobe srext 
sudo srconf localsid add 1::d6 end.dx6 ip a::2 veth1_1

exit 
