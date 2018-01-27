#!/bin/bash

# This script configures the nfv  node for testbed1
# Testbed1 represents the use-case of chaining of SR-unaware SFs
# This script deos the following
### Creates three network namespace which are used as SR-unaware VNFS(SFs)
### Uses srext to add an End.AD6 localsid for each VNF which handles...
### ...the processing of SRv6 encapsulation in behalf of the SR-unaware VNFs
### For simplicity, End.AD6 (proxy behavior) uses the same interface as ...
### ...Target (OIF) and source (IIF) interface
### Uses srext to add an End localsid which is used by traffic coming...
### ... from the server towards the client 

# Create VNFS
sudo ./vnf-single_iface.sh add vnf1 veth1_2 inet6 2:f1::1/64 2:f1::f1/64
sudo ./vnf-single_iface.sh add vnf2 veth2_2 inet6 2:f2::1/64 2:f2::f2/64
sudo ./vnf-single_iface.sh add vnf3 veth3_2 inet6 2:f3::1/64 2:f3::f3/64

# Configure localsids
sudo modprobe srext
sudo srconf localsid add 2::AD6:F1 end.ad6 ip 2:f1::f1 veth1_2 veth1_2 
sudo srconf localsid add 2::AD6:F2 end.ad6 ip 2:f2::f2 veth2_2 veth2_2
sudo srconf localsid add 2::AD6:F3 end.ad6 ip 2:f3::f3 veth3_2 veth3_2
sudo srconf localsid add 2:: end

exit 
