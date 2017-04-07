# SFC chaining testbed using srext module

We consider a Service Function Chaining scenario supported by IPv6 Segment Routing. In our scenario, a Service Chain is an ordered set of Virtual Network Functions (VNFs) and each VNF is represented by its IPv6 address. We assume that VNFs are hosted in "NFV nodes". 

In this scenario, the srext module is used in a Linux NFV node in order to support legacy VNFs (i.e. "SR-unaware" VNFs). 

The srext module allows introducing SR-unaware VNFs in a Service Chain implemented with IPv6 Segment Routing. It removes the Segment
Routing encapsulation before handing the packets to the VNF and properly reinserts the SR encapsulation to the packets processed by the VNF. 

## Chaining of SR-unaware VNFs 

In order to replicate the experiment of chaining of SR-unaware VNFs by using the srext module, we provide a simple VirtualBox testbed using vagrant.

The testbed is composed of three Virtual Machines (VMs) that represent SR ingress node, NFV node, and SR egress node: 

**SR ingress node:** processes incoming packets, classifies them, and enforces a per-flow VNF chain; the list of VNF identifiers is applied by encapsulating the original packets in a new IPv6 packets with a SRH reporting as segment list the ordered list of addresses of the given VNFs

**SR egress node:** removes the SR encapsulation and forwards the inner packet toward its final destination. This allows the final destination to correctly process the original packet.

**NFV node:** is capable of processing SR-encapsulated packets and passing them to the srext module.

The ingress node can also be used to generate traffic (either simple ICMP packets  or by means of iperf), this traffic will be encapsulated in SR packets (with outer header IPv6 header and SRH).

The NFV node has a VNF running inside a network namespace. The VNF is SR-unaware which means that it has to receive the packets without SR encapsulation. 

The srext module (a Linux kernel module), is used to de-encapsulate the packets, by removing the SR encapsulation, before sending them to the VNF.

The VNF processes the packet (in this scenario the VNF just forwards the packet) and sends it back again to the srext module which will re-insert the SR encapsulation to the packet before sending it to the egress node.

The egress node removes SR encapsulation from packets and sends them towards the final destination.

### Testbed Setup 
Before starting, please be sure that you have [vagrant](https://www.vagrantup.com/downloads.html) and [virtualbox](https://www.virtualbox.org/wiki/Downloads) installed on your machine.

Clone the srext repository in your machine: 

```
$ git clone https://github.com/netgroup/SRv6-net-prog
$ cd  SRv6-net-prog
```
Add the srext vagrant box:
```
$ vagrant box add sr-vnf http://cs.gssi.infn.it/files/SFC/sr_nfv_connector.box 
```
Start the testbed:
```
$ vagrant up 
```
It takes a bit of time …. please be patient 

#### Verifying functionality of srext module and its ability to de-encapsulate and re-encapsulate packets

Log into the VM of ingress node: 
```
$ vagrant ssh ingress 
```
You can a have a look at the routing table of ingress node and see the configuration of SR encapsulation  
```
$ ip -6 route 
```
As a simple example, the ingress node is used to generate icmp traffic
```
$ ping6  C::2 
```
#### To see packets received by VNF after being de-encapsulated by SR-NFV_connector

Open a new terminal and log into the NFV node:
```
$ vagrant ssh nfv 
```
The VNF is running inside network namespace to get inside the VNF:
```
$ sudo su
$ ip netns exec vnf1 bash 
```
Capture the received packets. Packets are received as normal IPv6 packets with next header icmp6 (no SR encapsulation):
```
$ sudo su
$ tcpdump -vvv
``` 
#### To see packets with SR encapsulation before being de-encapasulated by SR-NFV_connector (or after SR encapsulation being  reinserted to packets coming form the VNF)

Open a new terminal and log into the NFV node:
```
$ vagrant ssh nfv
```
Capture packets on either eth1 or eth2. Packets will be in SR encapsulation: 
```
$ sudo su
$ tcpdump -i eth1 -vvv
```
Or ;
```
$ sudo su
$ tcpdump -i eth2 -vvv
```
### Performance Evaluation
In order to get some preliminary performance measures, we run some simple tests using means of iperf.

Iperf is a commonly used tool for measurements of maximum achievable bandwidth on IP networks. It supports tuning of various parameters related to timing, buffers, and protocol. For each test it reports the bandwidth, loss, and other parameters.

Iperf has a client and server functionality that allows to measure the throughput between two ends. In our test scenario, we run iperf server on the egress node and iperf client on the ingress node.

#### Iperf Server
Open a new terminal and log into the egress VM:

```
$ vagrant ssh egress 
```
Run iperf server
```
$ iperf3 -6 -s
```

#### Iperf Client 
In this example, we use iperf client to generate a stream of UDP packet/s each of 1024 byte data size, with a payload data rate of 80MB/s

From the terminal of the ingress VM:
```
$ iperf3 -6 -u -c C::2 -l 1024 -b 80M -t 60
```

It will run for 60 seconds and after taht you will have a report about throughput, loss,… etc.


### CPU Utilization

While iperf test is running you can look at the cpu utilization in the NFV node by using top linux utility.

```
$ top 
```

Or you can log top output for further processing

```
$ top -b -d 0.1 -n 600 | grep -i "%Cpu(s)"  > cpu_util_log
```

### Comparison to plain SR kernel
To measure the overhead added by the SR-NFV_connector. You can run the same iperf tests without the SR-NFV_connector and compare the results.

### Unloading the srext module
From the terminal of NFV node:
```
$ sudo rmmod srext
```

### Notes 

- Resources assigned to any of the VMs can be customized by modifying Vagrantfile 

```
 virtualbox.memory = "1024"
 virtualbox.cpus = "1"
```
- Configuration of ingress node, NFV node , or egress node can be customized by modifying the scripts in the vagrant folder.

- Parameters of iperf client can be customized in order to run the test for longer time, also to generate higher or lower packet rate.

- Parameters of the top command can also be customized to define the number of samples of cpu utilization that you want to log.
