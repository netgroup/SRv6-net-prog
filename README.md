# SREXT

SREXT is a kernel module providing the basic Segment Routing functions in addition to more advanced
ones. It can be used as a standalone SRv6 implementation or as a complement to the existing SRv6 
kernel implementation (kernel 4.10 and later kernels). 

This is the [project web page](https://github.com/netgroup/SRv6-net-prog/), part of the [ROSE](https://netgroup.github.io/rose/) project.

SREXT supports “my local SID table” which contains the local SRv6 segments explicitly instantiated 
in the node and associates each SID with a function. The local SID table is completely independent 
from the Linux routing table and contains only SRv6 segments. Each entry of the localsid table is an
SRv6 segment that is associated with an SRv6 endpoint behavior. 

SREXT registers a callback function in the pre-routing hook of the netfilter framework. This 
callback function is invoked for each received IPv6 packet. If the destination address of the IPv6 
packet matches an entry in the local SID table, the associated behavior is applied otherwise the 
packet will go through the kernel's routing sub-system for normal processing.

SREXT support most endpoint behaviors of the [I-D.ietf-spring-srv6-network-programming](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming) by associating a different function to different 
SRv6 segments. The following table summarize the currently implemented SRv6 endpoint behaviors. 
```
+-------------+--------------------------------------------------------------------------------+
| BEHAVIOR    |                                  Desription                                    |
|-------------+--------------------------------------------------------------------------------+
|  End        | The Endpoint function ("End" for short) is the most basic function             |
|-------------+--------------------------------------------------------------------------------+
|  End.X      | Endpoint with cross-connect to an array of layer-3 adjacencies                 |
|-------------+--------------------------------------------------------------------------------+
|  End.DX2    | Endpoint with decapsulation and Layer-2 cross-connect to OIF                   |
|-------------+--------------------------------------------------------------------------------+
|  End.Dx4    | Endpoint with decapsulation and cross-connect to an IPv4 adjacency             |
|-------------+--------------------------------------------------------------------------------+
|  End.DX6    | Endpoint with decapsulation and cross-connect to an IPv6 adjacency             |
|-------------+--------------------------------------------------------------------------------+
|  End.AD4    | Endpoint to IPv4 SR-unaware APP via dynamic proxy                              |
|-------------+--------------------------------------------------------------------------------+
|  End.AD6    | Endpoint to IPv6 SR-unaware APP via dynamic proxy                              |
|-------------+--------------------------------------------------------------------------------+
|  End.AM     | Endpoint to SR-unaware APP via masquerading                                    |
|-------------+--------------------------------------------------------------------------------+
|  End.EAD4   | Extended End.AD4 behavior that allow SR-unaware VNFS to be the last SF in SFC  |
|-------------+--------------------------------------------------------------------------------+
|  End.EAD6   | Extended End.AD6 behavior that allow SR-unaware VNFS to be the last SF in SFC  |
+-------------+--------------------------------------------------------------------------------+
```

## I. Compilation and Installation 

### Clone srv6-net-prog repository in your machine:

```
$ git clone https://github.com/netgroup/SRv6-net-prog 
```

### Compile srext module and CLI

```
$ cd srv6-net-prog/srext/
$ sudo make 
```

### Install srext module and CLI

```
$ sudo make install
```

### Deinstall srext module and CLI

```
$ sudo rmmod srext
$ sudo make deinstall
$ sudo make clean
```

## II. Usage

SREXT provides a command-line interface to interact with the local SID table, for adding a new SID, 
removing an existing SID, showing its content and more. Some examples of the CLI syntax is shown
hereafter 

### Loading srext module

```
$ sudo depmod -a
$ sudo modprobe srext
```

### srext CLI

```
$ sudo srconf localsid
Usage: srconf localsid { help | flush }
       srconf localsid { show | clear-counters } [SID]
       srconf localsid del SID
       srconf localsid add SID BEHAVIOUR
BEHAVIOUR:= { end |
              end.dx2 TARGETIF |
              end.dx4 NEXTHOP4 TARGETIF |
              { end.x | end.dx6 } NEXTHOP6 TARGETIF |
              { end.ad4 | end.ead4 } NEXTHOP4 TARGETIF SOURCEIF |
              { end.am | end.ad6 | end.ead6 } NEXTHOP6 TARGETIF SOURCEIF |
              end.as4 NEXTHOP4 TARGETIF SOURCEIF src ADDR segs SIDLIST left SEGMENTLEFT }
              end.as6 NEXTHOP6 TARGETIF SOURCEIF src ADDR segs SIDLIST left SEGMENTLEFT |
NEXTHOP4:= { ip IPv4-ADDR | mac MAC-ADDR }
NEXTHOP6:= { ip IPv6-ADDR | mac MAC-ADDR }
```

#### - Adding a new SID to “my localsid table” 

Let's take an example of adding a SID with End.AM behavior. The End.AM behavioris used mostly is SFC
use cases. It supports service chaining through SR-unaware application. 

```
$ sudo srconf localsid add SID end.am ip IPv6-ADDR TARGETIF SOURCEIF
```

  SID: SRv6 segment

  IP-ADDR: IPv6 address of the VNF

  TARGETIF: Target interface is used to trnsmmit packets to the VNF (after Masquerading)

  SOURCEIF: Source interface identifies packets coming back from the VNF (to be de-masqueraded)

#### - Deleting and existing SID from “my localsid table” 

```
$ sudo srconf localsid del SID 
```

If you want to delete all SIDs of the local SId table, you can use the `flush` command instead

```
$ sudo srconf localsid flush 
```

#### - Printing the SIDs of “my localsid table”

The show command prints SIDs of “my localsid table”, and shows, for each SID, the associated 
behavior, attributes, and counters for both good and bad traffic

The `show` command comes in two variants; 

##### - show all SIDs of my local SID table 

```
$ sudo srconf localsid show 
```

##### - show specific SID from my local SID table 

```
$ sudo srconf localsid show SID
```

Here an example output of the show command for all SIDs:  

```
$ sudo srconf localsid show
SRv6 - MY LOCALSID TABLE:
======================================================= 
  SID     :        2::AD6:F1  
  Behavior:        end.ad6  
  Next hop:        2:f1::f1  
  OIF     :        veth1-2-f1   
  IIF     :        veth1-2-f1   
  Good traffic:    [33 packets : 3894  bytes]  
  Bad traffic:     [0 packets : 0  bytes]
 ------------------------------------------------------   
  SID     :        2::AD6:F2  
  Behavior:        end.ad6
  Next hop:        00:00:00:02:f3:f3   
  OIF     :        veth1-2-f2   
  IIF     :        veth1-2-f2   
  Good traffic:    [33 packets : 3894  bytes]  
  Bad traffic:     [0 packets : 0  bytes]
 ------------------------------------------------------ 
  SID     :        2::D6:3
  Behavior:        end.dx6  
  Next hop:        2:3::3
  OIF     :        eth2   
  Good traffic:    [33 packets : 3894  bytes]  
  Bad traffic:     [0 packets : 0  bytes]
  ------------------------------------------------------
```

### SID counters 

SREXT ClI provides, for each SID, counters for both good and bad traffic that match with each SID. 
The counters are printed in the output of the show command.

SREXT gives the ability to clear the SID conuters using the `clear-counters` command 

The `clear-counters` command comes in two variants; 

##### - clear counters of all SIDs of my local SID table 

```
$ sudo srconf localsid clear-counters 
```

##### - clear counters of specific SID from my local SID table 

```
$ sudo srconf localsid clear-counters SID
```

## Testbed - SFC use-case 

we provide a VirtualBox testbed using Vagrant. The testbed gives an example of using the srext module 
to support the chaining of SR-unaware VNFs use-case. 

For a complete description of the use-case, please visit the [testbed page](https://netgroup.github.io/SRv6-net-prog/testbed-basic.html)

&nbsp;
* [Project Home Page](https://netgroup.github.io/SRv6-net-prog/)
