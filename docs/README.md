# SRv6 Network Programming in Linux

The “SRv6 Network Programming” is a new paradigm (see the [IETF draft](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming)) to support advanced services in IPv6 networks. It relies on the capability to compose complex network service by chaining individual functions distributed through the SRv6 network and to represent the chains with Segment Routing headers that are included in the IPv6 packet headers.

### srext - a Linux kernel module for the SRv6 Network Programming model

We are implementing the SRv6 Network Programming model in the _srext_ Linux kernel module, supported by a CLI based configuration application called _srconf_. See our public [code repository](https://github.com/netgroup/SRv6-net-prog).

We implemented a [[testbed for a SFC use case (chaining of SR-unaware VNFs using SRv6)|testbed-basic]]. The testbed can be easily replicated using Vagrant/VirtualBox.

### Scientific papers, technical reports

- A. AbdelSalam, F. Clad, C. Filsfils, S. Salsano, G. Siracusano and L. Veltri  
"[Implementation of Virtual Network Function Chaining through Segment Routing in a Linux-based NFV Infrastructure](http://arxiv.org/abs/1702.05157)",  
To appear in: 3rd IEEE Conference on Network Softwarization (NetSoft 2017), Bologna, Italy, July 2017.


### Design documents

- "[Linux implementation of SRv6 Network Programming model](https://www.dropbox.com/s/ly6qnod8as8dnj0/linux-SRv6-net-prog-design-shared.pdf?dl=1)"

### Useful links

- Cisco-maintained website about Segment Routing: http://www.segment-routing.net
- Linux kernel implementation of IPv6 Segment Routing: http://www.segment-routing.org
- IETF draft "[SRv6 Network Programming](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming)", IETF 98 (March 2017) presentation [slides](https://www.ietf.org/proceedings/98/slides/slides-98-spring-srv6-network-programming-00.pdf)



