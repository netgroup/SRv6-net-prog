# SRv6 Network Programming in Linux

The “SRv6 Network Programming” is a new paradigm (see the [IETF draft](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming)) to support advanced services in IPv6 networks. It relies on the capability to compose complex network service by chaining individual functions distributed through the SRv6 network and to represent the chains with Segment Routing headers that are included in the IPv6 packet headers.

### srext - Segment Routing Extension Linux kernel module
We are implementing the SRv6 Network Programming model in the _srext_ Linux kernel module, supported by a CLI based configuration application called _srconf_. See our public [code repository](https://github.com/netgroup/SRv6-net-prog).

### Chaining of SRv6-unaware VNFs 
We implemented a [testbed](testbed-basic.md) for a SFC use case (chaining of SR-unaware VNFs using SRv6). The testbed can be easily replicated using Vagrant/VirtualBox.

### Scientific papers, technical reports, IETF drafts, Slides

- A. AbdelSalam, F. Clad, C. Filsfils, S. Salsano, G. Siracusano and L. Veltri  
"[Implementation of Virtual Network Function Chaining through Segment Routing in a Linux-based NFV Infrastructure](http://ieeexplore.ieee.org/document/8004208/)",  
 3rd IEEE Conference on Network Softwarization (NetSoft 2017), Bologna, Italy, July 2017.

- IETF draft "[SRv6 Network Programming](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming)", IETF 98 (March 2017) presentation [slides](https://www.ietf.org/proceedings/98/slides/slides-98-spring-srv6-network-programming-00.pdf)

- IETF draft "[Segment Routing for Service Chaining](https://tools.ietf.org/html/draft-clad-spring-segment-routing-service-chaining-00)," October 2017. 

- Slides " [Service Function Chaining with SRv6](https://www.slideshare.net/amsalam20/service-function-chaining-with-srv6)," January 2018.

### Design documents

- "[Linux implementation of SRv6 Network Programming model](https://www.dropbox.com/s/fk4o8xecbmuoeji/linux-SRv6-net-prog-design-shared.pdf?dl=1)"

### Useful links

- Cisco-maintained website about Segment Routing: [http://www.segment-routing.net](http://www.segment-routing.net)
- Linux kernel implementation of IPv6 Segment Routing: [http://www.segment-routing.org](http://www.segment-routing.org)

