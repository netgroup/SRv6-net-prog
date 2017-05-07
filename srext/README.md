## Compile srext module and CLI
```
$ make 
```

## Install srext module and CLI
```
$ sudo make install
$ sudo modprobe srext
```

## Configure NFV node and create the VNF (experiment 1)
```
$ sudo scripts/nfv-node-setup.sh
```


## Usage
```
$ srconf srdev add node-vnf1-ve0 encap auto bbbb::2
$ srconf localsid add bbbb::2 decapfw auto node-vnf1-ve0 00:00:00:00:00:22
$ srconf localsid del bbbb::2
```

## Usage (to enter in the namespace and run tcpdump inside)
```
$ ip netns list
$ sudo ip netns exec <NAMESPACE_NAME> bash
$ ip a
$ tcpdump -i <VIRTUAL_IF_NAME>

EXAMPLES:
$ sudo ip netns exec vnf1 bash
$ tcpdump -i vnf1-ve0
```

## Deinstall CLI and module
```
$ sudo rmmod srext
$ sudo make deinstall
$ make clean
```
