## Compile CLI and module
```
$ make 
```

## Install CLI and module
```
$ sudo make install
```

## Usage
```
$ sudo modprobe sr_connector
$ srconf north add bbbb::2 decapfw auto veth0-nfv-node 00:00:00:00:00:22
$ srconf south add veth0-nvf-node encap auto bbbb::2
$ srconf north del bbbb::2
$ sudo rmmod sr_connector
```

## Usage (to enter in the namespace)
```
$ ip netns list
$ sudo ip netns exec <NAMESPACE_NAME> bash
$ ip a
$ tcpdump -i <VIRTUAL_IF_NAME>
```

## Deinstall CLI and module
```
$ sudo make deinstall
$ make clean
```
