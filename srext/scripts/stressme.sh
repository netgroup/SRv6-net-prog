#! /bin/bash
make
sudo rmmod srext
sudo insmod kernel/srext.ko


legal_cmd_n=1 # real number -1 !!
mix_cmd_n=7

# ok commands

cmd[0]='srconf south add veth0-nfv encap auto bbbb::2'
cmd[1]='srconf north add bbbb::2 decapfw auto veth0-nfv-node 00:00:00:00:00:02'
cmd[2]='srconf south del veth0-nfv'
cmd[3]='srconf north del bbbb::2'

# not working commands

cmd[4]='srconf south add veth18-nvf-node encap auto bbbb::2'
cmd[5]='srconf north add bbcc::2::212 decapfw auto veth0-nfv-node 00:00:00:00:00:02'
cmd[6]='srconf south del veth15-nvf-node'
cmd[7]='srconf north del bccc::2'

ok_mix(){
	for i in {1..5000}
	do
		index=$(($RANDOM % ${legal_cmd_n}))
		eval ${cmd[${index}]}
		#srconf south add veth0-nvf-node encap auto bbbb::2
		#srconf north add bbbb::2 decapfw auto veth0-nfv-node 00:00:00:00:00:02
	done
}
ok(){
	for i in {1..5000}
	do
		eval ${cmd[0]}
		eval ${cmd[1]}
		eval ${cmd[2]}
		eval ${cmd[3]}
		#srconf north add bbbb::2 decapfw auto veth0-nfv-node 00:00:00:00:00:02
	done
}
mix(){
	for i in {1..5000}
	do
		index=$(($RANDOM % ${mix_cmd_n}))
		eval ${cmd[${index}]}
		#srconf south add veth0-nvf-node encap auto bbbb::2
		#srconf north add bbbb::2 decapfw auto veth0-nfv-node 00:00:00:00:00:02
	done
}


$1

# ok commands 
srconf south add veth0-nfv encap auto bbbb::2
srconf north add bbbb::2 decapfw auto veth0-nfv 00:00:00:00:00:22
