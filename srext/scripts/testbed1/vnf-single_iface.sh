#!/bin/bash

# This script adds or cleans a network namespace
# it can create a name IPv4, IPv6, or dual network stack. 
# it can be used as follows 
# ./vnf-single_iface.sh add VNF_NAME NFV_IFACE MODE [--vnf-mac VNF_MAC_ADDR]
# MODE := inet   NFV_IPv4_ADDR  VNF_IPv4_ADDR
#         inet6  NFV_IPv6_ADDR  VNF_IPv6_ADDR
#         dual   NFV_IPv4_ADDR  VNF_IPv4_ADDR  NFV_IPv6_ADDR  VNF_IPv6_ADDR
# ./vnf-single_iface.sh del VNF_NAME NFV_IFACE
# N.B:
# All IP addresses should be in the form of IP/mask "10.0.0.1/24" --  "A::2/64"
# IF anything goes wrong while adding a VNF please do ./vnf-single_iface.sh del VNF_NAME NFV_IFACE before re-trying!

#usage 
NEWLINE=$'\n'
usage="$0 add VNF_NAME NFV_IFACE MODE [--vnf-mac VNF_MAC_ADDR]${NEWLINE}"
usage="${usage}MODE := inet   NFV_IPv4_ADDR  VNF_IPv4_ADDR ${NEWLINE}"
usage="${usage}        inet6  NFV_IPv6_ADDR  VNF_IPv6_ADDR ${NEWLINE}"
usage="${usage}        dual   NFV_IPv4_ADDR  VNF_IPv4_ADDR  NFV_IPv6_ADDR  VNF_IPv6_ADDR ${NEWLINE}"
usage="${usage}$0 del VNF_NAME NFV_IFACE ${NEWLINE}"
usage="${usage}N.B:${NEWLINE}All IP addresses should be in the form of IP/mask \"10.0.0.1/24\" --  \"A::2/64\" ${NEWLINE}"
usage="${usage}IF anything goes wrong while adding a VNF please do $0 del VNF_NAME NFV_IFACE before re-trying!"

if [ $# -eq 0 ] 
	then 
	echo "${usage}"
	exit
fi 

if [ $1 = "help" ]
	then 
	echo "${usage}"
	exit
fi

if [ $1 != "add" ] && [ $1 != "del" ]
	then 
	echo "ERROR: unrecognized coomand. please try \"$0 help\" " 
	exit
fi 

if [ $# -lt 3 ] 
	then
	echo "ERROR: too few parameters. please try \"$0 help\" " 
	exit 
fi 

COMMAND=$1
VNF_NAME=$2
NFV_IFACE=$3

if [ $COMMAND = "del" ] 
	then
	if [ $# -gt 3 ]
		then
		echo "ERROR: too many parameters for del command. please try \"$0 help\" "
		exit
	fi
   echo "DELETING \"${VNF_NAME}\"........."
   sudo ip link delete dev ${NFV_IFACE} 
   sudo ip netns del $VNF_NAME
   exit
fi


if [ $# -ge 4 ]
	then
	MODE=$4
	if [ $MODE != "inet" ] &&  [ $MODE != "inet6" ]  && [ $MODE != "dual" ] 
		then 
		echo " ERROR: Mode ${MODE} is not a valid inet mode  many. please try \"$0 help\" "
		exit
	fi
fi

if [ $# -lt 6 ] 
	then
	echo "ERROR: too few parameters for add command. please try \"$0 help\" "
	exit
fi

VNF_IFACE="veth0-${VNF_NAME}"

if [ $MODE = "inet" ] || [ $MODE = "inet6" ]
	then
	
	if [ $# -gt 8 ] 
		then 
		echo "ERROR: too many parameters for inet or inet6 mode. please try \"$0 help\" "
		exit
	fi 

	echo "ADDING \"${VNF_NAME}\"........." 
	NFV_IP=$5
	VNF_IP=$6
	NH=`echo ${NFV_IP} | cut -d'/' -f1`

	# create VNF 
	sudo ip netns add $VNF_NAME
	#create link between NFV and VNF
	sudo ip link add ${NFV_IFACE} type veth peer name ${VNF_IFACE}
	#assign virtual interface to VNF
	sudo ip link set ${VNF_IFACE} netns ${VNF_NAME}
	sudo ifconfig ${NFV_IFACE} up
	sudo ip netns exec ${VNF_NAME} ifconfig ${VNF_IFACE} up

	if [ $MODE = "inet" ] 
		then 
			#configure NFV Interface 
			sudo ip addr add ${NFV_IP} dev ${NFV_IFACE}
			#configure VNF interfcae
			sudo ip netns exec ${VNF_NAME} ip addr add ${VNF_IP} dev ${VNF_IFACE}
			#enable forwarding in VNF
			sudo ip netns exec ${VNF_NAME} sysctl -w net.ipv4.conf.all.forwarding=1
			sudo ip netns exec ${VNF_NAME} ip route add default via ${NH}

	else
		sudo ip netns exec ${VNF_NAME} sysctl -w net.ipv6.conf.all.forwarding=1
		sudo ip -6 addr add ${NFV_IP} dev ${NFV_IFACE}
		sudo ip netns exec ${VNF_NAME} ip -6 addr add ${VNF_IP} dev ${VNF_IFACE}
		sudo ip netns exec ${VNF_NAME} ip -6 route add default via ${NH}

	fi 


	if  [ $# -ge 7 ] 
		then 

		if [ $7 != "--vnf-mac" ] 
			then
			echo "ERROR: invalid token \"$7 \". please try \"$0 help\" "
			sudo ip link delete dev ${NFV_IFACE} > /dev/null
			sudo ip netns del $VNF_NAME > /dev/null
			echo "\"${VNF_NAME}\" CLEANED " 
			exit
		fi 

		if [ $# -eq 8 ]
			then 
			VNF_MAC=$8
			sudo ip netns exec ${VNF_NAME} ifconfig ${VNF_IFACE} hw ether ${VNF_MAC}
		fi		
	exit
	fi
else 
	if [ $# -lt 8 ] 
		then 
		echo "ERROR: too few parameters for dual mode. please try \"$0 help\" "
		exit
	fi 

	if [ $# -gt 10 ] 
		then 
		echo "ERROR: too many parameters for dual mode. please try \"$0 help\" "
		exit
	fi 
	
	echo "ADDING \"${VNF_NAME}\"........." 
	NFV_IPv4=$5
	VNF_IPv4=$6
	NFV_IPv6=$7
	VNF_IPv6=$8

	# create VNF 
	sudo ip netns add $VNF_NAME
	#create link between NFV and VNF
	sudo ip link add ${NFV_IFACE} type veth peer name ${VNF_IFACE}
	#assign virtual interface to VNF
	sudo ip link set ${VNF_IFACE} netns ${VNF_NAME}
	sudo ifconfig ${NFV_IFACE} up
	sudo ip netns exec ${VNF_NAME} ifconfig ${VNF_IFACE} up

	#configure NFV Interface 
	sudo ip addr add ${NFV_IPv4} dev ${NFV_IFACE}
	sudo ip -6 addr add ${NFV_IPv6} dev ${NFV_IFACE}

	#configure VNF interfcae
	sudo ip netns exec ${VNF_NAME} ip addr add ${VNF_IPv4} dev ${VNF_IFACE}
	sudo ip netns exec ${VNF_NAME} ip -6 addr add ${VNF_IPv6} dev ${VNF_IFACE}

	#enable forwarding in VNF
	sudo ip netns exec ${VNF_NAME} sysctl -w net.ipv4.conf.all.forwarding=1
	sudo ip netns exec ${VNF_NAME} sysctl -w net.ipv6.conf.all.forwarding=1

	NH4=`echo ${NFV_IPv4} | cut -d'/' -f1`
	NH6=`echo ${NFV_IPv6} | cut -d'/' -f1`

	sudo ip netns exec ${VNF_NAME} ip route add default via ${NH4}
	sudo ip netns exec ${VNF_NAME} ip -6 route add default via ${NH6}

	if  [ $# -ge 9 ] 
		then 

		if [ $9 != "--vnf-mac" ] 
			then
			echo "ERROR: invalid token \"$9 \". please try \"$0 help\" "
			sudo ip link delete dev ${NFV_IFACE} > /dev/null
			sudo ip netns del $VNF_NAME > /dev/null
			echo "\"${VNF_NAME}\" CLEANED " 
			exit
		fi 

		if [ $# -eq 10 ]
			then 
			VNF_MAC=$10
			sudo ip netns exec ${VNF_NAME} ifconfig ${VNF_IFACE} hw ether ${VNF_MAC}
		fi		
	fi
fi
exit