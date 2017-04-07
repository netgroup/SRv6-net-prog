# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

    config.ssh.username = "sr6"
    config.ssh.password = "sr6"

    # Configure ingress node
    config.vm.define "ingress" do |ingress|
	ingress.vm.box = "sr-vnf"
        ingress.vm.network "private_network", ip: "A::2", virtualbox__intnet: "ingress-NFV"

        ingress.vm.provider "virtualbox" do |virtualbox|
            # Customize the amount of memory on the VM:
            virtualbox.memory = "1024"
            virtualbox.cpus = "1"
            virtualbox.customize ['modifyvm', :id, '--cableconnected1', 'on']
            # Enable promiscuous mode
            virtualbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        end

        # Setup Ingress Node 
        ingress.vm.provision "shell", path: "vagrant/setup-ingress.sh"
    end


    # Configure NFV node 
    config.vm.define "nfv" do |nfv|
        nfv.vm.box = "sr-vnf"
        nfv.vm.network "private_network", ip: "A::1", virtualbox__intnet: "ingress-NFV"
        nfv.vm.network "private_network", ip: "C::1", virtualbox__intnet: "NFV-egress"

        nfv.vm.provider "virtualbox" do |virtualbox|
            # Customize the amount of memory on the VM:
            virtualbox.memory = "1024"
            virtualbox.cpus = "1"
	    virtualbox.customize ['modifyvm', :id, '--cableconnected1', 'on']
            # Enable promiscuous mode
            virtualbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
            virtualbox.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
        end

        # Setup NFV Node
        nfv.vm.provision "shell", path: "vagrant/setup-nfv_node.sh"
    end


    # Configure egress node
    config.vm.define "egress" do |egress|
        egress.vm.box = "sr-vnf"
        egress.vm.network "private_network", ip: "C::2", virtualbox__intnet: "NFV-egress"

        egress.vm.provider "virtualbox" do |virtualbox|
            # Customize the amount of memory on the VM:
            virtualbox.memory = "1024"
            virtualbox.cpus = "1"
	    virtualbox.customize ['modifyvm', :id, '--cableconnected1', 'on']
            # Enable promiscuous mode
            virtualbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        end

        # Setup Egress Node 
        egress.vm.provision "shell", path: "vagrant/setup-egress.sh"
    end

end
