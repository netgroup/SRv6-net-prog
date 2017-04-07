
default:
	sudo make deinstall
	make clean
	$(MAKE) -C kernel/
	$(MAKE) -C tools/
	
install:
	$(MAKE) -C kernel/ install
	$(MAKE) -C tools/ install

clean:
	$(MAKE) -C kernel/ clean
	$(MAKE) -C tools/ clean
	
deinstall:
	$(MAKE) -C kernel/ deinstall
	$(MAKE) -C tools/ deinstall
