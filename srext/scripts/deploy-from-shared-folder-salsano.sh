#! /bin/bash

# copies all files from the shared folders
# makes and installs the module

sudo rmmod srext

sudo sh /home/sr6/v0.1-integration/scripts/copy-salsano.sh


make
sudo make install

sudo modprobe srext






