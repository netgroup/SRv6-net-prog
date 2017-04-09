#! /bin/bash

# makes and installs the module
# it needs to be called from the srext folder as follows:
# ./scripts/deploy.sh

# ./scripts/deploy.sh from-shared-salsano
# also copies all files from the shared folders before compiling


sudo rmmod srext


if [ $# -gt 0 ] && [ $1 = "from-shared-salsano" ]
then
    sudo sh scripts/from-shared-folder-salsano.sh
fi

make
sudo make install

sudo modprobe srext






