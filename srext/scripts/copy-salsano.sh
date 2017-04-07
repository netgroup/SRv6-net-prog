#! /bin/bash

#copy all the files from the shared folder into the current directory
#ATTENTION: THE FILES IN THE SHARED FOLDER NEEDS TO BE SYNCED WHEN REMOTE UPDATES ARE MADE
#USE the to-shared-folder-salsano.sh script

cp /media/sf_shared-nfv-node/v01devel/kernel/*.c /home/sr6/v0.1-integration/kernel
cp /media/sf_shared-nfv-node/v01devel/tools/*.c /home/sr6/v0.1-integration/tools
cp /media/sf_shared-nfv-node/v01devel/include/*.h /home/sr6/v0.1-integration/include
cp /media/sf_shared-nfv-node/v01devel/scripts/*.sh /home/sr6/v0.1-integration/scripts








