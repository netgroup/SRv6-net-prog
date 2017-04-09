#! /bin/bash

#copy all the files from the shared folder into the current directory
#ATTENTION: THE FILES IN THE SHARED FOLDER NEEDS TO BE SYNCED WHEN REMOTE UPDATES ARE MADE
#USE the to-shared-folder-salsano.sh script

LOCAL_FOLDER=/home/sr6/srv6-net-prog/srext
SHARED_FOLDER=/media/sf_shared-nfv-node/srv6-net-prog


cp $SHARED_FOLDER/kernel/*.c $LOCAL_FOLDER/kernel
cp $SHARED_FOLDER/tools/*.c $LOCAL_FOLDER/tools
cp $SHARED_FOLDER/include/*.h $LOCAL_FOLDER/include
cp $SHARED_FOLDER/scripts/*.sh $LOCAL_FOLDER/scripts








