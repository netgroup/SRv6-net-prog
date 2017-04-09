#! /bin/bash

# copy all the files from the shared folder into the local folder
# ATTENTION: whhen remote updates are made, the files in the shared folder
# needs to be updated using the script: 
# sudo scripts/to-shared-folder-salsano.sh 

LOCAL_FOLDER=/home/sr6/srv6-net-prog/srext
SHARED_FOLDER=/media/sf_shared-nfv-node/srv6-net-prog


cp $SHARED_FOLDER/kernel/*.c $LOCAL_FOLDER/kernel
cp $SHARED_FOLDER/tools/*.c $LOCAL_FOLDER/tools
cp $SHARED_FOLDER/include/*.h $LOCAL_FOLDER/include
cp $SHARED_FOLDER/scripts/*.sh $LOCAL_FOLDER/scripts








