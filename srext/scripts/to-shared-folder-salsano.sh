#! /bin/bash

# copy all the files from the current directory to the shared folder 
# USED TO SYNC THE FILES IN THE SHARED FOLDER 
# IT IS NEEDED AT THE START OF A DEVELOPMENT SESSION AND WHEN REMOTE UPDATES ARE MADE

LOCAL_FOLDER=/home/sr6/srv6-net-prog/srext
SHARED_FOLDER=/media/sf_shared-nfv-node/srv6-net-prog

cd $SHARED_FOLDER/scripts
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp $LOCAL_FOLDER/scripts/*.sh .

cd $SHARED_FOLDER/kernel
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp $LOCAL_FOLDER/kernel/*.c .

cd $SHARED_FOLDER/tools
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp $LOCAL_FOLDER/tools/*.c .

cd $SHARED_FOLDER/include
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp $LOCAL_FOLDER/include/*.h .



