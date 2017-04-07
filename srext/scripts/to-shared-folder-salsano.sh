#! /bin/bash

#copy all the files from the current directory to the shared folder 
#USED TO SYNC THE FILES IN THE SHARED FOLDER NEEDS WHEN REMOTE UPDATES ARE MADE

cd /media/sf_shared-nfv-node/v01devel/scripts
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp /home/sr6/v0.1-integration/scripts/*.sh .

cd /media/sf_shared-nfv-node/v01devel/kernel
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp /home/sr6/v0.1-integration/kernel/*.c .

cd /media/sf_shared-nfv-node/v01devel/tools
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp /home/sr6/v0.1-integration/tools/*.c .

cd /media/sf_shared-nfv-node/v01devel/include
if [ $? -ne 0 ]
then
  echo "folder not found, the script has failed"
  exit 1
fi

rm *
cp /home/sr6/v0.1-integration/include/*.h .



