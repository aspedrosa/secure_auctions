#!/bin/bash

#################################
#                               #
# Create symbolic links on the  #
#   directory of the entities   #
#                               #
#################################

cd client
rm -r encryption
ln -s ../shared/encryption      encryption


cd ../manager
rm -r encryption
ln -s ../shared/encryption      encryption

cd ../repository
rm -r encryption
ln -s ../shared/encryption      encryption
