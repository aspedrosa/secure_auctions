#!/bin/bash

#########################################
#                                       #
# Copy the content of all shared files  #
#   ad to the directory of every entity #
# Can also be used to update them after #
#   any change                          #
#                                       #
#########################################

cd client
rm encryption
cp -r ../shared/encryption   encryption


cd ../manager
rm encryption
cp -r ../shared/encryption   encryption

cd ../repository
rm encryption
cp -r ../shared/encryption   encryption
