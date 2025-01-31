#!/bin/bash

apt update
apt install -y ssh
echo """$SSH_PRIVATE_KEY""" > ./key.key
chmod 600 ./key.key
scp -P $REMOTE_PORT -o StrictHostKeyChecking=accept-new -i ./key.key -r ./$SOURCE/* $REMOTE_USER@$REMOTE_HOST:$TARGET_DIR
rm -rf ./key.key