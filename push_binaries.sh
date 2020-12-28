#!/bin/bash

echo "mkdir shared ; mount -t 9p -o trans=virtio host shared ; cd shared ; export LD_LIBRARY_PATH=\"/root/shared/lib/:/root/shared/usr/lib64/\" ; export PATH=\$PATH:/root/shared/usr/bin ; python2 crit/critserver.py &" | xclip -sel clip
cp -rf ta/*.ta /opt/optee-qemu/build/shared_folder/
cp -rf host/optee_app_migrator /opt/optee-qemu/build/shared_folder/
cp -rf install_and_run.sh /opt/optee-qemu/build/shared_folder/
