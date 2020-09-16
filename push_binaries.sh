#!/bin/bash

echo "mkdir shared && mount -t 9p -o trans=virtio host shared && cd shared" | xclip -sel clip
cp -rf ta/*.ta /opt/optee-qemu/build/shared_folder/
cp -rf host/optee_app_migrator /opt/optee-qemu/build/shared_folder/
cp -rf install_and_run.sh /opt/optee-qemu/build/shared_folder/
