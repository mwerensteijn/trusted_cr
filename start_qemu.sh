source /opt/optee-qemu/optee_examples/optee_app_migrator/setup_build_envs.sh
echo "Run this: mkdir shared && mount -t 9p -o trans=virtio host shared"
cd /opt/optee-qemu/build
./run.sh

