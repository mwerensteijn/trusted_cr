source /opt/optee-qemu/optee_examples/trusted_cr/setup_build_envs.sh
echo "Run this: mkdir shared && mount -t 9p -o trans=virtio host shared"
cd /opt/optee-qemu/build
./run.sh

