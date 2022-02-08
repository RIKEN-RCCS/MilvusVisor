# How to build the hypervisor

## By Rust toolchain
(TBD)


## By docker
### Requirements
- Docker (Tested by `Docker version 20.10.8, build 3967b7d28e`)
  - I tested by non-root users (See [this](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user) to run docker command by non-root user)

### Steps (commands list)

```bash
cd path/to/repo-root/src
./build_docker_image.sh #Build docker image to build
./build_hypervisor_by_docker.sh #Build the hypervisor by the docker image
```
More detail, please see the scripts.

# How to run the hypervisor
## On QEMU
First, please install QEMU that support to emulate `QEMU 2.12 ARM Virtual Machine`, `cortex-a53` CPU.
Then, run the following command to run the built hypervisor.

```bash
cd path/to/repo-root/src
make QEMU_EFI=/usr/share/qemu-efi/QEMU_EFI.fd run #Please set the path of your QEMU_EFI.fd to QEMU_EFI
```

## On a physical machine from an USB memory stick
### Requirement
- Prepare a USB memory which has an EFI (FAT) partition that has `/EFI/BOOT/` directory. Please confirm that there is no important file in the partition.
- Prepare a physical machine that has ARMv8-A or later, and UEFI firmware.

### Steps
1. Attach your USB memory stick to the development machine which built the hypervisor binary.
2. Identify the EFI partition (in the following description, `/dev/sdX1` is the EFI partition).
3. Run `sudo make DEVICE=/dev/sdX1 write` to copy the binary.
   !! Please be carefully not to specifying a wrong partition as `DEVICE` because the script mount/unmount the partition and copy the binary file with root privilege.!!
4. Detach the USB memory from the development machine, and attach it to the physical machine to run the hypervisor.
5. Boot the physical machine with UEFI, and specify `BOOTAA64.EFI` in the EFI partition as the EFI application to boot.

