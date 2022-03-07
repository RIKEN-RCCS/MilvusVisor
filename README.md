# MilvusVisor
MilvusVisor is a thin hypervisor that runs on aarch64 CPUs.

The features of the MilvusVisor are the following.

- (Theoretically) Smaller footprint and overhead than typical VMM (e.g. QEMU/KVM, Xen)
- Support running only one guest OS simultaneously for keeping it simple and thin
- Written in Rust


MilvusVisor allows providing functions OS-independently without the overhead of device virtualization.
We are currently developing MilvusVisor as a research activity to achieve HPC environments that provide root privilege to the users without virtualization overhead.

## Functions

Currently, MilvusVisor provides the following function.

- Protecting non-volatile data in devices from guest OS (e.g. Firmware, MAC address)
  - Supported device: Intel I210
- Protecting MilvusVisor itself against DMA attack
  - Using SMMUv3 Stage 2 Page Translation to protect from DMA attack

## Tested machines

We have tested MilvusVisor on the following machines.

- FX700
- AML-S805X-AC
- QEMU

The following table shows which feature worked on which machines.

| Test items \\ Machine                            | FX700 | AML | QEMU |
|:-------------------------------------------------|:-----:|:---:|:----:|
| Booting Linux on MilvusVisor (Multi-core)        | o     | o   | o    |
| Protecting non-volatile data of Intel I210       | o     | -   | -    |
| Protecting MilvusVisor itself against DMA attack | o     | -   | -    |


## How to build the hypervisor

### By Rust toolchain

#### Requirements
- `rustup` command-line tool (you can install from https://rustup.rs/)

#### Steps (commands list)
```
rustup component add rust-src
cd path/to/repo-root/src
make
```

Next (How to run the hypervisor)[＃How to run the hypervisor]

### By docker
#### Requirements
- Docker (Tested by `Docker version 20.10.8, build 3967b7d28e`)
  - I tested by non-root users (See [this](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user) to run docker command by non-root user)

#### Steps (commands list)

```bash
cd path/to/repo-root/src
./build_docker_image.sh #Build docker image to build
./build_hypervisor_by_docker.sh #Build the hypervisor by the docker image
```
For more detail, please see the scripts.

## How to run the hypervisor
### On QEMU
First, please install QEMU that supports emulating `QEMU ARM Virtual Machine`, `a64fx` CPU.
Then, run the following command to run the built hypervisor.

```bash
cd path/to/repo-root/src
make QEMU_EFI=/usr/share/qemu-efi/QEMU_EFI.fd run #Please set the path of your QEMU_EFI.fd to QEMU_EFI
```

### On a physical machine from a USB memory stick
#### Requirement
- Prepare a USB memory that has an EFI (FAT) partition that has `/EFI/BOOT/` directory. Please confirm that there is no important file in the partition.
- Prepare a physical machine that has ARMv8-A or later, and UEFI firmware.

#### Steps
1. Attach your USB memory stick to the development machine which built the hypervisor binary.
2. Identify the EFI partition (in the following description, `/dev/sdX1` is the EFI partition).
3. Run `sudo make DEVICE=/dev/sdX1 write` to copy the binary.
   !! Please be careful not to specify a wrong partition as `DEVICE` because the script mount/unmount the partition and copies the binary file with root privilege.!!
4. Detach the USB memory from the development machine, and attach it to the physical machine to run the hypervisor.
5. Boot the physical machine with UEFI, and specify `BOOTAA64.EFI` in the EFI partition as the EFI application to boot.

## How to generate the documentation
You can generate the document by `cargo doc` in each cargo project directory.

If you want to see bootloader's document, please run the following command.

```bash
cd path/to/repo-root/src/hypervisor_bootloader
cargo doc --open # Browser will open
```

If you want to see kernel's document, please run the following command.

```bash
cd path/to/repo-root/src/hypervisor_kernel
cargo doc --open # Browser will open
```

## Acknowledgment
This work was supported by JSPS KAKENHI Grant Number 21K17727.
