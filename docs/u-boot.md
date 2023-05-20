# U-Boot Support
MilvusVisor has support for U-Boot environments.
We tested this on QEMU.

## How to build
To enable U-Boot support, you need to add `u-boot` feature flag on building binaries of hypervisor and bootloader.

```shell
rustup component add rust-src
cd path/to/repo-root/src
make custom_all FEATURES=u_boot
```

## How to execute on QEMU
After you build MilvusVisor with U-Boot support, you need 2 U-Boot binary, for EL2 and for EL1.
The first U-Boot runs in EL2 to boot MilvusVisor, and the second U-Boot runs in EL1.
The following steps are example to run Linux on MilvusVisor:

1. Install `qemu-system-aarch64`
2. Build your U-Boot for QEMU for EL2 and EL1
    - Basically, you can use the same binary both in EL2 and EL1, but we recommend to disable `CONFIG_ARCH_FIXUP_FDT_MEMORY` in EL1 build.
3. Put EL2 `u-boot.bin` to `path/to/u-boot-root/u-boot.bin`
4. Put EL1 `u-boot.bin` to `path/to/repo-root/src/bin/EFI/BOOT`
5. Put your Linux kernel (and initramfs if necessary) to `path/to/linux`
6. To generate DTB for EL1, run QEMU with following command:
```shell
$QEMU -display curses \
      -m 8G \
      -cpu a64fx \
      -machine virt,virtualization=on,gic-version=max,dumpdtb=dumb.dtb \
      -nographic \
      -bios path/to/u-boot-root/u-boot.bin \
      -drive file=fat:rw:path/to/repo-root/src/bin/,format=raw,if=none,media=disk,id=drive1 \
      -device virtio-blk,drive=drive1,bootindex=0 \
      -drive file=fat:rw:path/to/linux,format=raw,if=none,media=disk,id=drive2 \
      -device virtio-blk,drive=drive2,bootindex=1
```
7. Convert `dump.dtb` to DTS by following command:
```shell
dtc -I dtb -O dts -o dump.dts dump.dtb
```
8. Edit `dumb.dts` to shrink RAM region. In this example, RAM region has 8GB, so shrink RAM region to 4GB in EL1
```dts
	memory@40000000 {
		reg = <0x00 0x40000000 0x01 0x00>;
		device_type = "memory";
	};
```
9. Convert `dump.dts` to DTB and put it to `path/to/linux`
```shell
dtc -I dts -O dto -o path/to/linux/el1.dtb dump.dts
```
10. Run QEMU with following command:

```shell
$QEMU -display curses \
      -m 8G \
      -cpu a64fx \
      -machine virt,virtualization=on,gic-version=max \
      -nographic \
      -bios path/to/u-boot-root/u-boot.bin \
      -drive file=fat:rw:path/to/repo-root/src/bin/,format=raw,if=none,media=disk,id=drive1 \
      -device virtio-blk,drive=drive1,bootindex=0 \
      -drive file=fat:rw:path/to/linux,format=raw,if=none,media=disk,id=drive2 \
      -device virtio-blk,drive=drive2,bootindex=1
```
11. Firstly, `u-boot.bin` is executed, and automatically load MilvusVisor from `path/to/repo-root/src/bin/EFI/BOOT`
12. MilvusVisor loads `u-boot` in `path/to/repo-root/src/bin/EFI/BOOT`, and then execute it in EL1
13. Once U-Boot starts, press any key to enter the console.
14. Boot Linux by following commands
```shell
load virtio 1 $kernel_addr_r Image
load virtio 1 $fdt_addr el1.dtb
booti $kernel_addr_r - $fdt_addr
```
