# Raspberry Pi4 Support

MilvusVisor has support for Raspberry Pi 4 environments.
We tested "Raspberry Pi 4 Computer Model B"

## How to build

To enable Raspberry Pi 4 support, you need to add `raspberrypi` feature flag on building binaries of hypervisor and
bootloader.

```shell
./builder.rs -r -f raspberrypi
```

## How to boot

### Build U-boot

(This step assumed that your environment is Ubuntu. Otherwise, please replace the package names to suitable.)

1. Install `gcc-aarch64-linux-gnu` and `libssl-dev`
2. Clone u-boot and move into the directory
3. `export CROSS_COMPILE=aarch64-linux-gnu-`
4. Set configuration for Raspberry Pi 4: `make rpi_4_defconfig`
5. Build: `make`
6. Copy u-boot.bin
7. Create boot.scr with boot script like below: `tools/mkimage -A arm64 -T script -C none -d boot.txt boot.scr`

```
fatload mmc 0:1 ${kernel_addr_r} EFI/BOOT/BOOTAA64.EFI
bootefi ${kernel_addr_r}
fatload mmc 0:1 ${fdt_addr_r} EFI/BOOT/dtb
fdt addr ${fdt_addr_r}
fatload mmc 0:1 ${kernel_addr_r} kernel8.img
setenv kernel_comp_size ${filesize}
setenv kernel_comp_addr_r 0x3800000
booti ${kernel_addr_r} - ${fdt_addr_r}
```

You can build in the docker with the below shell script(When run docker, don't forget bind directory to get the output
binary :) )

```shell
#!/bin/sh
apt-get update
apt-get install -y build-essential bison bc flex gcc-aarch64-linux-gnu libssl-dev git make
git clone --depth=1 https://source.denx.de/u-boot/u-boot.git
cd u-boot
export CROSS_COMPILE=aarch64-linux-gnu-
make rpi_4_defconfig
make -j`nproc`
cp u-boot.bin /path/to/bound/
cat <<"EOF" > boot.txt
fatload mmc 0:1 ${kernel_addr_r} EFI/BOOT/BOOTAA64.EFI
bootefi ${kernel_addr_r}
fatload mmc 0:1 ${fdt_addr_r} EFI/BOOT/dtb
fdt addr ${fdt_addr_r}
fatload mmc 0:1 ${kernel_addr_r} kernel8.img
setenv kernel_comp_size ${filesize}
setenv kernel_comp_addr_r 0x3800000
booti ${kernel_addr_r} - ${fdt_addr_r}
EOF
tools/mkimage -A arm64 -T script -C none -d boot.txt boot.scr
cp boot.scr /path/to/bound/
```

### Download "Raspberry Pi OS (64-bit)"

Go to https://www.raspberrypi.com/software/operating-systems/ , find "Raspberry Pi OS (64-bit)" section, and download "
Raspberry Pi OS with desktop" or "Raspberry Pi OS Lite". (We tested with "Raspberry Pi OS Lite")

### Write image and binaries

1. Write the OS image to SD: (For
   example: `unxz 20XX-XX-XX-raspios-version-arm64-lite.img.xz && sudo dd if=20XX-XX-XX-raspios-version-arm64-lite.img of=/dev/mmcblk0 bs=10M status=progress`)
2. Mount SD Card: `sudo mount /dev/mmcblk0p1 /mnt`
3. Copy u-boot.bin: `sudo cp u-boot.bin /mnt/`
4. Copy MilvusVisor: `sudo cp -r /path/to/MlivusVisor/bin/EFI /mnt`
5. Copy boot.scr: `sudo cp boot.scr /mnt/`
6. Modify config.txt: `sudo sed -i '/arm_64bit=1/akernel=u-boot.bin' /mnt/config.txt`
7. Modify cmdline.txt: `sudo sed -i -e 's/console=serial0,115200 console=tty1//g' /mnt/cmdline.txt`
8. Enable UART(
   Optional): `sudo sed -i '/arm_64bit=1/adtoverlay=miniuart-bt\ncore_freq=250' /mnt/config.txt && sudo sed -i -e 's/quiet/console=ttyAMA0/g' /mnt/cmdline.txt`
9. Unmount: `sudo umount /mnt`
