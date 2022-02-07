# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

MAKE = make -C
COMMON_MODULE = common
UEFI_MODULE = uefi
BOOTLOADER = hypervisor_bootloader
BOOTLOADER_ARCH = aarch64-uefi
KERNEL = hypervisor_kernel
KERNEL_ARCH = aarch64-none
CP = cp
MKDIR = mkdir -p
QEMU = qemu-system-aarch64
RM = rm -rf
MOUNT = mount
UMOUNT = umount
QEMU_EFI ?= QEMU_EFI.fd

all:  bootloader kernel
	$(MKDIR) bin/EFI/BOOT/
	$(CP) $(BOOTLOADER)/target/$(BOOTLOADER_ARCH)/release/$(BOOTLOADER) bin/EFI/BOOT/BOOTAA64.EFI
	$(CP) $(KERNEL)/target/$(KERNEL_ARCH)/release/$(KERNEL) bin/EFI/BOOT/$(KERNEL)

bootloader: .FORCE
	$(MAKE) $(BOOTLOADER)

kernel: .FORCE
	$(MAKE) $(KERNEL)

clean:
	$(RM) bin
	$(MAKE) $(COMMON_MODULE) clean
	$(MAKE) $(UEFI_MODULE) clean
	$(MAKE) $(BOOTLOADER) clean
	$(MAKE) $(KERNEL) clean

fmt:
	$(MAKE) $(COMMON_MODULE) fmt
	$(MAKE) $(UEFI_MODULE) fmt
	$(MAKE) $(BOOTLOADER) fmt
	$(MAKE) $(KERNEL) fmt

run:  all
	$(QEMU) -m 1G -cpu cortex-a53 -machine virt-2.12,virtualization=on -smp 4 -nographic -bios $(QEMU_EFI) -drive file=fat:rw:bin/,format=raw,media=disk

debug:  all
	$(QEMU) -m 1G -cpu cortex-a53 -machine virt-2.12,virtualization=on -smp 4 -monitor stdio -bios $(QEMU_EFI) -drive file=fat:rw:bin/,format=raw,media=disk

write:
	$(MOUNT) $(DEVICE) /mnt
	$(CP) bin/EFI/BOOT/BOOTAA64.EFI /mnt/EFI/BOOT/BOOTAA64.EFI
	$(CP) bin/EFI/BOOT/$(KERNEL) /mnt/EFI/BOOT/$(KERNEL)
	$(UMOUNT) /mnt

.FORCE:
