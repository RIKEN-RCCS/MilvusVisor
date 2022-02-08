# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

MAKE = make -C
COMMON_MODULE = common
UEFI_MODULE = uefi
BOOTLOADER = hypervisor_bootloader
KERNEL = hypervisor_kernel
CP = cp
MKDIR = mkdir -p
QEMU = qemu-system-aarch64
RM = rm -rf
CARGO = cargo
CARGO_BUILD_OPTION = --release
MOUNT = mount
UMOUNT = umount
CD = cd
QEMU_EFI ?= QEMU_EFI.fd

all:  bootloader kernel
	$(MKDIR) bin/EFI/BOOT/
	$(CP) $(BOOTLOADER)/target/*/release/$(BOOTLOADER).efi bin/EFI/BOOT/BOOTAA64.EFI
	$(CP) $(KERNEL)/target/*/release/$(KERNEL) bin/EFI/BOOT/$(KERNEL)

bootloader: .FORCE
	$(CD) $(BOOTLOADER) && $(CARGO) build $(CARGO_BUILD_OPTION)

kernel: .FORCE
	$(CD) $(KERNEL) && $(CARGO) build $(CARGO_BUILD_OPTION)

clean:
	$(RM) bin
	$(CD) $(BOOTLOADER) && $(CARGO) clean
	$(CD) $(KERNEL) && $(CARGO) clean

fmt:
	$(CD) $(COMMON_MODULE) && $(CARGO) fmt
	$(CD) $(UEFI_MODULE) && $(CARGO) fmt
	$(CD) $(BOOTLOADER) && $(CARGO) fmt
	$(CD) $(KERNEL) && $(CARGO) fmt

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
