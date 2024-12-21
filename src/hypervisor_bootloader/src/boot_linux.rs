// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Booting Multi Linux
//!

use common::*;

use uefi::file;

use crate::asm;

/// **Depend on the machine**: The base number of INTID for virtio-net
const AP_VIRTIO_INTID_BASE: u32 = 32 /* SPI Base */ + 0x10;

#[repr(C)]
struct LinuxHeader {
    code0: u32,
    code1: u32,
    text_offset: u64,
    image_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,
}

pub fn boot_linux(boot_mpidr_el1: u64) {
    const RAM_SIZE: usize = 0x40000000;
    const ALIGN_SIZE: usize = 1 << 21;

    let image_handle = unsafe { crate::IMAGE_HANDLE };
    let b_s = unsafe { &*(*crate::SYSTEM_TABLE).efi_boot_services };
    let root_protocol =
        file::EfiFileProtocol::open_root_dir(image_handle, b_s).expect("Failed to open the volume");
    let mut kernel_name_utf16: [u16; LINUX_PATH.len() + 1] = [0; LINUX_PATH.len() + 1];
    let mut initramfs_name_utf16: [u16; LINUX_INITRAMFS.len() + 1] = [0; LINUX_INITRAMFS.len() + 1];

    /* Allocate RAM */
    let ram_address = b_s
        .alloc_highest_memory(RAM_SIZE >> 12, usize::MAX)
        .expect("Failed to allocate memory");
    let dtb_address = ram_address;

    /* Load Kernel */
    println!("Loading Kernel...");
    let kernel_address =
        ((dtb_address + crate::virt::DTB_VIRT.len() - 1) & !(ALIGN_SIZE - 1)) + ALIGN_SIZE;
    for (i, e) in LINUX_PATH.encode_utf16().enumerate() {
        kernel_name_utf16[i] = e;
    }
    let linux_protocol = file::EfiFileProtocol::open_file(root_protocol, &kernel_name_utf16)
        .expect("Failed to open the hypervisor binary file");
    let kernel_size = linux_protocol.get_file_info().unwrap().file_size;
    let read_size = linux_protocol
        .read(kernel_address as *mut u8, kernel_size)
        .unwrap();
    assert_eq!(read_size, kernel_size);

    let header = unsafe { &*(kernel_address as *const LinuxHeader) };
    if header.magic != 0x644d_5241 {
        panic!("Invalid Kernel Magic: {:#X}", header.magic);
    }
    let mut text_offset = header.text_offset;
    let image_size = header.image_size;
    if image_size == 0 {
        text_offset = 0x80000;
    }
    let boot_address = kernel_address + text_offset as usize;

    /* Load Initramfs */
    println!("Loading initramfs...");
    let initramfs_address =
        ((kernel_address + kernel_size - 1) & !(ALIGN_SIZE - 1)) + ALIGN_SIZE * 2;
    for (i, e) in LINUX_INITRAMFS.encode_utf16().enumerate() {
        initramfs_name_utf16[i] = e;
    }
    let initramfs_protocol = file::EfiFileProtocol::open_file(root_protocol, &initramfs_name_utf16)
        .expect("Failed to open the hypervisor binary file");
    let initramfs_size = initramfs_protocol.get_file_info().unwrap().file_size;
    let read_size = initramfs_protocol
        .read(initramfs_address as *mut u8, initramfs_size)
        .unwrap();
    assert_eq!(read_size, initramfs_size);
    let initramfs_end = initramfs_address + initramfs_size;

    /* Load DTB */
    println!("Loading DTB...");
    unsafe {
        core::ptr::copy_nonoverlapping(
            crate::virt::DTB_VIRT.as_ptr(),
            dtb_address as *mut u8,
            crate::virt::DTB_VIRT.len(),
        )
    };
    /* Modify DTB */
    /* Modify RAM */
    let dtb_analyzer = crate::dtb::DtbAnalyser::new(dtb_address).expect("Failed to parse DTB");
    let mut ram_node = dtb_analyzer.get_root_node().get_search_holder().unwrap();
    let ram_node = ram_node
        .search_next_device_by_node_name(b"memory", &dtb_analyzer)
        .unwrap()
        .unwrap();
    ram_node
        .edit_offset(ram_address)
        .expect("Failed to edit ram offset");
    ram_node
        .edit_reg(&dtb_analyzer, 0, ram_address, RAM_SIZE)
        .expect("Failed to edit ram reg");

    /* Modify Initramfs */
    let mut chosen_node = dtb_analyzer.get_root_node().get_search_holder().unwrap();
    let chosen_node = chosen_node
        .search_next_device_by_node_name(b"chosen", &dtb_analyzer)
        .unwrap()
        .unwrap();
    chosen_node
        .edit_address_property(&dtb_analyzer, b"linux,initrd-start", initramfs_address)
        .expect("Failed to modify initrd-start");
    chosen_node
        .edit_address_property(&dtb_analyzer, b"linux,initrd-end", initramfs_end)
        .expect("Failed to modify initrd-end");

    /* Modify CPU */
    let cpu_node = dtb_analyzer
        .get_root_node()
        .get_search_holder()
        .unwrap()
        .search_next_device_by_node_name(b"cpu", &dtb_analyzer)
        .unwrap()
        .unwrap();
    cpu_node
        .edit_reg(&dtb_analyzer, 0, boot_mpidr_el1 as usize, 0)
        .expect("Failed to edit CPU's reg");

    /* Modify VirtIO-MMIO */
    let virtio_int_id = AP_VIRTIO_INTID_BASE + (boot_mpidr_el1 as u32 - 1);
    let virtio_node = dtb_analyzer
        .get_root_node()
        .get_search_holder()
        .unwrap()
        .search_next_device_by_node_name(b"virtio_mmio", &dtb_analyzer)
        .unwrap()
        .unwrap();
    virtio_node
        .edit_property(
            &dtb_analyzer,
            b"interrupts",
            1,
            virtio_int_id - 32, /* SPI Base */
        )
        .expect("Failed to edit Virtio interrupts");

    println!("Boot Linux...");
    let linux_info = LinuxBootInformation {
        ram_physical_address: ram_address,
        ram_size: RAM_SIZE,
        boot_address,
        dtb_address,
        mpidr_el1: boot_mpidr_el1,
        virtio_int_id,
    };
    unsafe { asm!("hvc 0xFFE0", in("x0") &linux_info as *const _ as usize) };
}
