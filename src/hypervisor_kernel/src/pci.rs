// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! PCI
//!

use crate::{drivers, paging};
use common::PAGE_SIZE;

pub fn init_pci(ecam_address: usize, start_bus_number: u8, end_bus_number: u8) {
    for bus in start_bus_number..end_bus_number {
        for device in 0..32 {
            let vendor_id = get_configuration_space_data(ecam_address, bus, device, 0, 0, 2) as u16;
            if vendor_id == 0xffff {
                continue;
            }
            let device_id = get_configuration_space_data(ecam_address, bus, device, 0, 2, 2) as u16;

            println!(
                "{:X}:{:X} VendorId: {:#X}, DeviceId: {:#X}",
                bus, device, vendor_id, device_id
            );
            /* TODO: call handlers dynamically */
            if vendor_id == drivers::i210::VENDOR_ID && device_id == drivers::i210::DEVICE_ID {
                #[cfg(feature = "i210")]
                drivers::i210::setup_device(ecam_address, bus, device, 0);
            } else if vendor_id == drivers::mt27800::VENDOR_ID
                && device_id == drivers::mt27800::DEVICE_ID
            {
                #[cfg(feature = "mt27800")]
                drivers::mt27800::setup_device(ecam_address, bus, device, 0);
            } else if cfg!(feature = "shared_memory") && vendor_id == 0x1af4 && device_id == 0x1110
            {
                // ivshmemによる共有メモリ
                let bar2 = get_configuration_space_data(ecam_address, bus, device, 0, 0x18, 4);
                println!("BAR2: {:#X}", bar2);
                // is_64bit
                let addr = if bar2 & 0x4 != 0 {
                    let bar3 = get_configuration_space_data(ecam_address, bus, device, 0, 0x1c, 4);
                    println!("BAR3: {:#X}", bar3);
                    let addr = ((bar3 as u64) << 32) | ((bar2 as u64) & 0xfffffff0);
                    println!("Addr: {:#X}", addr);
                    addr
                } else {
                    let addr = bar2 & 0xfffffff0;
                    println!("Addr: {:#X}", addr);
                    addr as u64
                };
                paging::map_address(
                    addr as usize,
                    addr as usize,
                    PAGE_SIZE,
                    true,
                    true,
                    false,
                    true,
                )
                .expect("Failed to map ivshmem");
                // enable memory access (enable MSE bit in COMMAND register)
                write_configuration_space_data(ecam_address, bus, device, 0, 0x4, 4, 0x2);
            }
            for function in 1..8 {
                let vendor_id =
                    get_configuration_space_data(ecam_address, bus, device, function, 0, 2) as u16;
                if vendor_id == 0xffff {
                    continue;
                }
                println!(
                    "  {:X}:{:X}:{:X} VenderId: {:#X}",
                    bus, device, function, vendor_id
                );
                for i in 0..6 {
                    println!(
                        "BaseAddress{}: {:#X}",
                        i,
                        get_configuration_space_data(
                            ecam_address,
                            bus,
                            device,
                            function,
                            0x10 + (i << 2),
                            4
                        )
                    );
                }
            }
        }
    }
}

pub fn get_configuration_space_data(
    base_address: usize,
    bus: u8,
    device: u8,
    function: u8,
    offset: usize,
    size: u8,
) -> u32 {
    let address = get_ecam_target_address(base_address, bus, device, function);
    let aligned_offset = offset & !0b11;
    let data = unsafe { *((address + aligned_offset) as *const u32) };
    let byte_offset = (offset & 0b11) as u8;
    assert!(byte_offset + size <= 4);
    if size == 4 {
        data
    } else {
        (data >> (byte_offset << 3)) & ((1 << (size << 3)) - 1)
    }
}

pub fn write_configuration_space_data(
    base_address: usize,
    bus: u8,
    device: u8,
    function: u8,
    offset: usize,
    size: u8,
    data: u32,
) {
    let address = get_ecam_target_address(base_address, bus, device, function);
    let aligned_offset = offset & !0b11;
    let mut value = unsafe { *((address + aligned_offset) as *mut u32) };
    let byte_offset = (offset & 0b11) as u8;
    assert!(byte_offset + size <= 4);
    if size == 4 {
        value = data;
    } else {
        value &= !(((1 << (size << 3)) - 1) << (byte_offset << 3));
        value |= (data & ((1 << (size << 3)) - 1)) << (byte_offset << 3);
    }
    unsafe { *((address + aligned_offset) as *mut u32) = value };
}

pub fn get_ecam_target_address(base_address: usize, bus: u8, device: u8, function: u8) -> usize {
    assert!(device < 32);
    assert!(function < 8);

    base_address
        + (((bus as usize) << 20) | ((device as usize) << 15) | ((function as usize) << 12))
}
