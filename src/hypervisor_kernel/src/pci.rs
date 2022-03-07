// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! PCI
//!

use crate::drivers;

pub fn init_pci(ecam_address: usize, start_bus_number: u8, end_bus_number: u8) {
    for bus in start_bus_number..=end_bus_number {
        for device in 0..32 {
            let vendor_id = get_configuration_space_data(ecam_address, bus, device, 0, 0, 2) as u16;
            if vendor_id == 0xffff {
                continue;
            }
            let device_id = get_configuration_space_data(ecam_address, bus, device, 0, 2, 2) as u16;

            println!(
                "{:X}:{:X} VenderId: {:#X}, DeviceId: {:#X}",
                bus, device, vendor_id, device_id
            );
            /* TODO: 動的にハンドラ呼び出し */
            if vendor_id == drivers::i210::VENDOR_ID && device_id == drivers::i210::DEVICE_ID {
                drivers::i210::setup_device(ecam_address, bus, device, 0);
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
    return if size == 4 {
        data
    } else {
        (data >> (byte_offset << 3)) & ((1 << (size << 3)) - 1)
    };
}

pub fn get_ecam_target_address(base_address: usize, bus: u8, device: u8, function: u8) -> usize {
    assert!(device < 32);
    assert!(function < 8);

    base_address
        + (((bus as usize) << 20) | ((device as usize) << 15) | ((function as usize) << 12))
}
