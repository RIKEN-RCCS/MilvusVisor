// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use crate::paging::map_address;

use common::acpi::get_acpi_table;
use common::{EcamInfo, PAGE_MASK};

pub fn detect_pci_space(rsdp: usize) -> Option<EcamInfo> {
    use core::ptr::read_unaligned;
    let mcfg = get_acpi_table(rsdp, b"MCFG");
    if let Err(e) = mcfg {
        println!("Failed to get MCFG table: {:?}", e);
        return None;
    }
    let mcfg = mcfg.unwrap();
    /* Currently, supporting only one ECAM Address */
    let ecam_address = unsafe { read_unaligned((mcfg + 44) as *const u64) } as usize;
    let start_bus = unsafe { read_unaligned((mcfg + 54) as *const u8) };
    let end_bus = unsafe { read_unaligned((mcfg + 55) as *const u8) };
    println!(
        "ECAM: BaseAddress: {:#X}, Bus: {:#X} ~ {:#X}",
        ecam_address, start_bus, end_bus
    );
    assert_eq!(ecam_address & !PAGE_MASK, 0);
    map_address(
        ecam_address,
        ecam_address,
        ((1 + (end_bus - start_bus) as usize) << 20) - 1,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map ECAM Space");
    Some(EcamInfo {
        address: ecam_address,
        start_bus,
        end_bus,
    })
}
