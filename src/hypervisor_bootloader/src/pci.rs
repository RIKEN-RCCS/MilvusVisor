// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use crate::paging::map_address;

use common::acpi::get_acpi_table;
use common::EcamInfo;

pub fn detect_pci_space(rsdp: usize) -> Option<EcamInfo> {
    let mcfg = get_acpi_table(rsdp, b"MCFG");
    if let Err(e) = mcfg {
        println!("Failed to get MCFG table: {:?}", e);
        return None;
    }
    let mcfg = mcfg.unwrap();
    /* Currently, supporting only one ECAM Address */
    let pcie_ecam_address = unsafe { *((mcfg + 44) as *const u64) } as usize;
    let start_bus_number = unsafe { *((mcfg + 54) as *const u8) };
    let end_bus_number = unsafe { *((mcfg + 55) as *const u8) };
    println!(
        "ECAM Address: {:#X}, Start: {:#X}, End: {:#X}",
        pcie_ecam_address, start_bus_number, end_bus_number
    );
    assert_eq!(pcie_ecam_address & (8 * 1024 * 1024 - 1), 0);
    map_address(
        pcie_ecam_address,
        pcie_ecam_address,
        ((1 + end_bus_number as usize) << 20) - 1,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map ECAM Space");
    return Some(EcamInfo {
        address: pcie_ecam_address,
        start_bus: start_bus_number,
        end_bus: end_bus_number,
    });
}
