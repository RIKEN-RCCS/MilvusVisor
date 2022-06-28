// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use crate::{dtb, ACPI_20_TABLE_ADDRESS, DTB_ADDRESS};

use common::acpi::{get_acpi_table, GeneralAddressStructure};
use common::serial_port::{SerialPortInfo, SerialPortType};

fn try_to_get_serial_info_from_acpi(rsdp_address: usize) -> Option<SerialPortInfo> {
    let spcr = get_acpi_table(rsdp_address, b"SPCR");
    if let Err(e) = spcr {
        println!("SPCR is not found: {:?}", e);
        return None;
    }
    let table_address = spcr.unwrap();
    let serial_port_type = unsafe { *((table_address + 36) as *const u8) };
    let address =
        GeneralAddressStructure::new(unsafe { &*((table_address + 40) as *const [u8; 12]) });
    println!("SerialPort: {:#X?}(Type: {:#X})", address, serial_port_type);
    if address.get_address_type() != GeneralAddressStructure::SPACE_ID_SYSTEM_MEMORY {
        println!("Invalid Address Type");
        return None;
    }

    let port_type = match serial_port_type {
        0x03 => SerialPortType::ArmPl011,
        0x0E => SerialPortType::ArmSbsaGenericUart,
        _ => {
            println!("Unsupported Serial Port");
            return None;
        }
    };

    return Some(SerialPortInfo {
        physical_address: address.get_address() as usize,
        virtual_address: address.get_address() as usize,
        port_type,
    });
}

fn try_to_get_serial_info_from_dtb(dtb_address: usize) -> Option<SerialPortInfo> {
    let dtb_analyser = dtb::DtbAnalyser::new(dtb_address);
    if let Err(_) = dtb_analyser {
        println!("Invalid DTB");
        return None;
    }
    let dtb_analyser = dtb_analyser.unwrap();
    let dtb_search_holder = dtb_analyser.get_root_node().get_search_holder();
    if let Err(_) = dtb_search_holder {
        println!("Failed to analysis the DTB");
        return None;
    }

    let mut dtb_search_holder = dtb_search_holder.unwrap();

    loop {
        match dtb_search_holder
            .search_next_device_by_compatible(&["amlogic,meson-gx-uart".as_bytes()], &dtb_analyser)
        {
            Ok(Some((node, index))) => {
                if node.is_status_okay(&dtb_analyser) != Ok(Some(true)) {
                    println!("Device is not okay.");
                    continue;
                }
                assert_eq!(index, 0);
                let address = node.get_offset();
                println!("Found MesonGxUart at {:#X}", address);
                return Some(SerialPortInfo {
                    physical_address: address,
                    virtual_address: address,
                    port_type: SerialPortType::MesonGxUart,
                });
            }
            Ok(None) => break,
            Err(_) => {
                println!("Failed to analysis the DTB");
                break;
            }
        }
    }

    return None;
}

pub fn detect_serial_port() -> Option<SerialPortInfo> {
    if let Some(acpi_table) = unsafe { &ACPI_20_TABLE_ADDRESS } {
        let result = try_to_get_serial_info_from_acpi(*acpi_table);

        if result.is_some() {
            return result;
        }
    }
    if let Some(dtb_address) = unsafe { &DTB_ADDRESS } {
        let result = try_to_get_serial_info_from_dtb(*dtb_address);

        if result.is_some() {
            return result;
        }
    }

    println!("SerialPort is not found.");

    return None;
}
