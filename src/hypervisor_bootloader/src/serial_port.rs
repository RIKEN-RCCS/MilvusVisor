// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use common::acpi::{get_acpi_table, GeneralAddressStructure};
use common::serial_port::{SerialPortInfo, SerialPortType};
use core::num::NonZeroUsize;

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
    let dtb_analyser = crate::dtb::DtbAnalyser::new(dtb_address);
    if let Err(_) = dtb_analyser {
        println!("Invalid DTB");
        return None;
    }
    let dtb_analyser = dtb_analyser.unwrap();
    let Ok(mut serial_node) = dtb_analyser.get_root_node().get_search_holder() else {
        println!("Failed to analysis the DTB");
        return None;
    };
    loop {
        match serial_node.search_next_device_by_compatible(
            &[b"arm,pl011", b"amlogic,meson-gx-uart", b"xlnx,xuartps"],
            &dtb_analyser,
        ) {
            Ok(Some((node, index))) => {
                if node.is_status_okay(&dtb_analyser) != Ok(Some(true)) {
                    println!("Device is not okay.");
                    continue;
                }

                let address = node.get_offset();
                return Some(SerialPortInfo {
                    physical_address: address,
                    virtual_address: address,
                    port_type: match index {
                        0 => SerialPortType::ArmPl011,
                        1 => SerialPortType::MesonGxUart,
                        2 => SerialPortType::XilinxUart,
                        _ => unreachable!(),
                    },
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

#[cfg(feature = "raspberrypi")]
pub fn detect_serial_port(
    _: Option<NonZeroUsize>,
    _: Option<NonZeroUsize>,
) -> Option<SerialPortInfo> {
    println!("MIDR_EL1; {:#X}", common::cpu::get_midr_el1());
    match (common::cpu::get_midr_el1() >> 4) & 0xFFF {
        /* Raspberry Pi 3 */
        0xD03 => Some(SerialPortInfo {
            physical_address: 0x3F201000,
            virtual_address: 0x3F201000,
            port_type: SerialPortType::ArmPl011,
        }),
        /* Raspberry Pi 4 */
        0xD08 => Some(SerialPortInfo {
            physical_address: 0xFE201000,
            virtual_address: 0xFE201000,
            port_type: SerialPortType::ArmPl011,
        }),
        _ => None,
    }
}

#[cfg(not(feature = "raspberrypi"))]
pub fn detect_serial_port(
    acpi_table: Option<NonZeroUsize>,
    dtb_address: Option<NonZeroUsize>,
) -> Option<SerialPortInfo> {
    if let Some(acpi_table) = acpi_table {
        let result = try_to_get_serial_info_from_acpi(acpi_table.get());

        if result.is_some() {
            return result;
        }
    }
    if let Some(dtb_address) = dtb_address {
        let result = try_to_get_serial_info_from_dtb(dtb_address.get());

        if result.is_some() {
            return result;
        }
    }

    println!("SerialPort is not found.");

    None
}
