// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! ACPI Table Protection from store access
//!

use common::acpi::{RSDP, XSDT, XSDT_STRUCT_SIZE};
use common::{STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE};

use crate::memory_hook::{
    add_memory_store_access_handler, StoreAccessHandlerEntry, StoreHookResult,
};
use crate::paging::add_memory_access_trap;
use crate::StoredRegisters;

const EXCEPT_TABLE: [&[u8; 4]; 0] = [];

pub fn init_table_protection(rsdp_address: usize) {
    /* Assume table validation check is done */
    register_acpi_table(
        rsdp_address,
        Some(unsafe { (*(rsdp_address as *const RSDP)).length }),
    );
    let xsdt = unsafe { &*((*(rsdp_address as *const RSDP)).xsdt_address as *const XSDT) };
    register_acpi_table(xsdt as *const _ as usize, None);
    let mut is_dsdt_processed = false;

    'table_loop: for table_index in 0..((xsdt.length as usize - XSDT_STRUCT_SIZE) >> 3) {
        let table_address = unsafe {
            *((xsdt as *const _ as usize + XSDT_STRUCT_SIZE + (table_index << 3)) as *const u64)
        } as usize;
        let signature = unsafe { &*(table_address as *const [u8; 4]) };

        for e in EXCEPT_TABLE {
            if *signature == *e {
                continue 'table_loop;
            }
        }

        if *signature == *b"DSDT" {
            if !is_dsdt_processed {
                register_acpi_table(table_address, None);
                is_dsdt_processed = true;
            }
        } else if *signature == *b"FACP" && !is_dsdt_processed {
            register_acpi_table(table_address, None);
            let x_dsdt_address = unsafe { *((table_address + 140) as *const u64) };
            if x_dsdt_address != 0 {
                register_acpi_table(x_dsdt_address as usize, None);
                is_dsdt_processed = true;
            } else {
                let dsdt_address = unsafe { *((table_address + 40) as *const u32) };
                if dsdt_address != 0 {
                    register_acpi_table(dsdt_address as usize, None);
                    is_dsdt_processed = true;
                }
            }
        } else {
            register_acpi_table(table_address, None);
        }
    }
}

fn register_acpi_table(table_address: usize, table_length: Option<u32>) {
    let table_length =
        table_length.unwrap_or_else(|| unsafe { *((table_address + 4) as *const u32) });
    let aligned_table_address = table_address & STAGE_2_PAGE_MASK;
    let aligned_table_length =
        (((table_length as usize) + (table_address - aligned_table_address) - 1)
            & STAGE_2_PAGE_MASK)
            + STAGE_2_PAGE_SIZE;

    add_memory_access_trap(aligned_table_address, aligned_table_length, true, false)
        .expect("Failed to add memory trap");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        table_address,
        table_length as usize,
        0,
        acpi_table_store_handler,
    ))
    .expect("Failed to add ACPI table store handler");
    println!(
        "Protect {}({:#X}~{:#X}) from store access",
        core::str::from_utf8(unsafe { &*(table_address as *const [u8; 4]) }).unwrap_or("????"),
        aligned_table_address,
        aligned_table_address + aligned_table_length
    );
}

pub fn acpi_table_store_handler(
    _: usize,
    _: &mut StoredRegisters,
    _: u8,
    _: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    StoreHookResult::Cancel
}
