// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use crate::memory_hook::{
    add_memory_load_hook_handler, add_memory_store_hook_handler, remove_memory_load_hook_handler,
    remove_memory_store_hook_handler, LoadAccessHandlerEntry, LoadHookResult,
    StoreAccessHandlerEntry, StoreHookResult,
};
use crate::paging::{add_memory_access_trap, map_address, remove_memory_access_trap};
use crate::StoredRegisters;

use common::acpi::{get_acpi_table, madt::MADT};
use common::paging::{page_align_up, stage2_page_align_up};
use common::PAGE_SIZE;

use core::ptr::{read_volatile, write_volatile};

const GICR_MAP_SIZE: usize = 0x1000;

const GICR_CTLR: usize = 0x0000;
const GICR_CTLR_RWP: u32 = 1 << 3;
const GICR_CTLR_ENABLE_LPIS: u32 = 1;

const GICR_WAKER: usize = 0x0014;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;

const GICR_PROPBASER: usize = 0x0070;
const GICR_PROPBASER_PTZ: u64 = 1 << 62;

const GICD_CTLR: usize = 0x00;

const GITS_CTLR: usize = 0x00;
const GITS_CTLR_ENABLED: u32 = 0x01;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;

pub fn restore_gic(acpi_address: usize) {
    // TODO: Discovery Base Address
    if let Ok(table) = get_acpi_table(acpi_address, b"APIC") {
        let table = unsafe { &*(table as *const MADT) };

        for e in table.get_gic_its_list() {
            map_address(e, e, PAGE_SIZE, true, true, false, true).expect("Failed to map ITS");
            unsafe { write_volatile((e + GITS_CTLR) as *mut u32, 0) };
            while unsafe { read_volatile((e + GITS_CTLR) as *const u32) & GITS_CTLR_ENABLED } != 0 {
                core::hint::spin_loop();
            }
            unsafe { write_volatile((e + GITS_CTLR) as *mut u32, GITS_CTLR_QUIESCENT) };
        }

        if let Some(distributor) = table.get_gic_distributor_address() {
            if distributor != 0 {
                unsafe { write_volatile((distributor + GICD_CTLR) as *mut u32, 0) };
            }
        } else {
            println!("DistributorBase is zero");
        }

        for e in table.get_gic_list() {
            let redistributor_base = e.gicr_base_address as usize;
            if redistributor_base == 0 {
                todo!()
            }
            map_address(
                redistributor_base,
                redistributor_base,
                page_align_up(GICR_MAP_SIZE),
                true,
                true,
                false,
                true,
            )
            .expect("Failed to map GIC Redistributor");

            let ctrl = (redistributor_base + GICR_CTLR) as *mut u32;
            while unsafe { read_volatile(ctrl) & GICR_CTLR_RWP } != 0 {
                core::hint::spin_loop();
            }
            unsafe { write_volatile(ctrl, 0) };
            while unsafe { read_volatile(ctrl) & GICR_CTLR_RWP } != 0 {
                core::hint::spin_loop();
            }
            if (unsafe { read_volatile(ctrl) } & GICR_CTLR_ENABLE_LPIS) != 0 {
                pr_debug!(
                    "GICR_CTLR::EnableLPIs became RES1(this behavior is IMPLEMENTATION DEFINED).\
                     Therefore, add trap to mask this bit until EL1 writes this bit 1."
                );
                add_memory_load_hook_handler(LoadAccessHandlerEntry::new(
                    redistributor_base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    gic_redistributor_fast_restore_load_handler,
                ))
                .expect("Failed to add load handler");
                add_memory_store_hook_handler(StoreAccessHandlerEntry::new(
                    redistributor_base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    gic_redistributor_fast_restore_store_handler,
                ))
                .expect("Failed to add store handler");
                add_memory_access_trap(
                    redistributor_base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    false,
                    false,
                )
                .expect("Failed to trap GIC Register");
            }

            unsafe {
                write_volatile(
                    (redistributor_base + GICR_WAKER) as *mut u32,
                    GICR_WAKER_PROCESSOR_SLEEP,
                )
            };
        }
    }
}

fn gic_redistributor_fast_restore_load_handler(
    accessing_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _is_64bit_register: bool,
    _is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()> {
    let offset = accessing_address & (GICR_MAP_SIZE - 1);
    match offset {
        GICR_CTLR => Ok(LoadHookResult::Data(
            (unsafe { read_volatile(accessing_address as *const u32) } & !GICR_CTLR_ENABLE_LPIS)
                as u64,
        )),
        _ => Ok(LoadHookResult::PassThrough),
    }
}

fn gic_redistributor_fast_restore_store_handler(
    accessing_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    let base = accessing_address & !(GICR_MAP_SIZE - 1);
    let offset = accessing_address & (GICR_MAP_SIZE - 1);
    match offset {
        GICR_CTLR => {
            if (data & (GICR_CTLR_ENABLE_LPIS as u64)) != 0 {
                pr_debug!("Remove the trap of GIC Redistributor");
                remove_memory_access_trap(base, stage2_page_align_up(GICR_MAP_SIZE))
                    .expect("Failed to remove the trap GIC Register");
                remove_memory_load_hook_handler(LoadAccessHandlerEntry::new(
                    base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    gic_redistributor_fast_restore_load_handler,
                ))
                .expect("Failed to remove load handler");
                remove_memory_store_hook_handler(StoreAccessHandlerEntry::new(
                    base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    gic_redistributor_fast_restore_store_handler,
                ))
                .expect("Failed to remove store handler");
            }
            Ok(StoreHookResult::PassThrough)
        }
        GICR_PROPBASER => {
            let original_data = unsafe { read_volatile(accessing_address as *const u64) };
            assert_eq!(original_data & !GICR_PROPBASER_PTZ, data);
            Ok(StoreHookResult::Cancel)
        }
        _ => Ok(StoreHookResult::PassThrough),
    }
}
