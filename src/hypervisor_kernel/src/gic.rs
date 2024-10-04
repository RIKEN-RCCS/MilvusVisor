// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use core::ptr::{read_volatile, write_volatile};

use common::acpi::{get_acpi_table, madt::MADT};
use common::paging::{page_align_up, stage2_page_align_up};
use common::{cpu, GeneralPurposeRegisters, PAGE_SIZE};

use crate::memory_hook::*;
use crate::paging::{add_memory_access_trap, map_address, remove_memory_access_trap};

const GICR_MAP_SIZE: usize = 0x1000;

const GICR_CTLR: usize = 0x0000;
const GICR_CTLR_RWP: u32 = 1 << 3;
const GICR_CTLR_ENABLE_LPIS: u32 = 1;

const GICR_WAKER: usize = 0x0014;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;

const GICR_PROPBASER: usize = 0x0070;
const GICR_PROPBASER_PTZ: u64 = 1 << 62;

const GICD_CTLR: usize = 0x00;
#[cfg(feature = "virtio")]
const GICD_ISPENDR: usize = 0x0200;
#[cfg(feature = "fast_restore")]
const GICD_SGIR: usize = 0xF00;
#[cfg(feature = "fast_restore")]
const GICD_CPENDSGIR: usize = 0xF10;
const GICD_ICPIDR2: usize = 0xFE8;

const GITS_CTLR: usize = 0x00;
const GITS_CTLR_ENABLED: u32 = 0x01;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;

static mut GIC_DISTRIBUTOR_BASE_ADDRESS: usize = 0;
static mut GIC_VERSION: u8 = 0;

pub fn init_gic(acpi_address: usize) {
    if let Ok(table) = get_acpi_table(acpi_address, &MADT::SIGNATURE) {
        let table = unsafe { &*(table as *const MADT) };
        if let Some((mut version, base)) = table.get_gic_distributor_address() {
            if base != 0 && version == 0 {
                version = ((unsafe { read_volatile((base + GICD_ICPIDR2) as *const u32) } >> 4)
                    & 0b1111) as u8;
            }
            unsafe {
                GIC_VERSION = version;
                GIC_DISTRIBUTOR_BASE_ADDRESS = base;
            }
        }
    }
}

#[cfg(feature = "virtio")]
pub fn set_interrupt_pending(int_id: u32) {
    let distributor = unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS };
    if distributor == 0 {
        println!("Distributor is not available.");
        return;
    }
    let register_index = ((int_id / u32::BITS) as usize) * core::mem::size_of::<u32>();
    let register_offset = int_id & (u32::BITS - 1);
    unsafe {
        write_volatile(
            (distributor + GICD_ISPENDR + register_index) as *mut u32,
            1 << register_offset,
        )
    };
}

#[cfg(feature = "fast_restore")]
pub fn broadcast_sgi() {
    let distributor = unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS };
    let version = unsafe { GIC_VERSION };
    if distributor == 0 {
        println!("Distributor is not available.");
        return;
    } else if version == 0 {
        println!("Failed to detect the GIC version");
        return;
    }

    match version {
        1 | 2 => {
            unsafe { write_volatile((distributor + GICD_CTLR) as *mut u32, 0b11) };
            unsafe {
                write_volatile(
                    (distributor + GICD_SGIR) as *mut u32,
                    1 << 24, /* Broadcast */
                )
            };
        }
        3 | 4 => {
            /* TODO: check if register access was enabled. */
            cpu::set_icc_sgi1r_el1(1 << 40 /* Broadcast */);
            cpu::set_icc_sgi0r_el1(1 << 40 /* Broadcast */);
        }
        _ => {
            println!("Unsupported GIC version: {version}");
        }
    }
}

#[cfg(feature = "fast_restore")]
pub fn remove_sgi() {
    let distributor = unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS };
    let version = unsafe { GIC_VERSION };
    if distributor == 0 {
        println!("Distributor is not available.");
        return;
    } else if version == 0 {
        println!("Failed to detect the GIC version");
        return;
    }

    match version {
        2 | 3 | 4 => {
            for i in 0..4 {
                let r =
                    (distributor + GICD_CPENDSGIR + i * core::mem::size_of::<u32>()) as *mut u32;
                unsafe { write_volatile(r, read_volatile(r)) };
            }
        }
        _ => {
            println!("Unsupported GIC version: {version}");
        }
    }
}

#[cfg(feature = "fast_restore")]
pub fn restore_gic(acpi_address: usize) {
    // TODO: Discovery Base Address
    if let Ok(table) = get_acpi_table(acpi_address, &MADT::SIGNATURE) {
        let table = unsafe { &*(table as *const MADT) };

        for e in table.get_gic_its_list() {
            map_address(e, e, PAGE_SIZE, true, true, false, true).expect("Failed to map ITS");
            unsafe { write_volatile((e + GITS_CTLR) as *mut u32, 0) };
            while unsafe { read_volatile((e + GITS_CTLR) as *const u32) & GITS_CTLR_ENABLED } != 0 {
                core::hint::spin_loop();
            }
            unsafe { write_volatile((e + GITS_CTLR) as *mut u32, GITS_CTLR_QUIESCENT) };
        }

        if unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS } != 0 {
            unsafe { write_volatile((GIC_DISTRIBUTOR_BASE_ADDRESS + GICD_CTLR) as *mut u32, 0) };
        } else {
            println!("DistributorBase is zero");
        }

        for e in table.get_gic_list() {
            let redistributor_base = e.get_gic_redistributor_base_address();
            if redistributor_base == 0 {
                continue;
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
                add_memory_load_access_handler(LoadAccessHandlerEntry::new(
                    redistributor_base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    0,
                    gic_redistributor_fast_restore_load_handler,
                ))
                .expect("Failed to add load handler");
                add_memory_store_access_handler(StoreAccessHandlerEntry::new(
                    redistributor_base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    0,
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
    _: &mut GeneralPurposeRegisters,
    _: u8,
    _: bool,
    _: bool,
    _: &LoadAccessHandlerEntry,
) -> LoadHookResult {
    let offset = accessing_address & (GICR_MAP_SIZE - 1);
    match offset {
        GICR_CTLR => LoadHookResult::Data(
            (unsafe { read_volatile(accessing_address as *const u32) } & !GICR_CTLR_ENABLE_LPIS)
                as u64,
        ),
        _ => LoadHookResult::PassThrough,
    }
}

fn gic_redistributor_fast_restore_store_handler(
    accessing_address: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    let base = accessing_address & !(GICR_MAP_SIZE - 1);
    let offset = accessing_address & (GICR_MAP_SIZE - 1);
    match offset {
        GICR_CTLR => {
            if (data & (GICR_CTLR_ENABLE_LPIS as u64)) != 0 {
                pr_debug!("Remove the trap of GIC Redistributor");
                remove_memory_access_trap(base, stage2_page_align_up(GICR_MAP_SIZE))
                    .expect("Failed to remove the trap GIC Register");
                remove_memory_load_access_handler(LoadAccessHandlerEntry::new(
                    base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    0,
                    gic_redistributor_fast_restore_load_handler,
                ))
                .expect("Failed to remove load handler");
                remove_memory_store_access_handler(StoreAccessHandlerEntry::new(
                    base,
                    stage2_page_align_up(GICR_MAP_SIZE),
                    0,
                    gic_redistributor_fast_restore_store_handler,
                ))
                .expect("Failed to remove store handler");
            }
            StoreHookResult::PassThrough
        }
        GICR_PROPBASER => {
            let original_data = unsafe { read_volatile(accessing_address as *const u64) };
            assert_eq!(original_data & !GICR_PROPBASER_PTZ, data);
            StoreHookResult::Cancel
        }
        _ => StoreHookResult::PassThrough,
    }
}
