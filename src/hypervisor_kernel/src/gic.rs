// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use core::ptr::{read_volatile, write_volatile};

use common::acpi::{get_acpi_table, madt::MADT};
use common::paging::{page_align_up, stage2_page_align_up};
use common::{GeneralPurposeRegisters, PAGE_SIZE, cpu};

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

const GICD_MAP_SIZE: usize = 0x10000;

const GICD_CTLR: usize = 0x00;
#[cfg(feature = "virtio")]
const GICD_ISPENDR: usize = 0x0200;
#[cfg(feature = "fast_restore")]
const GICD_SGIR: usize = 0xF00;
#[cfg(feature = "fast_restore")]
const GICD_CPENDSGIR: usize = 0xF10;
const GICD_ICPIDR2: usize = 0xFE8;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ICENABLER: usize = 0x0180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ICFGR: usize = 0xC00;
const GICD_IGRPMODR: usize = 0x0D00;
const GICD_IROUTER: usize = 0x6000;

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
    let register_index = ((int_id / u32::BITS) as usize) * size_of::<u32>();
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
        2..=4 => {
            for i in 0..4 {
                let r = (distributor + GICD_CPENDSGIR + i * size_of::<u32>()) as *mut u32;
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

static mut GICD_PROTECT_LIST: [(u64 /* Affinity */, u32 /* INTID */); 8] = [(0, 0); 8];

pub fn add_gic_distributor_protector(target_mpidr: u64, int_id: u32) {
    let mut is_first = true;
    for e in unsafe { (&raw mut GICD_PROTECT_LIST).as_mut().unwrap() }.iter_mut() {
        if e.0 == 0 && e.1 == 0 {
            e.0 = cpu::mpidr_to_affinity(target_mpidr);
            e.1 = int_id;
            break;
        }
        is_first = false;
    }
    let gic_distributor_address = unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS };
    let int_id = int_id as usize;
    assert_ne!(
        gic_distributor_address, 0,
        "GIC Distributor is not available"
    );
    add_memory_access_trap(gic_distributor_address, GICD_MAP_SIZE, true, false)
        .expect("Failed to add access trap of GIC Distributor");

    println!("Protect INTID#{int_id} for CPU#{:X}", target_mpidr);

    if !is_first {
        return;
    }

    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_CTLR,
        4,
        gic_distributor_address,
        gic_ctlr_protect_handler,
    ))
    .expect("Failed to protect GICD_CTLR");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_IGROUPR,
        4 * 32,
        gic_distributor_address,
        gic_igroupr_protect_handler,
    ))
    .expect("Failed to protect GICD_IGROUPR");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_ICENABLER,
        4 * 32,
        gic_distributor_address,
        gic_icenabler_protect_handler,
    ))
    .expect("Failed to protect GICD_ICENABLER");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_IPRIORITYR,
        4 * 255,
        gic_distributor_address,
        gic_ipriorityr_protect_handler,
    ))
    .expect("Failed to protect GICD_IPRIORITYR");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_ICFGR,
        4 * 64,
        gic_distributor_address,
        gic_icfgr_protect_handler,
    ))
    .expect("Failed to protect GICD_ICFGR");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_IGRPMODR,
        4 * 32,
        gic_distributor_address,
        gic_igrpmodr_protect_handler,
    ))
    .expect("Failed to protect GICD_IGRPMODR");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address + GICD_IROUTER,
        8 * 1020,
        gic_distributor_address,
        gic_irouter_protect_handler,
    ))
    .expect("Failed to protect GICD_IROUTER");
    /* Currently, handlers are sorted by the registration order.
       Therefore, this handler will be called as default handler of GIC.
    */
    fn gic_default_handler(
        _: usize,
        _: &mut GeneralPurposeRegisters,
        _: u8,
        _: u64,
        _: &StoreAccessHandlerEntry,
    ) -> StoreHookResult {
        StoreHookResult::PassThrough
    }
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        gic_distributor_address,
        GICD_MAP_SIZE,
        gic_distributor_address,
        gic_default_handler,
    ))
    .unwrap();
}

pub fn add_gic_distributor_protector_ap() {
    let gic_distributor_address = unsafe { GIC_DISTRIBUTOR_BASE_ADDRESS };
    assert_ne!(
        gic_distributor_address, 0,
        "GIC Distributor is not available"
    );
    add_memory_access_trap(gic_distributor_address, GICD_MAP_SIZE, true, false)
        .expect("Failed to add access trap of GIC Distributor");
}

fn gic_ctlr_protect_handler(
    accessing_address: usize,
    _: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
    _e: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    assert_eq!(access_size, 0b10);
    let original_data = unsafe { read_volatile(accessing_address as *const u32) };
    pr_debug!(
        "GIC: {:#X} <= {:#X}({{original: {:#X}, writing: {:#X}}})",
        accessing_address - _e.get_data(),
        data | (original_data as u64),
        original_data,
        data
    );
    StoreHookResult::Data(data | (original_data as u64))
}

fn create_masked_data(
    _distributor_address: usize,
    accessing_address: usize,
    access_size: u8,
    mask: u64,
    writing_dara: u64,
    should_ignore_original_data: bool,
) -> StoreHookResult {
    if mask == 0 {
        return StoreHookResult::PassThrough;
    }
    let original_data = if should_ignore_original_data {
        0
    } else {
        unsafe {
            match access_size {
                0b00 => read_volatile(accessing_address as *const u8) as u64,
                0b01 => read_volatile(accessing_address as *const u16) as u64,
                0b10 => read_volatile(accessing_address as *const u32) as u64,
                0b11 => read_volatile(accessing_address as *const u64),
                _ => unreachable!(),
            }
        }
    };
    let masked_data = writing_dara & !mask;
    let result = masked_data | (original_data & mask);
    pr_debug!(
        "GIC: {:#X} <= {:#X}({{original: {:#X}, writing: {:#X}, mask: {:#b}}})",
        accessing_address - _distributor_address,
        result,
        original_data,
        writing_dara,
        mask
    );
    StoreHookResult::Data(result)
}

macro_rules! create_protect_handler {
    ($handler_name:ident, $expected_access_size:expr, $register_base:expr, $register_bits:expr, $num_of_fields: expr,
     $bits_per_fields:expr, $mask_pattern:expr, $should_ignore_original_data:expr) => {
        fn $handler_name(
            accessing_address: usize,
            _: &mut GeneralPurposeRegisters,
            access_size: u8,
            data: u64,
            handler: &StoreAccessHandlerEntry,
        ) -> StoreHookResult {
            if access_size != $expected_access_size {
                println!("Access Size is not aligned");
                return StoreHookResult::Cancel;
            }
            let offset = accessing_address & (GICD_MAP_SIZE - 1);
            let register_offset = offset - $register_base;
            let affinity = cpu::mpidr_to_affinity(cpu::get_mpidr_el1());
            let int_id_start = ((register_offset / $register_bits) * $num_of_fields) as u32;
            let int_id_end = int_id_start + $num_of_fields - 1;
            let mut register_mask = 0u64;

            for e in unsafe { (&raw const GICD_PROTECT_LIST).as_ref().unwrap() }.iter() {
                if int_id_start <= e.1 && e.1 <= int_id_end {
                    if e.0 == affinity {
                        continue;
                    }
                    register_mask |= $mask_pattern << ((e.1 - int_id_start) * $bits_per_fields);
                }
            }
            create_masked_data(
                handler.get_data(),
                accessing_address,
                access_size,
                register_mask,
                data,
                $should_ignore_original_data,
            )
        }
    };
}

create_protect_handler!(
    gic_icenabler_protect_handler,
    0b10,
    GICD_ICENABLER,
    4,
    32,
    1,
    1,
    true
);

create_protect_handler!(
    gic_igroupr_protect_handler,
    0b10,
    GICD_IGROUPR,
    4,
    32,
    1,
    1,
    false
);

create_protect_handler!(
    gic_ipriorityr_protect_handler,
    0b10,
    GICD_IPRIORITYR,
    4,
    4,
    8,
    0xFF,
    false
);

create_protect_handler!(
    gic_icfgr_protect_handler,
    0b10,
    GICD_ICFGR,
    4,
    16,
    2,
    0b11,
    false
);

create_protect_handler!(
    gic_igrpmodr_protect_handler,
    0b10,
    GICD_IGRPMODR,
    4,
    32,
    1,
    1,
    false
);

create_protect_handler!(
    gic_irouter_protect_handler,
    0b11,
    GICD_IROUTER,
    8,
    1,
    64,
    u64::MAX,
    false
);
