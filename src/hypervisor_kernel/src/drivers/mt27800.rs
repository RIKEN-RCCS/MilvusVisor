// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Mellanox Technologies(R) MT27800
//!

use core::sync::atomic::{AtomicBool, Ordering};

use common::{bitmask, GeneralPurposeRegisters, STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE};

use crate::memory_hook::*;
use crate::paging;
use crate::pci::{get_configuration_space_data, get_ecam_target_address};

static mut CURRENT_EXPANSION_ROM_BAR: usize = 0;
static mut EXPANSION_ROM_SIZE: usize = 0;

pub const VENDOR_ID: u16 = 0x15b3;
pub const DEVICE_ID: u16 = 0x1017;

pub fn setup_device(ecam_address: usize, bus: u8, device: u8, function: u8) {
    let class_code = get_configuration_space_data(ecam_address, bus, device, function, 0x09, 3);
    println!(
        "MT27800 Infiniband controller: ClassCode: {:#X}",
        class_code
    );

    paging::add_memory_access_trap(
        get_ecam_target_address(ecam_address, bus, device, function),
        0x1000,
        false,
        false,
    )
    .expect("Failed to setup memory trap.");

    add_memory_load_access_handler(LoadAccessHandlerEntry::new(
        get_ecam_target_address(ecam_address, bus, device, function) + 0xD0,
        4 * 2,
        0,
        mt27800_address_and_data_load_handler,
    ))
    .expect("Failed to add the handler for PCI configuration space");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        get_ecam_target_address(ecam_address, bus, device, function) + 0xD0,
        4 * 2,
        0,
        mt27800_address_and_data_store_handler,
    ))
    .expect("Failed to add the handler for PCI configuration space");

    /* Expansion ROM */
    let expansion_rom_base_address =
        get_configuration_space_data(ecam_address, bus, device, function, 0x30, 4);
    if (expansion_rom_base_address & 1) == 1 {
        let expansion_rom_bar = (expansion_rom_base_address & bitmask!(31, 11)) as usize;
        paging::map_address(
            expansion_rom_bar,
            expansion_rom_bar,
            1024 * 1024,
            true,
            false,
            false,
            true,
        )
        .expect("Failed to map Expansion ROM");
        unsafe { EXPANSION_ROM_SIZE = 1024 * 1024 };
        setup_expansion_rom_memory_trap(expansion_rom_bar);
        add_memory_store_access_handler(StoreAccessHandlerEntry::new(
            get_ecam_target_address(ecam_address, bus, device, function) + 0x30,
            4,
            0,
            mt27800_pci_expansion_rom_bar_address_store_handler,
        ))
        .expect("Failed to add the handler for expansion rom bar");
    } else {
        println!("No Expansion ROM");
    }
}

fn setup_expansion_rom_memory_trap(expansion_rom_bar: usize) {
    let aligned_bar = expansion_rom_bar & STAGE_2_PAGE_MASK;
    let aligned_size = ((unsafe { EXPANSION_ROM_SIZE } + (expansion_rom_bar - aligned_bar) - 1)
        & STAGE_2_PAGE_MASK)
        + STAGE_2_PAGE_SIZE;
    paging::add_memory_access_trap(aligned_bar, aligned_size, true, false)
        .expect("Failed to add the trap for Expansion ROM");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        aligned_bar,
        aligned_size,
        0,
        mt27800_expansion_rom_store_handler,
    ))
    .expect("Failed to add the handler for Expansion ROM");
}

fn remove_expansion_rom_memory_trap(expansion_rom_bar: usize) {
    let aligned_bar = expansion_rom_bar & STAGE_2_PAGE_MASK;
    let aligned_size = ((unsafe { EXPANSION_ROM_SIZE } + (expansion_rom_bar - aligned_bar) - 1)
        & STAGE_2_PAGE_MASK)
        + STAGE_2_PAGE_SIZE;
    paging::remove_memory_access_trap(aligned_bar, aligned_size)
        .expect("Failed to add the trap for Expansion ROM");
    remove_memory_store_access_handler(StoreAccessHandlerEntry::new(
        expansion_rom_bar,
        aligned_size,
        0,
        mt27800_expansion_rom_store_handler,
    ))
    .expect("Failed to add the handler for Expansion ROM");
}

fn mt27800_pci_expansion_rom_bar_address_store_handler(
    _: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    let new_expansion_rom_bar = (data & bitmask!(31, 11)) as usize;
    pr_debug!(
        "Change MT27800 Expansion ROM BAR: {:#X} => {:#X}",
        unsafe { CURRENT_EXPANSION_ROM_BAR },
        new_expansion_rom_bar
    );
    remove_expansion_rom_memory_trap(unsafe { CURRENT_EXPANSION_ROM_BAR });
    setup_expansion_rom_memory_trap(new_expansion_rom_bar);
    StoreHookResult::PassThrough
}

fn mt27800_expansion_rom_store_handler(
    _: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    _: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    pr_debug!("MT27800 Expansion ROM Store Access");
    StoreHookResult::Cancel
}

static IS_WRITE_CANCELED: AtomicBool = AtomicBool::new(false);

fn mt27800_address_and_data_load_handler(
    accessing_memory_address: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    _: bool,
    _: bool,
    _: &LoadAccessHandlerEntry,
) -> LoadHookResult {
    pr_debug!(
        "MT27800 PCI Configuration Space Address/Data Store: Address: {:#X}",
        accessing_memory_address
    );
    if (accessing_memory_address & 0b100 == 0) && IS_WRITE_CANCELED.load(Ordering::Relaxed) {
        LoadHookResult::Data(0)
    } else {
        LoadHookResult::PassThrough
    }
}

fn mt27800_address_and_data_store_handler(
    accessing_memory_address: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    pr_debug!(
        "MT27800 PCI Configuration Space Address/Data Store: Address: {:#X}, Data: {:#X}",
        accessing_memory_address,
        data
    );
    if accessing_memory_address & 0b100 != 0 {
        IS_WRITE_CANCELED.store(true, Ordering::Relaxed);
        return StoreHookResult::Cancel;
    } else if accessing_memory_address & 0b100 == 0 {
        if (data & (1 << 31)) != 0 {
            IS_WRITE_CANCELED.store(true, Ordering::Relaxed);
            return StoreHookResult::Cancel;
        } else {
            IS_WRITE_CANCELED.store(false, Ordering::Relaxed);
        }
    }
    return StoreHookResult::PassThrough;
}
