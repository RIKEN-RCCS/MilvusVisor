// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Intel(R) Ethernet Controller I210
//!

use crate::memory_hook::{
    add_memory_load_hook_handler, add_memory_store_hook_handler, remove_memory_load_hook_handler,
    remove_memory_store_hook_handler, LoadAccessHandlerEntry, LoadHookResult,
    StoreAccessHandlerEntry, StoreHookResult,
};
use crate::pci::{get_configuration_space_data, get_ecam_target_address};
use crate::{paging, StoredRegisters};

use common::{bitmask, PAGE_SIZE, STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE};

pub const VENDOR_ID: u16 = 0x8086;
pub const DEVICE_ID: u16 = 0x1533;

static mut EEPROM_BLOCK_BASE: u32 = 0;
static mut EEPROM_BLOCK_END: u32 = 0;
static mut IS_64BIT_BAR: bool = false;
static mut CURRENT_MEMORY_BAR: usize = 0;
static mut CURRENT_EXPANSION_ROM_BAR: usize = 0;
static mut FLBAR_SIZE: usize = 1024 * 64;

const FLASH_SECURITY_REGISTERS_BASE: usize = 0x12000;
const EEWR: usize = 0x12018;
const EEWR_ALIAS: usize = 0x1101C;
const FLSWCTL: usize = 0x12048;
const FLSWDATA: usize = 0x1204C;
const I_NVM_DATA: usize = 0x12120;
const I_NVM_DATA_LEN: usize = (0x1221C - I_NVM_DATA) + 1;

static I210_LOAD_HANDLERS: [LoadAccessHandlerEntry; 2] = [
    LoadAccessHandlerEntry::new(EEWR, 4, i210_eeprom_write_register_load_handler),
    LoadAccessHandlerEntry::new(EEWR_ALIAS, 4, i210_eeprom_write_register_load_handler),
];

static I210_STORE_HANDLERS: [StoreAccessHandlerEntry; 4] = [
    StoreAccessHandlerEntry::new(EEWR, 4, i210_eeprom_write_register_store_handler),
    StoreAccessHandlerEntry::new(EEWR_ALIAS, 4, i210_eeprom_write_register_store_handler),
    StoreAccessHandlerEntry::new(
        FLSWCTL,
        FLSWDATA - FLSWCTL,
        i210_i_flash_burst_registers_store_handler,
    ),
    StoreAccessHandlerEntry::new(I_NVM_DATA, I_NVM_DATA_LEN, i210_i_nvm_data_store_handler),
];

pub fn setup_device(ecam_address: usize, bus: u8, device: u8, function: u8) {
    let class_code = get_configuration_space_data(ecam_address, bus, device, function, 0x09, 3);
    if class_code != 0x020000 && class_code != 0x010000 {
        println!("Unsupported I210 Class Code: {:#X}", class_code);
        return;
    }
    println!("I210 Ethernet controller: ClassCode: {:#X}", class_code);
    let is_64bit_bar =
        ((get_configuration_space_data(ecam_address, bus, device, function, 0x10, 4) >> 2) & 1)
            != 0;
    if is_64bit_bar {
        println!("64bit BAR Mode");
    } else {
        println!("32bit BAR Mode");
    }
    unsafe { IS_64BIT_BAR = is_64bit_bar };

    add_memory_store_hook_handler(StoreAccessHandlerEntry::new(
        get_ecam_target_address(ecam_address, bus, device, function) + 0x10,
        4 * 2,
        i210_pci_bar_address_store_handler,
    ))
    .expect("Failed to add the handler for memory bar");
    paging::add_memory_access_trap(
        get_ecam_target_address(ecam_address, bus, device, function),
        0x1000,
        true,
        false,
    )
    .expect("Failed to setup memory trap.");
    let memory_bar = ((get_configuration_space_data(ecam_address, bus, device, function, 0x10, 4))
        & !0b1111) as usize
        | (if is_64bit_bar {
            ((get_configuration_space_data(ecam_address, bus, device, function, 0x14, 4)) as usize)
                << 32
        } else {
            0
        });
    println!("I210 Base Address Register: {:#X}", memory_bar);
    unsafe { CURRENT_MEMORY_BAR = memory_bar };
    setup_memory_trap(memory_bar);
    println!("Add I210 Ethernet Controller BAR Handler");

    /* Expansion ROM */
    let expansion_rom_base_address =
        get_configuration_space_data(ecam_address, bus, device, function, 0x30, 4);
    if (expansion_rom_base_address & 1) == 1 {
        let expansion_rom_bar = (expansion_rom_base_address & bitmask!(31, 11)) as usize;

        paging::map_address(
            expansion_rom_bar,
            expansion_rom_bar,
            PAGE_SIZE,
            true,
            false,
            false,
            true,
        )
        .expect("Failed to map Expansion ROM");
        let pci_e_control_2 = unsafe { *((expansion_rom_bar + 0x28 * 2) as *const u16) };
        let flbar_size = 64 * 1024 * 2usize.pow(((pci_e_control_2 >> 1) & 0b111) as u32);
        println!(
            "Expansion ROM: {:#X}, FLBAR_SIZE: {:#X}",
            expansion_rom_bar, flbar_size
        );
        unsafe { FLBAR_SIZE = flbar_size };
        setup_expansion_rom_memory_trap(expansion_rom_bar);
        add_memory_store_hook_handler(StoreAccessHandlerEntry::new(
            get_ecam_target_address(ecam_address, bus, device, function) + 0x30,
            4,
            i210_pci_expansion_rom_bar_address_store_handler,
        ))
        .expect("Failed to add the handler for expansion rom bar");
    } else {
        println!("No Expansion ROM");
    }

    /* TODO: Inspect BARCTRL field */
    //let bar_ctrl = unsafe { *((memory_bar + 0x5BFC) as *const u32) };
    let eeprom_block_base = unsafe { *((memory_bar + 0x1210C) as *const u32) };
    let eeprom_block_end = unsafe { *((memory_bar + 0x12110) as *const u32) };
    println!(
        "EEPROM: 1st: {:#X} ~ {:#X}, 2nd: {:#X}",
        eeprom_block_base & bitmask!(10, 0),
        eeprom_block_end & bitmask!(10, 0),
        (eeprom_block_base & bitmask!(22, 12)) >> 12
    );
    unsafe {
        EEPROM_BLOCK_BASE = eeprom_block_base;
        EEPROM_BLOCK_END = eeprom_block_end;
    }
}

fn setup_memory_trap(new_memory_bar: usize) {
    pr_debug!("I210 Base Address Register: {:#X}", new_memory_bar);
    paging::map_address(
        new_memory_bar,
        new_memory_bar,
        128 * 1024,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map");

    /* Set up to trap registers' area */
    paging::add_memory_access_trap(
        new_memory_bar + FLASH_SECURITY_REGISTERS_BASE,
        STAGE_2_PAGE_SIZE,
        false,
        false,
    )
    .expect("Failed to map EEPROM Register");
    paging::add_memory_access_trap(
        (new_memory_bar + EEWR_ALIAS) & STAGE_2_PAGE_MASK,
        STAGE_2_PAGE_SIZE,
        false,
        false,
    )
    .expect("Failed to map EEPROM Register(Alias)");

    /* Set up load access handlers */
    for e in &I210_LOAD_HANDLERS {
        let mut e = e.clone();
        e.set_target_address(e.get_target_address() + new_memory_bar);
        add_memory_load_hook_handler(e).expect("Failed to set up the load handler");
    }

    /* Set up store access handlers */
    for e in &I210_STORE_HANDLERS {
        let mut e = e.clone();
        e.set_target_address(e.get_target_address() + new_memory_bar);
        add_memory_store_hook_handler(e).expect("Failed to set up the store handler");
    }
}

fn remove_memory_trap(bar_address: usize) {
    pr_debug!("Remove I210 Base Address Register Trap: {:#X}", bar_address);

    /* Remove the trap of registers' area */
    paging::remove_memory_access_trap(
        bar_address + FLASH_SECURITY_REGISTERS_BASE,
        STAGE_2_PAGE_SIZE,
    )
    .expect("Failed to map EEPROM Register");
    paging::remove_memory_access_trap(
        (bar_address + EEWR_ALIAS) & STAGE_2_PAGE_MASK,
        STAGE_2_PAGE_SIZE,
    )
    .expect("Failed to map EEPROM Register(Alias)");

    /* Remove load access handlers */
    for e in &I210_LOAD_HANDLERS {
        let mut e = e.clone();
        e.set_target_address(e.get_target_address() + bar_address);
        remove_memory_load_hook_handler(e).expect("Failed to remove the load handler");
    }

    /* Remove store access handlers */
    for e in &I210_STORE_HANDLERS {
        let mut e = e.clone();
        e.set_target_address(e.get_target_address() + bar_address);
        remove_memory_store_hook_handler(e).expect("Failed to remove the store handler");
    }
}

fn setup_expansion_rom_memory_trap(expansion_rom_bar: usize) {
    paging::add_memory_access_trap(expansion_rom_bar, unsafe { FLBAR_SIZE }, true, false)
        .expect("Failed to add the trap for Expansion ROM");
    add_memory_store_hook_handler(StoreAccessHandlerEntry::new(
        expansion_rom_bar,
        unsafe { FLBAR_SIZE },
        i210_expansion_rom_store_handler,
    ))
    .expect("Failed to add the handler for Expansion ROM");
}

fn remove_expansion_rom_memory_trap(expansion_rom_bar: usize) {
    paging::remove_memory_access_trap(expansion_rom_bar, unsafe { FLBAR_SIZE })
        .expect("Failed to add the trap for Expansion ROM");
    remove_memory_store_hook_handler(StoreAccessHandlerEntry::new(
        expansion_rom_bar,
        unsafe { FLBAR_SIZE },
        i210_expansion_rom_store_handler,
    ))
    .expect("Failed to add the handler for Expansion ROM");
}

fn i210_pci_bar_address_store_handler(
    accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    let offset = accessing_memory_address & 0xFFF;
    if offset == 0x10 {
        pr_debug!("Writing I210 BAR0: {:#X}", data);
    } else {
        pr_debug!("Writing I210 BAR1: {:#X}", data);
    }
    if offset != 0x10 || !unsafe { IS_64BIT_BAR } {
        let new_bar = ((if offset == 0x10 {
            data & bitmask!(31, 17)
        } else {
            assert_eq!(offset, 0x14);
            (unsafe { *((accessing_memory_address - 0x04) as *const u32) } & bitmask!(31, 17))
                as u64
        }) | (if unsafe { IS_64BIT_BAR } {
            assert_eq!(offset, 0x14);
            data
        } else {
            0
        })) as usize;
        pr_debug!(
            "Change I210 BAR: {:#X} => {:#X}",
            unsafe { CURRENT_MEMORY_BAR },
            new_bar
        );
        remove_memory_trap(unsafe { CURRENT_MEMORY_BAR });
        setup_memory_trap(new_bar);
        unsafe { CURRENT_MEMORY_BAR = new_bar };
    }
    return Ok(StoreHookResult::PassThrough);
}

fn i210_pci_expansion_rom_bar_address_store_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    let new_expansion_rom_bar = (data & bitmask!(31, 11)) as usize;
    pr_debug!(
        "Change I210 Expansion ROM BAR: {:#X} => {:#X}",
        unsafe { CURRENT_EXPANSION_ROM_BAR },
        new_expansion_rom_bar
    );
    remove_expansion_rom_memory_trap(unsafe { CURRENT_EXPANSION_ROM_BAR });
    setup_expansion_rom_memory_trap(new_expansion_rom_bar);
    return Ok(StoreHookResult::PassThrough);
}

fn i210_eeprom_write_register_load_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _is_64bit_register: bool,
    _is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()> {
    pr_debug!("EEPROM Write Register Load Access");
    let data: u64 = 1 << 1;
    pr_debug!("Return the alternative data: {:#X}", data);
    return Ok(LoadHookResult::Data(data));
}

fn i210_eeprom_write_register_store_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    println!("EEPROM Write Register Store Access");
    let address = ((data & bitmask!(12, 2)) >> 2) as u32;
    pr_debug!("EEPROM Address: {:#X}, Data: {:#X}", address, data >> 16);
    let eeprom_1st_block_end = unsafe { EEPROM_BLOCK_END & bitmask!(10, 0) };
    let eeprom_1st_block_start = unsafe { EEPROM_BLOCK_BASE & bitmask!(10, 0) };
    let eeprom_2nd_block_start = unsafe { (EEPROM_BLOCK_BASE & bitmask!(22, 12)) >> 12 };
    if eeprom_1st_block_end != 0
        && (eeprom_1st_block_start..=eeprom_1st_block_end).contains(&address)
    {
        pr_debug!("EEPROM 1st Block Access");
    } else if eeprom_2nd_block_start != 0 && address >= eeprom_2nd_block_start {
        pr_debug!("EEPROM 2nd Block Access");
    }
    return Ok(StoreHookResult::Cancel);
}

fn i210_i_nvm_data_store_handler(
    accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    println!(
        "iNVM Data Register Store Access: Offset: {:#X}, Data: {:#X}",
        accessing_memory_address - unsafe { CURRENT_MEMORY_BAR } - I_NVM_DATA,
        data
    );

    return Ok(StoreHookResult::Cancel);
}

fn i210_i_flash_burst_registers_store_handler(
    accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    println!(
        "iNVM Flash Burst Registers Store Access: Register: {}, Data: {:#X}",
        if accessing_memory_address - unsafe { CURRENT_MEMORY_BAR } == FLSWCTL {
            "FLSWCTL"
        } else {
            "FLSWDATA"
        },
        data
    );

    return Ok(StoreHookResult::Cancel);
}

fn i210_expansion_rom_store_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _data: u64,
) -> Result<StoreHookResult, ()> {
    println!("i210 Expansion ROM Store Access");
    return Ok(StoreHookResult::Cancel);
}
