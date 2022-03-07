// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Memory Hook Handler
//!

use crate::StoredRegisters;

#[allow(dead_code)]
pub enum LoadHookResult {
    PassThrough,
    Data(u64),
}

#[allow(dead_code)]
pub enum StoreHookResult {
    PassThrough,
    AlternativeData(u64),
    Cancel,
}

pub type LoadAccessHandler = fn(
    accessing_memory_address: usize,
    stored_registers: &mut StoredRegisters,
    access_size: u8,
    is_64bit_register: bool,
    is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()>;

pub type StoreAccessHandler = fn(
    accessing_memory_address: usize,
    stored_registers: &mut StoredRegisters,
    access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()>;

#[derive(Clone, Copy)]
pub struct LoadAccessHandlerEntry {
    target_address: usize,
    range: usize,
    handler: LoadAccessHandler,
    //busy_flag: AtomicBool
}

#[derive(Clone, Copy)]
pub struct StoreAccessHandlerEntry {
    target_address: usize,
    range: usize,
    handler: StoreAccessHandler,
    //busy_flag: AtomicBool
}

impl LoadAccessHandlerEntry {
    pub const fn new(target_address: usize, range: usize, handler: LoadAccessHandler) -> Self {
        Self {
            target_address,
            range,
            handler,
        }
    }

    pub const fn get_target_address(&self) -> usize {
        self.target_address
    }

    pub fn set_target_address(&mut self, address: usize) {
        self.target_address = address;
    }
}

impl StoreAccessHandlerEntry {
    pub const fn new(target_address: usize, range: usize, handler: StoreAccessHandler) -> Self {
        Self {
            target_address,
            range,
            handler,
        }
    }

    pub const fn get_target_address(&self) -> usize {
        self.target_address
    }

    pub fn set_target_address(&mut self, address: usize) {
        self.target_address = address;
    }
}

pub static mut LOAD_HANDLER_LIST: [Option<LoadAccessHandlerEntry>; 256] = [None; 256];
static mut NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES: usize = 0;
pub static mut STORE_HANDLER_LIST: [Option<StoreAccessHandlerEntry>; 256] = [None; 256];
static mut NUM_OF_STORE_HANDLER_ENABLED_ENTRIES: usize = 0;

pub fn add_memory_load_hook_handler(entry: LoadAccessHandlerEntry) -> Result<(), ()> {
    for e in unsafe { &mut LOAD_HANDLER_LIST } {
        if e.is_none() {
            *e = Some(entry);
            unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES += 1 };
            return Ok(());
        }
    }
    return Err(());
}

pub fn add_memory_store_hook_handler(entry: StoreAccessHandlerEntry) -> Result<(), ()> {
    for e in unsafe { &mut STORE_HANDLER_LIST } {
        if e.is_none() {
            *e = Some(entry);
            unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES += 1 };
            return Ok(());
        }
    }
    return Err(());
}

pub fn remove_memory_load_hook_handler(entry: LoadAccessHandlerEntry) -> Result<(), ()> {
    for e in unsafe { &mut LOAD_HANDLER_LIST } {
        if let Some(t_e) = e {
            if t_e.target_address == entry.target_address && t_e.range == entry.range {
                *e = None;
                unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES -= 1 };
                return Ok(());
            }
        }
    }
    return Err(());
}

pub fn remove_memory_store_hook_handler(entry: StoreAccessHandlerEntry) -> Result<(), ()> {
    for e in unsafe { &mut STORE_HANDLER_LIST } {
        if let Some(t_e) = e {
            if t_e.target_address == entry.target_address && t_e.range == entry.range {
                *e = None;
                unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES -= 1 };
                return Ok(());
            }
        }
    }
    return Err(());
}

pub fn memory_load_hook_handler(
    accessing_memory_address: usize,
    stored_registers: &mut StoredRegisters,
    access_size: u8,
    is_64bit_register: bool,
    is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()> {
    let mut num_of_check_entries = 0;
    for e in unsafe { &LOAD_HANDLER_LIST } {
        if let Some(handler_entry) = e {
            if (handler_entry.target_address..(handler_entry.target_address + handler_entry.range))
                .contains(&accessing_memory_address)
            {
                return (handler_entry.handler)(
                    accessing_memory_address,
                    stored_registers,
                    access_size,
                    is_64bit_register,
                    is_sign_extend_required,
                );
            }
            num_of_check_entries += 1;
            if num_of_check_entries == unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES } {
                break;
            }
        }
    }
    return Ok(LoadHookResult::PassThrough);
}

pub fn memory_store_hook_handler(
    accessing_memory_address: usize,
    stored_registers: &mut StoredRegisters,
    access_size: u8,
    data: u64,
) -> Result<StoreHookResult, ()> {
    let mut num_of_check_entries = 0;
    for e in unsafe { &STORE_HANDLER_LIST } {
        if let Some(handler_entry) = e {
            if (handler_entry.target_address..(handler_entry.target_address + handler_entry.range))
                .contains(&accessing_memory_address)
            {
                return (handler_entry.handler)(
                    accessing_memory_address,
                    stored_registers,
                    access_size,
                    data,
                );
            }
            num_of_check_entries += 1;
            if num_of_check_entries == unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES } {
                break;
            }
        }
    }
    return Ok(StoreHookResult::PassThrough);
}
