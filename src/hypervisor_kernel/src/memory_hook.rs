// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Memory Access Handler
//!

use core::mem::MaybeUninit;

use common::GeneralPurposeRegisters;

const DEFAULT_LOAD_EMULATION_RESULT: LoadHookResult = LoadHookResult::PassThrough;
const DEFAULT_STORE_EMULATION_RESULT: StoreHookResult = StoreHookResult::PassThrough;
const NUMBER_OF_HANDLER_ENTRIES: usize = 256;

/// The return value of LoadAccessHandler
///
/// * PasThrough: Allow loading the real value from the memory
/// * Data(u64): Store the value into the register instead of accessing memory
pub enum LoadHookResult {
    PassThrough,
    Data(u64),
}

/// The return value of StoreAccessHandler
///
/// * PassThrough: Allow storing the value guest requested into the memory
/// * Data(u64): Store the value into the memory
/// * Cancel: Disallow memory access, pretend to be accessed
pub enum StoreHookResult {
    PassThrough,
    Data(u64),
    Cancel,
}

pub type LoadAccessHandler = fn(
    accessing_memory_address: usize,
    regs: &mut GeneralPurposeRegisters,
    access_size: u8,
    is_64bit_register: bool,
    is_sign_extend_required: bool,
    entry: &LoadAccessHandlerEntry,
) -> LoadHookResult;

pub type StoreAccessHandler = fn(
    accessing_memory_address: usize,
    regs: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
    entry: &StoreAccessHandlerEntry,
) -> StoreHookResult;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct LoadAccessHandlerEntry {
    target_address: usize,
    range: usize,
    handler: LoadAccessHandler,
    data: usize,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct StoreAccessHandlerEntry {
    target_address: usize,
    range: usize,
    handler: StoreAccessHandler,
    data: usize,
}

#[allow(dead_code)]
impl LoadAccessHandlerEntry {
    /// Create the entry of LoadAccessHandler
    ///
    /// * target_address: The base address to handle with this handler
    /// * range: The valid range of this handler,`target_address` ~ (`target_address` + `range` - 1) will be handled by this handler
    /// * handler: The pointer of handler
    /// * data: The value which will be passed to handler
    pub const fn new(
        target_address: usize,
        range: usize,
        data: usize,
        handler: LoadAccessHandler,
    ) -> Self {
        Self {
            target_address,
            range,
            handler,
            data,
        }
    }

    pub const fn get_target_address(&self) -> usize {
        self.target_address
    }

    pub fn set_target_address(&mut self, address: usize) {
        self.target_address = address;
    }

    pub const fn get_range(&self) -> usize {
        self.range
    }

    pub const fn get_data(&self) -> usize {
        self.data
    }
}

#[allow(dead_code)]
impl StoreAccessHandlerEntry {
    /// Create the entry of StoreAccessHandler
    ///
    /// * target_address: The base address to handle with this handler
    /// * range: The valid range of this handler,`target_address` ~ (`target_address` + `range` - 1) will be handled by this handler
    /// * handler: The pointer of handler
    /// * data: The value which will be passed to handler
    pub const fn new(
        target_address: usize,
        range: usize,
        data: usize,
        handler: StoreAccessHandler,
    ) -> Self {
        Self {
            target_address,
            range,
            handler,
            data,
        }
    }

    pub const fn get_target_address(&self) -> usize {
        self.target_address
    }

    pub fn set_target_address(&mut self, address: usize) {
        self.target_address = address;
    }

    pub const fn get_range(&self) -> usize {
        self.range
    }

    pub const fn get_data(&self) -> usize {
        self.data
    }
}

pub static mut LOAD_HANDLER_LIST: MaybeUninit<[LoadAccessHandlerEntry; NUMBER_OF_HANDLER_ENTRIES]> =
    MaybeUninit::uninit();
static mut NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES: usize = 0;
pub static mut STORE_HANDLER_LIST: MaybeUninit<
    [StoreAccessHandlerEntry; NUMBER_OF_HANDLER_ENTRIES],
> = MaybeUninit::uninit();
static mut NUM_OF_STORE_HANDLER_ENABLED_ENTRIES: usize = 0;

macro_rules! get_load_handler_list {
    () => {
        unsafe {
            (&*core::ptr::addr_of!(LOAD_HANDLER_LIST))
                .assume_init()
                .iter()
        }
    };
}

macro_rules! get_load_handler_list_mut {
    () => {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(LOAD_HANDLER_LIST))
                .assume_init_mut()
                .iter_mut()
        }
    };
}

macro_rules! get_store_handler_list {
    () => {
        unsafe {
            (&*core::ptr::addr_of!(STORE_HANDLER_LIST))
                .assume_init()
                .iter()
        }
    };
}

macro_rules! get_store_handler_list_mut {
    () => {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(STORE_HANDLER_LIST))
                .assume_init_mut()
                .iter_mut()
        }
    };
}

pub fn init_memory_access_handler() {
    for e in get_load_handler_list_mut!() {
        e.target_address = 0;
        e.range = 0;
    }
    for e in get_store_handler_list_mut!() {
        e.target_address = 0;
        e.range = 0;
    }
}

/// Register LoadAccessHandler
///
/// This function will add LoadAccessHandlerEntry into list.
/// Function will return Err if `entry.range == 0` or list is full.
///
/// This function **does not** add paging trap. Please call [`crate::paging::add_memory_access_trap`].
pub fn add_memory_load_access_handler(entry: LoadAccessHandlerEntry) -> Result<(), ()> {
    if entry.range == 0 {
        return Err(());
    }
    for e in get_load_handler_list_mut!() {
        if e.range == 0 {
            *e = entry;
            unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES += 1 };
            return Ok(());
        }
    }
    Err(())
}

/// Register StoreAccessHandlerEntry
///
/// This function will add StoreAccessHandlerEntry into list.
/// Function will return Err if entry.range == 0 or list is full.
///
/// This function **does not** add paging trap. Please call [`crate::paging::add_memory_access_trap`].
pub fn add_memory_store_access_handler(entry: StoreAccessHandlerEntry) -> Result<(), ()> {
    if entry.range == 0 {
        return Err(());
    }
    for e in get_store_handler_list_mut!() {
        if e.range == 0 {
            *e = entry;
            unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES += 1 };
            return Ok(());
        }
    }
    Err(())
}

/// Unregister LoadAccessHandler
///
/// This function will remove LoadAccessHandlerEntry from list.
/// Function will return Err if entry is not found in the list.
///
/// This function **does not** remove paging trap. Please call [`crate::paging::remove_memory_access_trap`].
/// If you call [`crate::paging::remove_memory_access_trap`], be careful if other handlers need the page trap.
pub fn remove_memory_load_access_handler(entry: LoadAccessHandlerEntry) -> Result<(), ()> {
    for e in get_load_handler_list_mut!() {
        if e.target_address == entry.target_address && e.range == entry.range {
            e.target_address = 0;
            e.range = 0;
            unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES -= 1 };
            return Ok(());
        }
    }
    Err(())
}

/// Unregister StoreAccessHandler
///
/// This function will remove StoreAccessHandlerEntry from list.
/// Function will return Err if entry is not found in the list.
///
/// This function **does not** remove paging trap. Please call [`crate::paging::remove_memory_access_trap`].
/// If you call [`crate::paging::remove_memory_access_trap`], be careful if other handlers need the page trap.
pub fn remove_memory_store_access_handler(entry: StoreAccessHandlerEntry) -> Result<(), ()> {
    for e in get_store_handler_list_mut!() {
        if e.target_address == entry.target_address && e.range == entry.range {
            e.target_address = 0;
            e.range = 0;
            unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES -= 1 };
            return Ok(());
        }
    }
    Err(())
}

pub fn memory_load_hook_handler(
    accessing_memory_address: usize,
    regs: &mut GeneralPurposeRegisters,
    access_size: u8,
    is_64bit_register: bool,
    is_sign_extend_required: bool,
) -> LoadHookResult {
    let mut num_of_check_entries = 0;
    for e in get_load_handler_list!() {
        if e.range == 0 {
            continue;
        }
        if (e.target_address..(e.target_address + e.range)).contains(&accessing_memory_address) {
            return (e.handler)(
                accessing_memory_address,
                regs,
                access_size,
                is_64bit_register,
                is_sign_extend_required,
                e,
            );
        }
        num_of_check_entries += 1;
        if num_of_check_entries == unsafe { NUM_OF_LOAD_HANDLER_ENABLED_ENTRIES } {
            break;
        }
    }
    DEFAULT_LOAD_EMULATION_RESULT
}

pub fn memory_store_hook_handler(
    accessing_memory_address: usize,
    regs: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
) -> StoreHookResult {
    let mut num_of_check_entries = 0;
    for e in get_store_handler_list!() {
        if (e.target_address..(e.target_address + e.range)).contains(&accessing_memory_address) {
            return (e.handler)(accessing_memory_address, regs, access_size, data, e);
        }
        num_of_check_entries += 1;
        if num_of_check_entries == unsafe { NUM_OF_STORE_HANDLER_ENABLED_ENTRIES } {
            break;
        }
    }
    DEFAULT_STORE_EMULATION_RESULT
}
