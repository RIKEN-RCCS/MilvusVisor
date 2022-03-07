// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! System Memory Management Unit
//!

use crate::memory_hook::{
    add_memory_load_hook_handler, add_memory_store_hook_handler, LoadAccessHandlerEntry,
    LoadHookResult, StoreAccessHandlerEntry, StoreHookResult,
};
use crate::paging::add_memory_access_trap;
use crate::StoredRegisters;

use common::smmu::{SMMU_IDR0, SMMU_IDR0_HYP, SMMU_IDR0_S1P, SMMU_IDR0_S2P, SMMU_MEMORY_MAP_SIZE};
use common::{STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE};

static mut SMMU_BASE_ADDRESS: usize = 0;

/// SMMU領域の保護の設定を行います
///
/// SMMUのMMIO領域をEL1からアクセス不能にします。
/// またEL1からはStage1&2が使用不能のSMMUであるかのように見せます。
/// IORTのアドレスが渡された場合はEL1からIORTのエントリがゼロクリアされた状態に見えるように設定します。
///
/// # Arguments
/// base_address: SMMUのベースアドレス
/// iort_address: IORTエントリのアドレス(Optional)
///
pub fn init_smmu(base_address: usize, iort_address: Option<usize>) {
    /* base_address must be mapped, accessible, and enabled. */
    unsafe { SMMU_BASE_ADDRESS = base_address };

    add_memory_access_trap(base_address, SMMU_MEMORY_MAP_SIZE, false, false)
        .expect("Failed to trap the memory access to SMMU");

    add_memory_load_hook_handler(LoadAccessHandlerEntry::new(
        base_address,
        SMMU_MEMORY_MAP_SIZE,
        smmu_registers_load_handler,
    ))
    .expect("Failed to add the load handler");
    add_memory_store_hook_handler(StoreAccessHandlerEntry::new(
        base_address,
        SMMU_MEMORY_MAP_SIZE,
        smmu_registers_store_handler,
    ))
    .expect("Failed to add the store handler");

    if let Some(iort_address) = iort_address {
        let iort_length = unsafe { *((iort_address + 4) as *const u32) } as usize;
        let aligned_iort_address = iort_address & STAGE_2_PAGE_MASK;
        let aligned_iort_size = (((iort_length + (iort_address - aligned_iort_address)) - 1)
            & STAGE_2_PAGE_MASK)
            + STAGE_2_PAGE_SIZE;
        add_memory_access_trap(aligned_iort_address, aligned_iort_size, false, true)
            .expect("Failed to trap the IORT area.");
        add_memory_load_hook_handler(LoadAccessHandlerEntry::new(
            iort_address,
            iort_length,
            iort_load_handler,
        ))
        .expect("Failed to add the load handler");
        println!(
            "Delete IORT(Address: {:#X}, Size: {:#X}) from EL1.",
            iort_address, iort_length
        );
    }
}

fn smmu_registers_load_handler(
    accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _is_64bit_register: bool,
    _is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()> {
    let register_offset = accessing_memory_address - unsafe { SMMU_BASE_ADDRESS };
    println!("SMMU Load Access Handler: Offset: {:#X}", register_offset);
    match register_offset {
        SMMU_IDR0 => {
            println!("SMMU_IDR0");
            Ok(LoadHookResult::Data(
                (unsafe { *(accessing_memory_address as *const u32) }
                    & (!(SMMU_IDR0_S2P | SMMU_IDR0_S1P | SMMU_IDR0_HYP))) as u64,
            ))
        }
        _ => Ok(LoadHookResult::PassThrough),
    }
}

fn smmu_registers_store_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _data: u64,
) -> Result<StoreHookResult, ()> {
    println!("SMMU Store Access Handler");
    return Ok(StoreHookResult::Cancel);
}

fn iort_load_handler(
    _accessing_memory_address: usize,
    _stored_registers: &mut StoredRegisters,
    _access_size: u8,
    _is_64bit_register: bool,
    _is_sign_extend_required: bool,
) -> Result<LoadHookResult, ()> {
    return Ok(LoadHookResult::Data(0));
}
