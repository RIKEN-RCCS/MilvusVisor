// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

///
/// A64 Store Instructions' Emulator
///
/// Supported: str, stp (except Atomic, SIMD)
///
use super::{
    advance_elr_el2, faulting_virtual_address_to_intermediate_physical_address,
    get_register_reference_mut, write_back_index_register_imm7, write_back_index_register_imm9,
};
use crate::{handler_panic, StoredRegisters};

use crate::memory_hook::{memory_store_hook_handler, StoreHookResult};
use common::cpu::convert_virtual_address_to_physical_address_el2_write;
use common::{bitmask, STAGE_2_PAGE_SHIFT};

pub fn emulate_store_register(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_store_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    //let op2 = ((target_instruction & bitmask!(24, 23)) >> 23) as u8;
    //let op3 = ((target_instruction & bitmask!(21, 16)) >> 16) as u8;
    let op4 = ((target_instruction & bitmask!(11, 10)) >> 10) as u8;
    let size = (target_instruction >> 30) as u8;

    pr_debug!(
        "[{:#X}](IPA) <= R{}({})",
        intermediate_physical_store_address,
        target_register,
        match op4 {
            0b00 => "Unscaled",
            0b01 => "PostIndexed",
            0b10 => "Unprivileged",
            0b11 => "PreIndexed",
            _ => unreachable!(),
        }
    );
    if op4 == 0b10 {
        unimplemented!("UnPrivileged Access is not implemented...");
    }

    if ((target_instruction >> 26) & 1) != 0 {
        /* V */
        handler_panic!(s_r, "SIMD is not supported: {:#X}", target_instruction);
    }

    pr_debug!("Size: {:#b}", size);
    store_register_into_address(
        s_r,
        intermediate_physical_store_address,
        target_register,
        size,
    )?;
    if (op4 & 1) != 0 {
        pr_debug!("Post/Pre Indexed");
        let imm9 = (target_instruction & bitmask!(20, 12)) >> 12;
        let base_register =
            get_register_reference_mut(s_r, ((target_instruction & bitmask!(9, 5)) >> 5) as u8);
        write_back_index_register_imm9(base_register, imm9);
    }

    advance_elr_el2();
    return Ok(());
}

pub fn emulate_unsigned_immediate_store_register(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_store_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    let size = (target_instruction >> 30) as u8;
    store_register_into_address(
        s_r,
        intermediate_physical_store_address,
        target_register,
        size,
    )?;
    advance_elr_el2();
    return Ok(());
}

pub fn emulate_store_register_register_offset(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_store_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    let size = (target_instruction >> 30) as u8;
    store_register_into_address(
        s_r,
        intermediate_physical_store_address,
        target_register,
        size,
    )?;
    advance_elr_el2();
    return Ok(());
}

pub fn emulate_store_pair(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let op2 = ((target_instruction & bitmask!(24, 23)) >> 23) as u8;
    let opc = (target_instruction >> 30) as u8;
    let sf = (opc & (1 << 1)) != 0;
    let sse = (opc & 1) != 0;
    let is_pre_or_post_indexed = (op2 & 1) != 0;
    let intermediate_physical_store_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    let target_register_1 = (target_instruction & bitmask!(4, 0)) as u8;
    let target_register_2 = ((target_instruction & bitmask!(14, 10)) >> 10) as u8;

    pr_debug!(
        "[{:#X}](IPA) <= {}{}, {}{}(+{}) (Sign Extend: {})({})",
        intermediate_physical_store_address,
        if sf { 'X' } else { 'W' },
        target_register_1,
        if sf { 'X' } else { 'W' },
        target_register_2,
        if sf { 8 } else { 4 },
        sse,
        match op2 {
            0b00 => "NonAllocate", /* It means the memory area is unlikely to access repeatedly */
            0b01 => "PostIndexed",
            0b10 => "Offset",
            0b11 => "PreIndexed",
            _ => unreachable!(),
        }
    );

    if (intermediate_physical_store_address >> STAGE_2_PAGE_SHIFT)
        != ((intermediate_physical_store_address + ((if sf { 8 } else { 4 }) * 2) - 1)
            >> STAGE_2_PAGE_SHIFT)
    {
        println!("STP alignment error.");
        return Err(());
    }
    if sse {
        unimplemented!();
    }
    store_register_into_address(
        s_r,
        intermediate_physical_store_address,
        target_register_1,
        if sf { 0b11 } else { 0b10 },
    )?;
    store_register_into_address(
        s_r,
        intermediate_physical_store_address + if sf { 8 } else { 4 },
        target_register_2,
        if sf { 0b11 } else { 0b10 },
    )?;

    if is_pre_or_post_indexed {
        pr_debug!("Post/Pre Indexed");
        let imm7 = (target_instruction & bitmask!(21, 15)) >> 15;
        let base_register =
            get_register_reference_mut(s_r, ((target_instruction & bitmask!(9, 5)) >> 5) as u8);
        write_back_index_register_imm7(base_register, imm7);
    }
    advance_elr_el2();
    return Ok(());
}

fn store_register_into_address(
    s_r: &mut StoredRegisters,
    intermediate_physical_store_address: usize,
    target_register: u8,
    size: u8,
) -> Result<(), ()> {
    /* TODO: 物理アドレスへのアクセス関数を用意する。現方法だとVA!=PAの時に誤動作する */
    let physical_store_address =
        convert_virtual_address_to_physical_address_el2_write(intermediate_physical_store_address)
            .expect("Failed to convert IPA => PA");

    pr_debug!(
        "[{:#X}](PA) <= R{}({})",
        physical_store_address,
        target_register,
        match size {
            0b00 => " 8Bit",
            0b01 => "16Bit",
            0b10 => "32Bit",
            0b11 => "64Bit",
            _ => unreachable!(),
        }
    );

    let reg_data = *get_register_reference_mut(s_r, target_register);
    let hook_result = memory_store_hook_handler(physical_store_address, s_r, size, reg_data)?;
    let data = match hook_result {
        StoreHookResult::PassThrough => reg_data,
        StoreHookResult::AlternativeData(d) => d,
        StoreHookResult::Cancel => {
            pr_debug!("The store instruction is cancelled.");
            return Ok(());
        }
    };

    pr_debug!("Data: {:#X}", data);
    match size {
        0b00 => unsafe { *(physical_store_address as *mut u8) = data as u8 },
        0b01 => unsafe { *(physical_store_address as *mut u16) = data as u16 },
        0b10 => unsafe { *(physical_store_address as *mut u32) = data as u32 },
        0b11 => unsafe { *(physical_store_address as *mut u64) = data },
        _ => unreachable!(),
    };

    return Ok(());
}
