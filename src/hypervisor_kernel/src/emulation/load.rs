// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! A64 Load Instructions' Emulator
//!
//! Supported: ldr, ldp (except Atomic, SIMD)
//!

use super::{
    advance_elr_el2, faulting_virtual_address_to_intermediate_physical_address,
    get_register_reference_mut, write_back_index_register_imm7, write_back_index_register_imm9,
};
use crate::StoredRegisters;

use crate::memory_hook::{memory_load_hook_handler, LoadHookResult};
use common::cpu::convert_virtual_address_to_physical_address_el2_read;
use common::{bitmask, STAGE_2_PAGE_SHIFT};

pub fn emulate_load_register(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_load_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    //let op2 = ((target_instruction & bitmask!(24, 23)) >> 23) as u8;
    //let op3 = ((target_instruction & bitmask!(21, 16)) >> 16) as u8;
    let op4 = ((target_instruction & bitmask!(11, 10)) >> 10) as u8;
    /* sf is usable only if sse is true */
    let sf = (target_instruction & (1 << 22)) == 0;
    let sse = (target_instruction & (1 << 23)) != 0;

    pr_debug!(
        "{}{} <= [{:#X}](IPA)(Sign Extend: {})({})",
        if sse && !sf { 'W' } else { 'X' },
        target_register,
        intermediate_physical_load_address,
        sse,
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

    let size = (target_instruction >> 30) as u8;
    if size == 0b11 && op4 == 0b00 && sse && !sf {
        pr_debug!("Prefetch Memory Unscaled Signals.");
        return Ok(());
    }
    pr_debug!("Size: {:#b}", size);
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address,
        target_register,
        size,
        sf,
        sse,
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

pub fn emulate_unsigned_immediate_load_register(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_load_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;

    /* sf is usable only if sse is true */
    let sf = (target_instruction & (1 << 22)) == 0;
    let sse = (target_instruction & (1 << 23)) != 0;
    let size = (target_instruction >> 30) as u8;

    pr_debug!("Size: {:#b}", size);
    if size == 0b11 && sse && !sf {
        pr_debug!("Prefetch Memory Immediate Signals.");
        return Ok(());
    }
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address,
        target_register,
        size,
        sf,
        sse,
    )?;
    advance_elr_el2();
    return Ok(());
}

pub fn emulate_load_register_register_offset(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_load_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;

    /* sf is usable only if sse is true */
    let sf = (target_instruction & (1 << 22)) == 0;
    let sse = (target_instruction & (1 << 23)) != 0;
    let size = (target_instruction >> 30) as u8;
    if size == 0b11 && sse {
        pr_debug!("Prefetch Memory Register Signals.");
        return Ok(());
    }

    pr_debug!("Size: {:#b}", size);
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address,
        target_register,
        size,
        sf,
        sse,
    )?;
    advance_elr_el2();
    return Ok(());
}

pub fn emulate_literal_load_register(
    s_r: &mut StoredRegisters,
    target_instruction: u32,
    far: u64,
    _hpfar: u64,
) -> Result<(), ()> {
    let target_register = (target_instruction & bitmask!(4, 0)) as u8;
    let intermediate_physical_load_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;

    let opc = (target_instruction >> 30) as u8;
    /* sf is usable only if sse is true */
    let sf = opc == 0b01 || opc == 0b10;
    let sse = opc == 0b10;
    let size = if opc == 0b01 { 0b11 } else { 0b10 };

    pr_debug!("Size: {:#b}", size);
    if opc == 0b11 {
        pr_debug!("Prefetch Memory Literal Signals");
        return Ok(());
    }
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address,
        target_register,
        size,
        sf,
        sse,
    )?;
    advance_elr_el2();
    return Ok(());
}

pub fn emulate_load_pair(
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
    let intermediate_physical_load_address =
        faulting_virtual_address_to_intermediate_physical_address(far)?;
    let target_register_1 = (target_instruction & bitmask!(4, 0)) as u8;
    let target_register_2 = ((target_instruction & bitmask!(14, 10)) >> 10) as u8;

    pr_debug!(
        "{}{}, {}{}(+{}) <= [{:#X}](IPA)(Sign Extend: {})({})",
        if sf { 'X' } else { 'W' },
        target_register_1,
        if sf { 'X' } else { 'W' },
        target_register_2,
        if sf { 8 } else { 4 },
        intermediate_physical_load_address,
        sse,
        match op2 {
            0b00 => "NonAllocate", /* It means the memory area is unlikely to access repeatedly */
            0b01 => "PostIndexed",
            0b10 => "Offset",
            0b11 => "PreIndexed",
            _ => unreachable!(),
        }
    );

    if (intermediate_physical_load_address >> STAGE_2_PAGE_SHIFT)
        != ((intermediate_physical_load_address + ((if sf { 8 } else { 4 }) * 2) - 1)
            >> STAGE_2_PAGE_SHIFT)
    {
        println!("LDP alignment error.");
        return Err(());
    }
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address,
        target_register_1,
        if sf { 0b11 } else { 0b10 },
        sf,
        sse,
    )?;
    load_from_address_and_store_into_register(
        s_r,
        intermediate_physical_load_address + if sf { 8 } else { 4 },
        target_register_2,
        if sf { 0b11 } else { 0b10 },
        sf,
        sse,
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

fn load_from_address_and_store_into_register(
    s_r: &mut StoredRegisters,
    intermediate_physical_load_address: usize,
    target_register: u8,
    size: u8,
    sf: bool, /* sf is usable only if sse is true */
    sse: bool,
) -> Result<(), ()> {
    let sf = !sse || sf;

    pr_debug!(
        "{}{} <= [{:#X}](IPA)(Sign Extend: {})",
        if sf { 'X' } else { 'W' },
        target_register,
        intermediate_physical_load_address,
        sse
    );
    /* TODO: 物理アドレスへのアクセス関数を用意する。現方法だとVA!=PAの時に誤動作する */
    let physical_load_address =
        convert_virtual_address_to_physical_address_el2_read(intermediate_physical_load_address)
            .expect("Failed to convert IPA => PA");

    pr_debug!(
        "{}{} <= [{:#X}](PA)(Sign Extend: {})",
        if sf { 'X' } else { 'W' },
        target_register,
        physical_load_address,
        sse
    );
    if !sf && size == 0b11 {
        println!("Invalid Instruction: Loading a 64bit data into the 32bit register.");
        return Err(());
    }

    let hook_result = memory_load_hook_handler(physical_load_address, s_r, size, sf, sse)?;
    let data = match hook_result {
        LoadHookResult::PassThrough => {
            if sse {
                unimplemented!();
            } else {
                match size {
                    0b00 => unsafe { *(physical_load_address as *const u8) as u64 },
                    0b01 => unsafe { *(physical_load_address as *const u16) as u64 },
                    0b10 => unsafe { *(physical_load_address as *const u32) as u64 },
                    0b11 => unsafe { *(physical_load_address as *const u64) },
                    _ => unreachable!(),
                }
            }
        }
        LoadHookResult::Data(d) => d,
    };

    pr_debug!("Data: {:#X}", data);
    *get_register_reference_mut(s_r, target_register) = data;

    return Ok(());
}
