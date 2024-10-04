// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! A64 Instructions' Emulator
//!

use core::arch::asm;

use common::cpu::{
    convert_virtual_address_to_intermediate_physical_address_el0_read,
    convert_virtual_address_to_intermediate_physical_address_el1_read,
    convert_virtual_address_to_intermediate_physical_address_el1_write,
    convert_virtual_address_to_physical_address_el2_read,
    convert_virtual_address_to_physical_address_el2_write, SPSR_EL2_M, SPSR_EL2_M_EL0T,
};
use common::{GeneralPurposeRegisters, PAGE_MASK, PAGE_SIZE, bitmask};

pub use load::read_memory;

use crate::paging::map_address;

mod load;
mod store;

const REGISTER_NUMBER_XZR: u8 = 31;

#[allow(unused_variables)]
pub fn data_abort_handler(
    s_r: &mut GeneralPurposeRegisters,
    esr: u64,
    elr: u64,
    far: u64,
    hpfar: u64,
    spsr: u64,
) -> Result<(), ()> {
    #[cfg(debug_assertions)]
    if (esr & (1 << 24)) != 0 {
        let sas = (esr >> 22) & 0b11;
        match sas {
            0b00 => println!("Byte(8Bits) Access"),
            0b01 => println!("HalfWord(16Bits) Access"),
            0b10 => println!("Word(32Bits) Access"),
            0b11 => println!("DoubleWord(64Bits) Access"),
            _ => unreachable!(),
        }
        if (esr & (1 << 21)) != 0 {
            println!("Sign Extension is required.");
        }
        let srt = (esr >> 16) & 0b11111;
        println!("SRT: {}", srt);
        if (esr & (1 << 15)) != 0 {
            println!("64Bit Register");
        } else {
            println!("32Bit Register");
        }
        if (esr & (1 << 10)) != 0 {
            panic!("FAR is not valid");
        }
        if (esr & (1 << 6)) != 0 {
            println!("Write Access");
        } else {
            println!("Read Access");
        }
    } else {
        println!("No Valid Instruction Syndrome Information.");
    }

    let instruction_intermediate_physical_address = if (spsr & SPSR_EL2_M) == SPSR_EL2_M_EL0T {
        pr_debug!("Access from EL0");
        convert_virtual_address_to_intermediate_physical_address_el0_read(elr as usize).unwrap()
    } else {
        convert_virtual_address_to_intermediate_physical_address_el1_read(elr as usize).unwrap()
    };
    pr_debug!(
        "Target Instruction Address: {:#X} => {:#X}",
        elr,
        instruction_intermediate_physical_address
    );
    let target_instruction_virtual_address =
        get_virtual_address_to_access_ipa(instruction_intermediate_physical_address, false)?;
    let target_instruction = unsafe { *(target_instruction_virtual_address as *const u32) };
    pr_debug!("Target Instruction: {:#X}", target_instruction);

    emulate_instruction(s_r, target_instruction, elr, far, hpfar)
}

fn emulate_instruction(
    s_r: &mut GeneralPurposeRegisters,
    target_instruction: u32,
    _elr: u64,
    far: u64,
    hpfar: u64,
) -> Result<(), ()> {
    /* ARM DDI 0487G.a ID011921 C4-280 */
    let op0 = ((target_instruction & bitmask!(28, 25)) >> 25) as u8;
    if (op0 & 0b0101) != 0b0100 {
        handler_panic!(s_r, "Not Load/Store Instruction: {:#X}", target_instruction);
    }
    let op1 = (op0 >> 1) & 1;
    let op0 = ((target_instruction & bitmask!(31, 28)) >> 28) as u8;
    let op2 = ((target_instruction & bitmask!(24, 23)) >> 23) as u8;
    let op3 = ((target_instruction & bitmask!(21, 16)) >> 16) as u8;
    let op4 = ((target_instruction & bitmask!(11, 10)) >> 10) as u8;
    pr_debug!(
        "op0: {:#b}, op1: {:#b}, op2: {:#b}, op3: {:#b}, op4: {:#b}",
        op0,
        op1,
        op2,
        op3,
        op4
    );
    let op0_half_bottom = op0 & 0b11;
    if op0_half_bottom == 0b11 {
        pr_debug!("Load/Store Register");
        if (op2 & 0b10) != 0 {
            /* unsigned immediate (No post|pre indexing) */
            if op1 != 0 {
                /* V */
                handler_panic!(s_r, "SIMD is not supported: {:#X}", target_instruction);
            }
            let opc = ((target_instruction & bitmask!(23, 22)) >> 22) as u8;
            return if opc == 0b00 {
                pr_debug!("STR(unsigned immediate)");
                store::emulate_unsigned_immediate_store_register(
                    s_r,
                    target_instruction,
                    far,
                    hpfar,
                )
            } else {
                pr_debug!("LDR(unsigned immediate)");
                load::emulate_unsigned_immediate_load_register(s_r, target_instruction, far, hpfar)
            };
        } else if (op3 & 0b100000) != 0 {
            match op4 {
                0b00 => {
                    println!("Atomic Operation")
                }
                0b10 => {
                    pr_debug!("Load/Store Register Offset");
                    if op1 != 0 {
                        /* V */
                        handler_panic!(s_r, "SIMD is not supported: {:#X}", target_instruction);
                    }
                    let opc = ((target_instruction & bitmask!(23, 22)) >> 22) as u8;
                    return if opc == 0b00 {
                        /* when implements SIMD, opc of SIMD-STR may not be 0b00 */
                        pr_debug!("STR Register Offset");
                        store::emulate_store_register_register_offset(
                            s_r,
                            target_instruction,
                            far,
                            hpfar,
                        )
                    } else {
                        pr_debug!("LDR Register Offset");
                        load::emulate_load_register_register_offset(
                            s_r,
                            target_instruction,
                            far,
                            hpfar,
                        )
                    };
                }
                _ => {
                    println!("Load/Store pac")
                }
            }
        } else {
            if op1 != 0 {
                /* V */
                handler_panic!(s_r, "SIMD is not supported: {:#X}", target_instruction);
            }
            let opc = ((target_instruction & bitmask!(23, 22)) >> 22) as u8;
            return if opc == 0b00 {
                /* when implements SIMD, opc of SIMD-STR may not be 0b00 */
                pr_debug!("STR");
                store::emulate_store_register(s_r, target_instruction, far, hpfar)
            } else {
                pr_debug!("LDR");
                load::emulate_load_register(s_r, target_instruction, far, hpfar)
            };
        }
    } else if op0_half_bottom == 0b10 {
        pr_debug!("Load/Store Register Pair");
        if op1 != 0 {
            /* V */
            handler_panic!(s_r, "SIMD is not supported: {:#X}", target_instruction);
        }
        return if (target_instruction & (1 << 22)) != 0 {
            pr_debug!("LDP");
            load::emulate_load_pair(s_r, target_instruction, far, hpfar)
        } else {
            pr_debug!("STP");
            store::emulate_store_pair(s_r, target_instruction, far, hpfar)
        };
    } else if op0_half_bottom == 0b01 {
        {
            if (op2 & (1 << 1)) == 0 {
                pr_debug!("Load Register Literal");
                if op1 != 0 {
                    /* V */
                    println!("SIMD is not supported: {:#X}", target_instruction);
                    return Err(EmulationError::Unsupported);
                }
                return load::emulate_literal_load_register(s_r, target_instruction, far, hpfar);
            }
        }
    }
    println!("Unknown Instruction: {:#X}", target_instruction);
    Err(EmulationError::Unsupported)
}

#[cfg(feature = "mrs_msr_emulation")]
pub fn mrs_msr_handler(s_r: &mut GeneralPurposeRegisters, esr: u64) -> Result<(), ()> {
    let op0 = ((esr & bitmask!(21, 20)) >> 20) as u8;
    let op2 = ((esr & bitmask!(19, 17)) >> 17) as u8;
    let op1 = ((esr & bitmask!(16, 14)) >> 14) as u8;
    let crn = ((esr & bitmask!(13, 10)) >> 10) as u8;
    let target_register = ((esr & bitmask!(9, 5)) >> 5) as u8;
    let crm = ((esr & bitmask!(4, 1)) >> 1) as u8;
    let is_read_access = (esr & 1) == 1;
    let mut xzr = 0;
    let reg = if target_register == REGISTER_NUMBER_XZR {
        &mut xzr
    } else {
        &mut s_r[target_register as usize]
    };

    macro_rules! emulate_mrs_msr_if_matched {
        ($op0:literal, $op1:literal, $crn:literal, $crm:literal, $op2:literal) => {
            if op0 == $op0 && op1 == $op1 && crn == $crn && crm == $crm && op2 == $op2 {
                pr_debug!("S{}_{}_C{}_C{}_{}", $op0, $op1, $crn, $crm, $op2);
                if is_read_access {
                    unsafe {
                        asm!("mrs {:x}, S{}_{}_C{}_C{}_{}",
                                out(reg) * reg,
                                const $op0,
                                const $op1,
                                const $crn,
                                const $crm,
                                const $op2)
                    };
                } else {
                    unsafe{
                        asm!("msr S{}_{}_C{}_C{}_{}, {:x}",
                                const $op0,
                                const $op1,
                                const $crn,
                                const $crm,
                                const $op2,
                                in(reg) *reg)
                    };
                }
                common::cpu::advance_elr_el2();
                return Ok(());
            }
        };
    }

    #[cfg(feature = "a64fx")]
    {
        /* IMP_FJ_CORE_UARCH_RESTRECTION_EL1 */
        emulate_mrs_msr_if_matched!(3, 0, 11, 0, 5);
        /* IMP_PF_CTRL_EL1 */
        emulate_mrs_msr_if_matched!(3, 0, 11, 4, 0);
        /* IMP_BARRIER_CTRL_EL1 */
        emulate_mrs_msr_if_matched!(3, 0, 11, 12, 0);
        /* IMP_SCCR_CTRL_EL1 */
        emulate_mrs_msr_if_matched!(3, 0, 11, 8, 0);
    }

    println!(
        "Unknown Register: S{}_{}_C{}_C{}_{}",
        op0, op1, crn, crm, op2
    );
    Err(())
}

fn faulting_va_to_ipa_load(far: u64) -> Result<usize, ()> {
    convert_virtual_address_to_intermediate_physical_address_el1_read(far as usize)
}

fn faulting_va_to_ipa_store(far: u64) -> Result<usize, ()> {
    convert_virtual_address_to_intermediate_physical_address_el1_write(far as usize)
}

fn get_virtual_address_to_access_ipa(
    intermediate_physical_address: usize,
    is_write_access: bool,
) -> Result<usize, ()> {
    if is_write_access {
        if let Ok(pa) =
            convert_virtual_address_to_physical_address_el2_write(intermediate_physical_address)
        {
            return if pa != intermediate_physical_address {
                println!("IPA({:#X}) != VA({:#X})", intermediate_physical_address, pa);
                Err(())
            } else {
                Ok(intermediate_physical_address)
            };
        }
    } else if let Ok(pa) =
        convert_virtual_address_to_physical_address_el2_read(intermediate_physical_address)
    {
        return if pa != intermediate_physical_address {
            println!("IPA({:#X}) != VA({:#X})", intermediate_physical_address, pa);
            Err(())
        } else {
            Ok(intermediate_physical_address)
        };
    }
    println!("Map {:#X}", intermediate_physical_address);
    map_address(
        intermediate_physical_address & PAGE_MASK,
        intermediate_physical_address & PAGE_MASK,
        PAGE_SIZE,
        true,
        true,
        false,
        true,
    )?;
    Ok(intermediate_physical_address)
}

fn write_back_index_register_imm9(base_register: &mut u64, imm9_u32: u32) {
    unsafe {
        asm!("
            sbfx {imm9}, {imm9}, #0, #9
            add  {base_reg}, {base_reg}, {imm9}
            ",
            imm9 = inout(reg) (imm9_u32 as u64) => _ ,
            base_reg = inout(reg) *base_register)
    };
}

fn write_back_index_register_imm7(base_register: &mut u64, imm7_u32: u32) {
    unsafe {
        asm!("
            sbfx {imm7}, {imm7}, #0, #7
            add  {base_reg}, {base_reg}, {imm7}
            ",
        imm7 = inout(reg) (imm7_u32 as u64) => _ ,
        base_reg = inout(reg) *base_register)
    };
}
