// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]
#![feature(asm_const)]
#![feature(const_maybe_uninit_uninit_array)]
#![feature(const_mut_refs)]
#![feature(maybe_uninit_uninit_array)]
#![feature(naked_functions)]
#![feature(panic_info_message)]

#[macro_use]
mod serial_port;
mod drivers;
mod emulation;
mod memory_hook;
mod multi_core;
mod paging;
mod panic;
mod pci;
mod psci;
mod smmu;

use crate::psci::{handle_psci_call, PsciFunctionId};
use crate::serial_port::DEFAULT_SERIAL_PORT;

use common::acpi;
use common::cpu::secure_monitor_call;
use common::{SystemInformation, ALLOC_SIZE, PAGE_SIZE};

use core::arch::{asm, global_asm};
use core::mem::MaybeUninit;

const EC_HVC: u64 = 0b010110;
const EC_SMC_AA64: u64 = 0b010111;
const EC_DATA_ABORT: u64 = 0b100100;

const SMC_INSTRUCTION_SIZE: usize = 4;

static mut MEMORY_POOL: ([MaybeUninit<usize>; ALLOC_SIZE / PAGE_SIZE], usize) =
    (MaybeUninit::uninit_array(), 0);

#[repr(C)]
#[derive(Debug)]
pub struct StoredRegisters {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
    sp: u64,
}

#[macro_export]
macro_rules! handler_panic {
    ($s_r:expr, $($t:tt)*) => {
        $crate::interrupt_handler_panic($s_r, format_args!($($t)*))
    };
}

#[no_mangle]
fn hypervisor_main(system_information: &mut SystemInformation) {
    if let Some(s_info) = &system_information.serial_port {
        unsafe { serial_port::init_default_serial_port(s_info.clone()) };
    }
    unsafe { MEMORY_POOL = system_information.memory_pool.clone() };

    println!("Hello,world from Hypervisor Kernel!!");
    if let Some(ecam_info) = &system_information.ecam_info {
        pci::init_pci(ecam_info.address, ecam_info.start_bus, ecam_info.end_bus);
    }
    if let Some(smmu_base_address) = system_information.smmu_v3_base_address {
        smmu::init_smmu(
            smmu_base_address,
            system_information
                .acpi_rsdp_address
                .and_then(|rsdp| acpi::get_acpi_table(rsdp, &acpi::iort::IORT::SIGNATURE).ok()),
        );
    }
    unsafe { asm!("adr {:x}, vector_table_el2", out(reg) system_information.vbar_el2 ) };
    return;
}

pub fn allocate_memory(pages: usize) -> Result<usize, ()> {
    if unsafe { MEMORY_POOL.1 < pages } {
        return Err(());
    }
    unsafe { MEMORY_POOL.1 -= pages };
    return Ok(unsafe { MEMORY_POOL.0[MEMORY_POOL.1].assume_init() });
}

#[no_mangle]
extern "C" fn synchronous_exception_handler(regs: &mut StoredRegisters) {
    let esr_el2: u64;
    let elr_el2: u64;
    let far_el2: u64;
    let hpfar_el2: u64;
    unsafe { asm!("mrs {:x}, esr_el2", out(reg) esr_el2) };
    unsafe { asm!("mrs {:x}, elr_el2", out(reg) elr_el2) };
    unsafe { asm!("mrs {:x}, far_el2", out(reg) far_el2) };
    unsafe { asm!("mrs {:x}, hpfar_el2", out(reg) hpfar_el2) };

    pr_debug!("Synchronous Exception!!");
    pr_debug!("ESR_EL2: {:#X}", esr_el2);
    pr_debug!("ELR_EL2: {:#X}", elr_el2);
    pr_debug!("FAR_EL2: {:#X}", far_el2);
    pr_debug!("HPFAR_EL2: {:#X}", hpfar_el2);
    pr_debug!("MPIDR_EL1: {:#X}", mpidr_el1);
    pr_debug!("Registers: {:#X?}", regs);

    match (esr_el2 >> 26) & ((1 << 6) - 1) {
        EC_HVC => {
            let hvc_number = esr_el2 & ((1 << 16) - 1);
            println!("Hypervisor Call: {:#X}", hvc_number);
        }
        EC_SMC_AA64 => {
            /* Adjust return address */
            unsafe {
                asm!("mrs {t}, ELR_EL2
                           add {t}, {t}, {size}
                           msr ELR_EL2, {t}", t = out(reg) _, size = const SMC_INSTRUCTION_SIZE )
            };
            let smc_number = esr_el2 & ((1 << 16) - 1);
            pr_debug!("SecureMonitor Call: {:#X}", smc_number);
            pr_debug!("Registers: {:#X?}", regs);
            if smc_number == 0 {
                if let Ok(psci_function_id) = PsciFunctionId::try_from(regs.x0) {
                    handle_psci_call(psci_function_id, regs);
                } else {
                    pr_debug!("Unknown Secure Monitor Call: {:#X}", regs.x0);
                    secure_monitor_call(
                        &mut regs.x0,
                        &mut regs.x1,
                        &mut regs.x2,
                        &mut regs.x3,
                        &mut regs.x4,
                        &mut regs.x5,
                        &mut regs.x6,
                        &mut regs.x7,
                        &mut regs.x8,
                        &mut regs.x9,
                        &mut regs.x10,
                        &mut regs.x11,
                        &mut regs.x12,
                        &mut regs.x13,
                        &mut regs.x14,
                        &mut regs.x15,
                        &mut regs.x16,
                        &mut regs.x17,
                    );
                }
            } else {
                panic!("SMC {:#X} is not implemented.", smc_number);
            }
        }
        EC_DATA_ABORT => {
            pr_debug!("Data Abort");
            emulation::data_abort_handler(regs, esr_el2, elr_el2, far_el2, hpfar_el2)
                .expect("Failed to emulate the instruction");
        }
        ec => {
            handler_panic!(regs, "Unknown EC: {:#X}", ec);
        }
    }
    pr_debug!("Return to EL1.");
}

#[no_mangle]
extern "C" fn s_error_exception_handler() {
    println!("S Error Exception!!");
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}

#[track_caller]
fn interrupt_handler_panic(s_r: &StoredRegisters, f: core::fmt::Arguments) -> ! {
    let esr_el2: u64;
    let elr_el2: u64;
    let far_el2: u64;
    let hpfar_el2: u64;
    let mpidr_el1: u64;
    unsafe { asm!("mrs {:x}, esr_el2", out(reg) esr_el2) };
    unsafe { asm!("mrs {:x}, elr_el2", out(reg) elr_el2) };
    unsafe { asm!("mrs {:x}, far_el2", out(reg) far_el2) };
    unsafe { asm!("mrs {:x}, hpfar_el2", out(reg) hpfar_el2) };
    unsafe { asm!("mrs {:x}, mpidr_el1", out(reg) mpidr_el1) };
    if let Some(s) = unsafe { DEFAULT_SERIAL_PORT.as_ref() } {
        unsafe { s.force_release_write_lock() };
    }
    println!("ESR_EL2: {:#X}", esr_el2);
    println!("ELR_EL2: {:#X}", elr_el2);
    println!("FAR_EL2: {:#X}", far_el2);
    println!("HPFAR_EL2: {:#X}", hpfar_el2);
    println!("MPIDR_EL1: {:#X}", mpidr_el1);
    println!("Registers: {:#X?}", s_r);
    panic!("{}", f)
}

global_asm!(
    "
.section .text
.balign 0x800
vector_table_el2:

.balign 0x080
synchronous_current_sp0:
    nop

.balign 0x080
irq_current_sp0:
    nop

.balign 0x080
fiq_current_sp0:
    nop

.balign 0x080
s_error_current_sp0:
    nop

.balign 0x080
synchronous_current_spx:
    nop

.balign 0x080
irq_current_spx:
    nop

.balign 0x080
fiq_current_spx:
    nop

.balign 0x080
s_error_current_spx:
    nop

.balign 0x080
synchronous_lower_aa64:
    // up to 32 instructions
    b   synchronous_lower_aa64_save_registers
synchronous_lower_aa64_1:
    mov x29, sp
    mov x0, sp
    bl  synchronous_exception_handler
    mov sp, x29
    b   lower_aa64_restore_registers_and_eret

.balign 0x080
irq_lower_aa64:
    nop

.balign 0x080
fiq_lower_aa64:
    nop

.balign 0x080
s_error_lower_aa64:
    // up to 32 instructions
    b   s_error_lower_aa64_save_registers
s_error_lower_aa64_1:
    mov x29, sp
    mov x0, sp
    bl  s_error_exception_handler
    mov sp, x29
    b   lower_aa64_restore_registers_and_eret

.balign 0x080
synchronous_lower_aa32:
    nop

.balign 0x080
irq_lower_aa32:
    nop

.balign 0x080
fiq_lower_aa32:
    nop

.balign 0x080
s_error_lower_aa32:
    nop
"
);

global_asm!("
synchronous_lower_aa64_save_registers:
    sub sp,   sp, {SR_SIZE}
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mrs  x0,  spsr_el2
    ubfx x0,  x0, #0, #4    // and x0, x0, #0b1111
    cmp  x0, #0b0101        // EL1h
    b.ne 1f
    mrs  x0, sp_el1
    str  x0, [sp, #( 15 * 16 + 8)]
    b    synchronous_lower_aa64_1
1:
    mrs  x0, sp_el0
    str  x0, [sp, #( 15 * 16 + 8)]
    b   synchronous_lower_aa64_1

s_error_lower_aa64_save_registers:
    sub sp,   sp, {SR_SIZE}
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mrs  x0,  spsr_el2
    ubfx x0,  x0, #0, #4    // and x0, x0, #0b1111
    cmp  x0, #0b0101        // EL1h
    b.ne 1f
    mrs  x0, sp_el1
    str  x0, [sp, #( 15 * 16 + 8)]
    b    s_error_lower_aa64_1
1:
    mrs  x0, sp_el0
    str  x0, [sp, #( 15 * 16 + 8)]
    b   s_error_lower_aa64_1


lower_aa64_restore_registers_and_eret:
    mrs  x0,  spsr_el2
    ubfx x0,  x0, #0, #4    // and x0, x0, #0b1111
    cmp  x0, #0b0101        // EL1h
    b.ne 1f
    ldr  x0, [sp, #( 15 * 16 + 8)]
    msr  sp_el1, x0
    b    2f
1:
    ldr  x0, [sp, #( 15 * 16 + 8)]
    msr  sp_el0, x0
2:
    ldp x30, xzr, [sp, #( 15 * 16)]
    ldp x28, x29, [sp, #( 14 * 16)]
    ldp x26, x27, [sp, #( 13 * 16)]
    ldp x24, x25, [sp, #( 12 * 16)]
    ldp x22, x23, [sp, #( 11 * 16)]
    ldp x20, x21, [sp, #( 10 * 16)]
    ldp x18, x19, [sp, #(  9 * 16)]
    ldp x16, x17, [sp, #(  8 * 16)]
    ldp x14, x15, [sp, #(  7 * 16)]
    ldp x12, x13, [sp, #(  6 * 16)]
    ldp x10, x11, [sp, #(  5 * 16)]
    ldp  x8,  x9, [sp, #(  4 * 16)]
    ldp  x6,  x7, [sp, #(  3 * 16)]
    ldp  x4,  x5, [sp, #(  2 * 16)]
    ldp  x2,  x3, [sp, #(  1 * 16)]
    ldp  x0,  x1, [sp, #(  0 * 16)]
    add  sp,  sp, {SR_SIZE}
    eret
", SR_SIZE = const core::mem::size_of::<StoredRegisters>());
