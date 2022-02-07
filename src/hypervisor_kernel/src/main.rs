#![no_std]
#![no_main]
#![feature(asm)]
#![feature(asm_const)]
#![feature(global_asm)]
#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_extra)]
#![feature(maybe_uninit_array_assume_init)]
#![feature(naked_functions)]
#![feature(panic_info_message)]

#[macro_use]
mod serial_port;
mod multi_core;
mod panic;
mod psci;

use crate::psci::{handle_psci_call, PsciFunctionId};

use common::cpu::secure_monitor_call;
use common::{SystemInformation, ALLOC_SIZE, PAGE_SIZE};

use core::mem::MaybeUninit;

const EC_HVC: u64 = 0b010110;
const EC_SMC_AA64: u64 = 0b010111;

const SMC_INSTRUCTION_SIZE: usize = 4;

static mut MEMORY_POOL: ([MaybeUninit<usize>; ALLOC_SIZE / PAGE_SIZE], usize) =
    (MaybeUninit::uninit_array(), 0);

#[repr(C)]
#[derive(Debug)]
pub struct StoredRegisters {
    x30: u64,
    x29: u64,
    x19: u64,
    x18: u64,
    x17: u64,
    x16: u64,
    x15: u64,
    x14: u64,
    x13: u64,
    x12: u64,
    x11: u64,
    x10: u64,
    x9: u64,
    x8: u64,
    x7: u64,
    x6: u64,
    x5: u64,
    x4: u64,
    x3: u64,
    x2: u64,
    x1: u64,
    x0: u64,
}

#[no_mangle]
fn hypervisor_main(system_information: &mut SystemInformation) {
    if let Some(s_info) = &system_information.serial_port {
        unsafe { serial_port::init_default_serial_port(s_info.clone()) };
    }
    unsafe { MEMORY_POOL = system_information.memory_pool.clone() };

    println!("Hello,world from Hypervisor Kernel!!");
    unsafe { asm!("adr {:x}, vector_table_el2", out(reg)system_information.vbar_el2 ) };
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
    println!("Synchronous Exception!!");
    let esr_el2: u64;
    let far_el2: u64;
    let hpfar_el2: u64;
    unsafe { asm!("mrs {:x}, far_el2", out(reg) far_el2) };
    unsafe { asm!("mrs {:x}, esr_el2", out(reg) esr_el2) };
    unsafe { asm!("mrs {:x}, hpfar_el2", out(reg) hpfar_el2) };
    println!("ESR_EL2: {:#X}", esr_el2);
    println!("FAR_EL2: {:#X}", far_el2);
    println!("HPFAR_EL2: {:#X}", hpfar_el2);

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
            println!("SecureMonitor Call: {:#X}", smc_number);
            println!("Registers: {:#X?}", regs);
            if smc_number == 0 {
                if let Ok(psci_function_id) = PsciFunctionId::try_from(regs.x0) {
                    handle_psci_call(psci_function_id, regs);
                } else {
                    println!("Unknown Secure Monitor Call: {:#X}", regs.x0);
                    println!("Try to call secure monitor.");
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
        ec => {
            panic!("Unknown EC: {:#X}", ec);
        }
    }
    println!("Return to EL1.");
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
    stp x1,  x0,  [sp, #-16]!
    stp x3,  x2,  [sp, #-16]!
    stp x5,  x4,  [sp, #-16]!
    stp x7,  x6,  [sp, #-16]!
    stp x9,  x8,  [sp, #-16]!
    stp x11, x10, [sp, #-16]!
    stp x13, x12, [sp, #-16]!
    stp x15, x14, [sp, #-16]!
    stp x17, x16, [sp, #-16]!
    stp x19, x18, [sp, #-16]!
    stp x30, x29, [sp, #-16]!
    mov x29, sp
    mov x0, sp
    bl  synchronous_exception_handler
    mov sp, x29
    ldp x30, x29, [sp], #16
    ldp x19, x18, [sp], #16
    ldp x17, x16, [sp], #16
    ldp x15, x14, [sp], #16
    ldp x13, x12, [sp], #16
    ldp x11, x10, [sp], #16
    ldp x9,  x8,  [sp], #16
    ldp x7,  x6,  [sp], #16
    ldp x5,  x4,  [sp], #16
    ldp x3,  x2,  [sp], #16
    ldp x1,  x0,  [sp], #16
    eret

.balign 0x080
irq_lower_aa64:
    nop

.balign 0x080
fiq_lower_aa64:
    nop

.balign 0x080
s_error_lower_aa64:
    // up to 32 instructions
    stp x1,  x0,  [sp, #-16]!
    stp x3,  x2,  [sp, #-16]!
    stp x5,  x4,  [sp, #-16]!
    stp x7,  x6,  [sp, #-16]!
    stp x9,  x8,  [sp, #-16]!
    stp x11, x10, [sp, #-16]!
    stp x13, x12, [sp, #-16]!
    stp x15, x14, [sp, #-16]!
    stp x17, x16, [sp, #-16]!
    stp x19, x18, [sp, #-16]!
    stp x30, x29, [sp, #-16]!
    mov x29, sp
    mov x0, sp
    bl  s_error_exception_handler
    mov sp, x29
    ldp x30, x29, [sp], #16
    ldp x19, x18, [sp], #16
    ldp x17, x16, [sp], #16
    ldp x15, x14, [sp], #16
    ldp x13, x12, [sp], #16
    ldp x11, x10, [sp], #16
    ldp x9,  x8,  [sp], #16
    ldp x7,  x6,  [sp], #16
    ldp x5,  x4,  [sp], #16
    ldp x3,  x2,  [sp], #16
    ldp x1,  x0,  [sp], #16
    eret

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
