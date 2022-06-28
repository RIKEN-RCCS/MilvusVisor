// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]
#![feature(asm_const)]
#![feature(const_maybe_uninit_uninit_array)]
#![feature(const_mut_refs)]
#![feature(core_intrinsics)]
#![feature(format_args_nl)]
#![feature(maybe_uninit_uninit_array)]
#![feature(naked_functions)]
#![feature(panic_info_message)]

#[macro_use]
mod serial_port;
mod acpi_protect;
mod drivers;
mod emulation;
mod fast_restore;
mod memory_hook;
mod multi_core;
mod paging;
mod panic;
mod pci;
mod psci;
mod smmu;

use common::cpu::{get_mpidr_el1, secure_monitor_call};
use common::{acpi, bitmask};
use common::{SystemInformation, ALLOC_SIZE, PAGE_SIZE};

use core::arch::{asm, global_asm};
use core::mem::MaybeUninit;

const EC_HVC: u8 = 0b010110;
const EC_SMC_AA64: u8 = 0b010111;
const EC_DATA_ABORT: u8 = 0b100100;

const INSTRUCTION_SIZE: usize = 4;

static mut MEMORY_POOL: ([MaybeUninit<usize>; ALLOC_SIZE / PAGE_SIZE], usize) =
    (MaybeUninit::uninit_array(), 0);
static mut ACPI_RSDP: Option<usize> = None;
static mut BSP_MPIDR: u64 = 0;

#[repr(C)]
#[derive(Clone, Debug)]
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
    unsafe {
        MEMORY_POOL = system_information.memory_pool.clone();
        ACPI_RSDP = system_information.acpi_rsdp_address;
    }

    println!("Hello,world from Hypervisor Kernel!!");
    show_features_status();

    if let Some(ecam_info) = &system_information.ecam_info {
        pci::init_pci(ecam_info.address, ecam_info.start_bus, ecam_info.end_bus);
    }
    #[cfg(feature = "smmu")]
    if let Some(smmu_base_address) = system_information.smmu_v3_base_address {
        smmu::init_smmu(
            smmu_base_address,
            system_information
                .acpi_rsdp_address
                .and_then(|rsdp| acpi::get_acpi_table(rsdp, &acpi::iort::IORT::SIGNATURE).ok()),
        );
    }

    #[cfg(feature = "acpi_table_protection")]
    if let Some(rsdp_address) = unsafe { ACPI_RSDP } {
        acpi_protect::init_table_protection(rsdp_address);
    }

    #[cfg(feature = "fast_restore")]
    {
        /* Fast Restore Initialization */
        fast_restore::add_memory_save_list(system_information.memory_save_list);
        fast_restore::add_trap_to_exit_boot_service(system_information.exit_boot_service_address);
        fast_restore::create_memory_trap_for_save_memory();
    }

    unsafe {
        BSP_MPIDR = get_mpidr_el1();
        asm!("adr {:x}, vector_table_el2", out(reg) system_information.vbar_el2 );
    }
    return;
}

fn show_features_status() {
    macro_rules! print_is_feature_enabled {
        ($feature:expr) => {
            println!(
                "Feature({}): {}",
                $feature,
                if cfg!(feature = $feature) {
                    "Enabled"
                } else {
                    "Disabled"
                }
            )
        };
    }

    print_is_feature_enabled!("smmu");
    print_is_feature_enabled!("i210");
    print_is_feature_enabled!("mt27800");
    print_is_feature_enabled!("fast_restore");
    print_is_feature_enabled!("acpi_table_protection");
    print_is_feature_enabled!("contiguous_bit");
    print_is_feature_enabled!("a64fx");
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

    let ec = ((esr_el2 >> 26) & bitmask!(5, 0)) as u8;

    /* FastRestore Hook */
    #[cfg(feature = "fast_restore")]
    {
        fast_restore::perform_restore_if_needed();
        if fast_restore::check_memory_access_for_memory_save_list(ec, far_el2) {
            return;
        }
    }

    match ec {
        EC_HVC => match (esr_el2 & bitmask!(15, 0)) as u16 {
            fast_restore::HVC_EXIT_BOOT_SERVICE_TRAP => {
                #[cfg(feature = "fast_restore")]
                fast_restore::exit_boot_service_trap_main(regs, elr_el2);
            }
            fast_restore::HVC_AFTER_EXIT_BOOT_SERVICE_TRAP => {
                #[cfg(feature = "fast_restore")]
                fast_restore::after_exit_boot_service_trap_main(regs, elr_el2);
            }
            hvc_number => {
                println!("Hypervisor Call: {:#X}", hvc_number);
            }
        },
        EC_SMC_AA64 => {
            /* Adjust return address */
            unsafe {
                asm!("mrs {t}, ELR_EL2
                           add {t}, {t}, {size}
                           msr ELR_EL2, {t}", t = out(reg) _, size = const INSTRUCTION_SIZE )
            };
            let smc_number = esr_el2 & bitmask!(15, 0);
            pr_debug!("SecureMonitor Call: {:#X}", smc_number);
            pr_debug!("Registers: {:#X?}", regs);
            if smc_number == 0 {
                if let Ok(psci_function_id) = psci::PsciFunctionId::try_from(regs.x0) {
                    psci::handle_psci_call(psci_function_id, regs);
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
                handler_panic!(regs, "SMC {:#X} is not implemented.", smc_number);
            }
        }
        EC_DATA_ABORT => {
            pr_debug!("Data Abort");
            if let Err(e) =
                emulation::data_abort_handler(regs, esr_el2, elr_el2, far_el2, hpfar_el2)
            {
                handler_panic!(regs, "Failed to emulate the instruction: {:?}", e);
            }
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
    let spsr_el2: u64;
    let hpfar_el2: u64;
    let mpidr_el1: u64;
    unsafe { asm!("mrs {:x}, esr_el2", out(reg) esr_el2) };
    unsafe { asm!("mrs {:x}, elr_el2", out(reg) elr_el2) };
    unsafe { asm!("mrs {:x}, far_el2", out(reg) far_el2) };
    unsafe { asm!("mrs {:x}, spsr_el2", out(reg) spsr_el2) };
    unsafe { asm!("mrs {:x}, hpfar_el2", out(reg) hpfar_el2) };
    unsafe { asm!("mrs {:x}, mpidr_el1", out(reg) mpidr_el1) };
    if let Some(s) = unsafe { crate::serial_port::DEFAULT_SERIAL_PORT.as_ref() } {
        unsafe { s.force_release_write_lock() };
    }
    println!("ESR_EL2: {:#X}", esr_el2);
    println!("ELR_EL2: {:#X}", elr_el2);
    println!("FAR_EL2: {:#X}", far_el2);
    println!("SPSR_EL2: {:#X}", spsr_el2);
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
