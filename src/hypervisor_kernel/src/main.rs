// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;

use common::cpu::*;
use common::spin_flag::SpinLockFlag;
use common::{
    COMPILER_INFO, GeneralPurposeRegisters, HYPERVISOR_HASH_INFO, HYPERVISOR_NAME,
    MemoryAllocationError, MemoryAllocator, PAGE_SHIFT, SystemInformation, acpi, bitmask,
};

#[macro_use]
mod drivers;
mod acpi_protect;
mod emulation;
#[cfg(feature = "fast_restore")]
mod fast_restore;
mod gic;
mod memory_hook;
mod multi_core;
mod paging;
mod panic;
mod pci;
mod psci;
mod smmu;

const EC_HVC: u8 = 0b010110;
const EC_SMC_AA64: u8 = 0b010111;
const EC_DATA_ABORT: u8 = 0b100100;
#[cfg(feature = "mrs_msr_emulation")]
const EC_MRS_MSR: u8 = 0b011000;

static mut MEMORY_ALLOCATOR: (SpinLockFlag, MaybeUninit<MemoryAllocator>) =
    (SpinLockFlag::new(), MaybeUninit::uninit());
static mut ACPI_RSDP: Option<NonZeroUsize> = None;
static mut BSP_MPIDR: u64 = 0;

#[macro_export]
macro_rules! handler_panic {
    ($s_r:expr, $($t:tt)*) => {
        $crate::interrupt_handler_panic($s_r, format_args!($($t)*))
    };
}

#[unsafe(no_mangle)]
fn hypervisor_main(system_information: &mut SystemInformation) {
    if let Some(s_info) = &system_information.serial_port {
        drivers::serial_port::init_default_serial_port(s_info.clone());
    }

    show_kernel_info();

    let (lock, allocator) = unsafe { (&raw mut MEMORY_ALLOCATOR).as_mut() }.unwrap();
    lock.lock();
    unsafe { allocator.assume_init_mut() }.init(
        system_information.available_memory_info.0,
        system_information.available_memory_info.1 << PAGE_SHIFT,
    );
    lock.unlock();

    unsafe { ACPI_RSDP = system_information.acpi_rsdp_address };

    memory_hook::init_memory_access_handler();

    if let Some(ecam_info) = &system_information.ecam_info {
        pci::init_pci(ecam_info.address, ecam_info.start_bus, ecam_info.end_bus);
    }

    if let Some(rsdp_address) = system_information.acpi_rsdp_address {
        gic::init_gic(rsdp_address.get());
    }

    #[cfg(feature = "smmu")]
    if let Some(smmu_base_address) = system_information.smmu_v3_base_address {
        smmu::init_smmu(
            smmu_base_address.get(),
            system_information.acpi_rsdp_address.and_then(|rsdp| {
                acpi::get_acpi_table(rsdp.get(), &acpi::iort::IORT::SIGNATURE).ok()
            }),
        );
    }

    if let Some((spin_table_address, length)) = system_information.spin_table_info {
        multi_core::setup_spin_table(spin_table_address, length.get());
    }

    #[cfg(feature = "acpi_table_protection")]
    if let Some(rsdp_address) = unsafe { ACPI_RSDP } {
        acpi_protect::init_table_protection(rsdp_address.get());
    }

    #[cfg(feature = "fast_restore")]
    if let Some(list) = system_information.memory_save_list {
        /* Fast Restore Initialization */
        fast_restore::add_memory_save_list(list.as_ptr());
        fast_restore::create_memory_trap_for_save_memory();
        if let Some(exit_boot_service_address) = system_information.exit_boot_service_address {
            fast_restore::add_trap_to_exit_boot_service(exit_boot_service_address.get());
        }
    }

    unsafe { BSP_MPIDR = get_mpidr_el1() };
    unsafe extern "C" {
        fn vector_table_el2();

    }
    system_information.vbar_el2 = vector_table_el2 as *const fn() as usize as u64;
}

fn show_kernel_info() {
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

    if let Some(hash_info) = HYPERVISOR_HASH_INFO {
        println!(
            "{} Kernel Version {}({hash_info})",
            HYPERVISOR_NAME,
            env!("CARGO_PKG_VERSION")
        );
    } else {
        println!(
            "{} Kernel Version {}",
            HYPERVISOR_NAME,
            env!("CARGO_PKG_VERSION")
        );
    }
    if let Some(compiler_info) = COMPILER_INFO {
        println!("Compiler Information: {compiler_info}");
    }

    print_is_feature_enabled!("smmu");
    print_is_feature_enabled!("i210");
    print_is_feature_enabled!("mt27800");
    print_is_feature_enabled!("fast_restore");
    print_is_feature_enabled!("acpi_table_protection");
    print_is_feature_enabled!("contiguous_bit");
    print_is_feature_enabled!("a64fx");
    print_is_feature_enabled!("advanced_memory_manager");
    print_is_feature_enabled!("mrs_msr_emulation");
    print_is_feature_enabled!("virtio");
    print_is_feature_enabled!("virtio_net");
}

/// Allocate memory from memory pool
///
/// # Arguments
/// * `pages` - The number of pages to allocate, the allocation size is `pages` << [`PAGE_SHIFT`]
/// * `align` - The alignment of the returned address, if `None`, [`PAGE_SHIFT`] will be used
///
/// # Result
/// If the allocation is succeeded, Ok(start_address), otherwise Err(())
pub fn allocate_memory(pages: usize, align: Option<usize>) -> Result<usize, MemoryAllocationError> {
    let (lock, allocator) = unsafe { (&raw mut MEMORY_ALLOCATOR).as_mut() }.unwrap();
    lock.lock();
    let result = unsafe { allocator.assume_init_mut() }
        .allocate(pages << PAGE_SHIFT, align.unwrap_or(PAGE_SHIFT));
    lock.unlock();
    result
}

/// Free memory to memory pool
///
/// # Arguments
/// * address: The start address to return to memory pool, it must be allocated by [`allocate_memory`]
/// * pages: The number of allocated pages
///
/// # Result
/// If succeeded, Ok(()), otherwise Err(())
pub fn free_memory(address: usize, pages: usize) -> Result<(), MemoryAllocationError> {
    let (lock, allocator) = unsafe { (&raw mut MEMORY_ALLOCATOR).as_mut() }.unwrap();
    lock.lock();
    let result = unsafe { allocator.assume_init_mut() }.free(address, pages << PAGE_SHIFT);
    lock.unlock();
    result
}

#[unsafe(no_mangle)]
extern "C" fn synchronous_exception_handler(regs: &mut GeneralPurposeRegisters) {
    let esr_el2 = get_esr_el2();
    let elr_el2 = get_elr_el2();
    let far_el2 = get_far_el2();
    let hpfar_el2 = get_hpfar_el2();
    let spsr_el2 = get_spsr_el2();

    pr_debug!("Synchronous Exception!!");
    pr_debug!("ESR_EL2: {:#X}", esr_el2);
    pr_debug!("ELR_EL2: {:#X}", elr_el2);
    pr_debug!("FAR_EL2: {:#X}", far_el2);
    pr_debug!("HPFAR_EL2: {:#X}", hpfar_el2);
    pr_debug!("MPIDR_EL1: {:#X}", get_mpidr_el1());
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
            #[cfg(feature = "fast_restore")]
            fast_restore::HVC_EXIT_BOOT_SERVICE_TRAP => {
                fast_restore::exit_boot_service_trap_main(regs, elr_el2);
            }
            #[cfg(feature = "fast_restore")]
            fast_restore::HVC_AFTER_EXIT_BOOT_SERVICE_TRAP => {
                fast_restore::after_exit_boot_service_trap_main(regs, elr_el2);
            }
            hvc_number => {
                println!("Hypervisor Call: {:#X}", hvc_number);
            }
        },
        EC_SMC_AA64 => {
            /* Adjust return address */
            advance_elr_el2();
            let smc_number = esr_el2 & bitmask!(15, 0);
            pr_debug!("SecureMonitor Call: {:#X}", smc_number);
            pr_debug!("Registers: {:#X?}", regs);
            if smc_number == 0 {
                if let Ok(psci_function_id) = psci::PsciFunctionId::try_from(regs[0]) {
                    psci::handle_psci_call(psci_function_id, regs);
                } else {
                    pr_debug!("Unknown Secure Monitor Call: {:#X}", regs[0]);
                    secure_monitor_call(regs);
                }
            } else {
                handler_panic!(regs, "SMC {:#X} is not implemented.", smc_number);
            }
        }
        EC_DATA_ABORT => {
            pr_debug!("Data Abort");
            if let Err(e) =
                emulation::data_abort_handler(regs, esr_el2, elr_el2, far_el2, hpfar_el2, spsr_el2)
            {
                handler_panic!(regs, "Failed to emulate the instruction: {:?}", e);
            }
        }
        #[cfg(feature = "mrs_msr_emulation")]
        EC_MRS_MSR => {
            pr_debug!("MRS/MSR Abort");
            if let Err(e) = emulation::mrs_msr_handler(regs, esr_el2) {
                handler_panic!(regs, "Failed to emulate MRS/MSR: {:?}", e);
            }
        }
        ec => {
            handler_panic!(regs, "Unknown EC: {:#X}", ec);
        }
    }
    pr_debug!("Return to EL1.");
}

#[unsafe(no_mangle)]
extern "C" fn s_error_exception_handler(regs: &mut GeneralPurposeRegisters) {
    handler_panic!(regs, "S Error Exception!!");
}

#[track_caller]
fn interrupt_handler_panic(s_r: &GeneralPurposeRegisters, f: core::fmt::Arguments) -> ! {
    let esr_el2 = get_esr_el2();
    let elr_el2 = get_elr_el2();
    let far_el2 = get_far_el2();
    let spsr_el2 = get_spsr_el2();
    let hpfar_el2 = get_hpfar_el2();
    let mpidr_el1 = get_mpidr_el1();

    unsafe { drivers::serial_port::force_release_serial_port_lock() };
    println!("ESR_EL2: {:#X}", esr_el2);
    println!("ELR_EL2: {:#X}", elr_el2);
    println!("FAR_EL2: {:#X}", far_el2);
    println!("SPSR_EL2: {:#X}", spsr_el2);
    println!("HPFAR_EL2: {:#X}", hpfar_el2);
    println!("MPIDR_EL1: {:#X}", mpidr_el1);
    println!("Registers: {:#X?}", s_r);
    panic!("{}", f)
}

global_asm!("
.section    .text
.type       vector_table_el2, %function
.size       vector_table_el2, 0x800
.balign     0x800
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

.type   synchronous_lower_aa64_save_registers, %function
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

.size   synchronous_lower_aa64_save_registers, . - synchronous_lower_aa64_save_registers

.type   s_error_lower_aa64_save_registers, %function
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

.size   s_error_lower_aa64_save_registers, . - s_error_lower_aa64_save_registers

.type   lower_aa64_restore_registers_and_eret, %function
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
    isb
    eret
.size   lower_aa64_restore_registers_and_eret, . - lower_aa64_restore_registers_and_eret
", SR_SIZE = const size_of::<GeneralPurposeRegisters>());
