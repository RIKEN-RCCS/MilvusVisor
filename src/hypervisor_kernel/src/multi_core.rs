// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! MultiCore Handling Functions
//!

use core::sync::atomic::{AtomicUsize, Ordering};

use common::{GeneralPurposeRegisters, PAGE_SHIFT, PAGE_SIZE, STACK_PAGES, cpu};

use crate::memory_hook::{
    StoreAccessHandlerEntry, StoreHookResult, add_memory_store_access_handler,
};
use crate::paging::{add_memory_access_trap, map_address};
use crate::psci::{PsciFunctionId, PsciReturnCode, call_psci_function};
use crate::{allocate_memory, free_memory};

pub static NUMBER_OF_RUNNING_AP: AtomicUsize = AtomicUsize::new(0);
pub static STACK_TO_FREE_LATER: AtomicUsize = AtomicUsize::new(0);

#[repr(C, align(16))]
struct HypervisorRegisters {
    cnthctl_el2: u64,
    cptr_el2: u64,
    ttbr0_el2: u64,
    mair_el2: u64,
    tcr_el2: u64,
    vbar_el2: u64,
    vttbr_el2: u64,
    vtcr_el2: u64,
    sctlr_el2: u64,
    hcr_el2: u64,
    el1_entry_point: u64,
    el1_context_id: u64,
}

pub fn setup_new_cpu(regs: &mut GeneralPurposeRegisters) {
    let stack_address = (allocate_memory(STACK_PAGES, Some(STACK_PAGES))
        .expect("Failed to allocate stack")
        + (STACK_PAGES << PAGE_SHIFT)) as u64;

    /* Write System Registers */
    let register_buffer = unsafe {
        &mut *((stack_address as usize - size_of::<HypervisorRegisters>())
            as *mut HypervisorRegisters)
    };
    register_buffer.cnthctl_el2 = cpu::get_cnthctl_el2();
    register_buffer.cptr_el2 = cpu::get_cptr_el2();
    register_buffer.ttbr0_el2 = cpu::get_ttbr0_el2();
    register_buffer.mair_el2 = cpu::get_mair_el2();
    register_buffer.tcr_el2 = cpu::get_tcr_el2();
    register_buffer.vbar_el2 = cpu::get_vbar_el2();
    register_buffer.vttbr_el2 = cpu::get_vttbr_el2();
    register_buffer.vtcr_el2 = cpu::get_vtcr_el2();
    register_buffer.sctlr_el2 = cpu::get_sctlr_el2();
    register_buffer.hcr_el2 = cpu::get_hcr_el2();
    register_buffer.el1_entry_point = regs[2];
    register_buffer.el1_context_id = regs[3];

    cpu::dsb();
    /* Flush Memory Cache for Application Processors */
    cpu::clean_data_cache_all();

    let cpu_boot_address_real_address =
        cpu::convert_virtual_address_to_physical_address_el2_read(cpu_boot as *const fn() as usize)
            .expect("Failed to convert virtual address to real address");

    regs[0] = call_psci_function(
        PsciFunctionId::CpuOn,
        regs[1],
        cpu_boot_address_real_address as u64,
        register_buffer as *const _ as usize as u64,
    );
    if regs[0] as i32 != PsciReturnCode::Success as i32 {
        if let Err(err) = free_memory(
            stack_address as usize - (STACK_PAGES << PAGE_SHIFT),
            STACK_PAGES,
        ) {
            println!("Failed to free memory: {:?}", err);
        }
        println!(
            "Failed to power on the cpu (MPIDR: {:#X}): {:?}",
            regs[1],
            PsciReturnCode::try_from(regs[0] as i32)
        );
        return;
    }
    NUMBER_OF_RUNNING_AP.fetch_add(1, Ordering::SeqCst);
    pr_debug!("The initialization completed.");
}

/// # ATTENTION
/// do not power off BSP(BSP's stack may not be aligned with [`STACK_PAGES`])
pub fn power_off_cpu() -> i32 {
    let stack_address = (cpu::get_sp() as usize) & !((STACK_PAGES << PAGE_SHIFT) - 1);

    loop {
        let current = STACK_TO_FREE_LATER.load(Ordering::Acquire);
        if let Ok(stack_address_to_free) = STACK_TO_FREE_LATER.compare_exchange(
            current,
            stack_address,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            if stack_address_to_free != 0 {
                if let Err(err) = free_memory(stack_address_to_free, STACK_PAGES) {
                    println!("Failed to free stack: {:?}", err);
                }
            }
            break;
        }
    }

    NUMBER_OF_RUNNING_AP.fetch_sub(1, Ordering::SeqCst);
    call_psci_function(PsciFunctionId::CpuOff, 0, 0, 0) as i32
}

pub fn setup_spin_table(base_address: usize, length: usize) {
    let aligned_base_address = if base_address == 0 {
        0
    } else {
        (base_address - 1) & !(PAGE_SIZE - 1)
    };
    let aligned_length =
        ((length + (base_address - aligned_base_address) - 1) & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    map_address(
        aligned_base_address,
        aligned_base_address,
        aligned_length,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map spin table");
    add_memory_access_trap(aligned_base_address, aligned_length, true, false)
        .expect("Failed to add trap of spin table");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        base_address,
        length,
        0,
        spin_table_store_access_handler,
    ))
    .expect("Failed to add store access handler");
}

fn spin_table_store_access_handler(
    accessing_memory_address: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    const SPIN_TABLE_STACK_ADDRESS_OFFSET: usize = cpu::AA64_INSTRUCTION_SIZE * 6;
    let stack_address = (allocate_memory(STACK_PAGES, Some(STACK_PAGES))
        .expect("Failed to allocate stack")
        + (STACK_PAGES << PAGE_SHIFT)) as u64;

    /* Write System Registers */
    let register_buffer = unsafe {
        &mut *((stack_address as usize - size_of::<HypervisorRegisters>())
            as *mut HypervisorRegisters)
    };
    register_buffer.cnthctl_el2 = cpu::get_cnthctl_el2();
    register_buffer.cptr_el2 = cpu::get_cptr_el2();
    register_buffer.ttbr0_el2 = cpu::get_ttbr0_el2();
    register_buffer.mair_el2 = cpu::get_mair_el2();
    register_buffer.tcr_el2 = cpu::get_tcr_el2();
    register_buffer.vbar_el2 = cpu::get_vbar_el2();
    register_buffer.vttbr_el2 = cpu::get_vttbr_el2();
    register_buffer.vtcr_el2 = cpu::get_vtcr_el2();
    register_buffer.sctlr_el2 = cpu::get_sctlr_el2();
    register_buffer.hcr_el2 = cpu::get_hcr_el2();
    register_buffer.el1_entry_point = data;
    register_buffer.el1_context_id = 0;

    let register_buffer_real_address = cpu::convert_virtual_address_to_physical_address_el2_read(
        register_buffer as *const _ as usize,
    )
    .expect("Failed to convert virtual address to real address");
    let spin_table_boot_real_address = cpu::convert_virtual_address_to_physical_address_el2_read(
        spin_table_boot as *const fn() as usize,
    )
    .expect("Failed to convert virtual address to real address");
    let spin_table_boot_stack_address = unsafe {
        &*((spin_table_boot_real_address + SPIN_TABLE_STACK_ADDRESS_OFFSET) as *const AtomicUsize)
    };

    loop {
        while spin_table_boot_stack_address.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
        if spin_table_boot_stack_address
            .compare_exchange(
                0,
                register_buffer_real_address,
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break;
        }
    }
    cpu::dsb();
    /* Flush Memory Cache for Application Processors */
    cpu::clean_data_cache_all();
    NUMBER_OF_RUNNING_AP.fetch_add(1, Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile(
            accessing_memory_address as *mut u64,
            spin_table_boot_real_address as u64,
        )
    };
    cpu::dsb();
    cpu::clean_and_invalidate_data_cache(accessing_memory_address);
    pr_debug!("The initialization completed.");
    StoreHookResult::Cancel
}

/* cpu_boot must use position-relative code */
#[naked]
extern "C" fn cpu_boot() {
    unsafe {
        core::arch::naked_asm!("
    ldp x1,   x2, [x0, 16 * 0]
    ldp x3,   x4, [x0, 16 * 1]
    ldp x5,   x6, [x0, 16 * 2]
    ldp x7,   x8, [x0, 16 * 3]
    ldp x9,  x10, [x0, 16 * 4]
    ldp x11, x12, [x0, 16 * 5]

    mov sp, x0
    add sp, sp, #(16 * 6)
    msr cnthctl_el2,     x1
    msr cntvoff_el2,    xzr
    msr cptr_el2,        x2
    msr ttbr0_el2,       x3
    msr mair_el2,        x4
    msr tcr_el2,         x5
    msr vbar_el2,        x6
    msr vttbr_el2,       x7
    msr vtcr_el2,        x8
    msr sctlr_el2,       x9
    msr hcr_el2,        x10

    mov x1, (1 << 7) |(1 << 6) | (1 << 2) | (1) // EL1h(EL1 + Use SP_EL1)
    msr spsr_el2,        x1
    msr elr_el2,        x11
    mov x0, x12
    isb
    eret",
    MAX_ZCR_EL2_LEN = const cpu::MAX_ZCR_EL2_LEN,
    A64FX = const cfg!(feature = "a64fx") as u64,
    SPSR_EL2 = const cpu::SPSR_EL2_DEFAULT)
    }
}

/// # ATTENTION
/// When modified the number of instructions,
///   adjust `SPIN_TABLE_STACK_ADDRESS_OFFSET` at spin_table_store_access_handler.
/// # TODO
/// Use atomic instructions(Currently "stlxr" fails to write zero).
#[naked]
extern "C" fn spin_table_boot() {
    unsafe {
        core::arch::naked_asm!("
.align  3
    adr     x1, 3f
2:
    //ldaxr     x0, [x1]
    ldr     x0, [x1]
    cbz     x0, 2b
    //stlxr     w2, xzr, [x1]
    str     xzr, [x1]
    //cbnz      w2, 2b
    nop
    b       {CPU_BOOT}
3:
    .quad   0",
    CPU_BOOT = sym cpu_boot)
    }
}
