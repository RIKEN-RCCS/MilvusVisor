// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! MultiCore Handling Functions
//!

use crate::{allocate_memory, handler_panic, StoredRegisters};

use crate::psci::{call_psci_function, PsciFunctionId, PsciReturnCode};

use common::cpu::{convert_virtual_address_to_physical_address_el2_read, MAX_ZCR_EL2_LEN};
use common::STACK_PAGES;

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(16))]
#[derive(Debug)]
struct HypervisorRegisters {
    stack_address: u64,
    cnthctl_el2: u64,
    cptr_el2: u64,
    hcr_el2: u64,
    vttbr_el2: u64,
    ttbr0_el2: u64,
    mair_el2: u64,
    tcr_el2: u64,
    vtcr_el2: u64,
    sctlr_el2: u64,
    vbar_el2: u64,
    el1_entry_point: u64,
    el1_context_id: u64,
    complete_flag: AtomicU64,
}

static mut REGISTER_BUFFER: HypervisorRegisters = HypervisorRegisters {
    stack_address: 0,
    cnthctl_el2: 0,
    cptr_el2: 0,
    hcr_el2: 0,
    vttbr_el2: 0,
    ttbr0_el2: 0,
    mair_el2: 0,
    tcr_el2: 0,
    vtcr_el2: 0,
    sctlr_el2: 0,
    vbar_el2: 0,
    el1_entry_point: 0,
    el1_context_id: 0,
    complete_flag: AtomicU64::new(1),
};

pub fn setup_new_cpu(regs: &mut StoredRegisters) {
    let stack_address: u64 =
        allocate_memory(STACK_PAGES).expect("Failed to alloc stack for new CPU.") as u64;
    let cnthctl_el2: u64;
    let cptr_el2: u64;
    let hcr_el2: u64;
    let vttbr_el2: u64;
    let ttbr0_el2: u64;
    let mair_el2: u64;
    let tcr_el2: u64;
    let vtcr_el2: u64;
    let sctlr_el2: u64;
    let vbar_el2: u64;
    unsafe {
        asm!("mrs {:x}, cnthctl_el2", out(reg) cnthctl_el2);
        asm!("mrs {:x}, cptr_el2", out(reg) cptr_el2);
        asm!("mrs {:x}, hcr_el2", out(reg) hcr_el2);
        asm!("mrs {:x}, ttbr0_el2", out(reg) ttbr0_el2);
        asm!("mrs {:x}, vttbr_el2", out(reg) vttbr_el2);
        asm!("mrs {:x}, mair_el2", out(reg)mair_el2);
        asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2);
        asm!("mrs {:x}, vtcr_el2", out(reg) vtcr_el2);
        asm!("mrs {:x}, sctlr_el2", out(reg) sctlr_el2);
        asm!("mrs {:x}, vbar_el2", out(reg) vbar_el2);
    }

    /* Aquire REGISTER_BUFFER's lock */
    loop {
        let mut current;
        loop {
            current = unsafe { REGISTER_BUFFER.complete_flag.load(Ordering::Relaxed) };
            if current != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        if unsafe {
            REGISTER_BUFFER
                .complete_flag
                .compare_exchange_weak(current, 0, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        } {
            break;
        }
    }
    unsafe {
        REGISTER_BUFFER.stack_address = stack_address;
        REGISTER_BUFFER.cnthctl_el2 = cnthctl_el2;
        REGISTER_BUFFER.cptr_el2 = cptr_el2;
        REGISTER_BUFFER.hcr_el2 = hcr_el2;
        REGISTER_BUFFER.vttbr_el2 = vttbr_el2;
        REGISTER_BUFFER.ttbr0_el2 = ttbr0_el2;
        REGISTER_BUFFER.mair_el2 = mair_el2;
        REGISTER_BUFFER.tcr_el2 = tcr_el2;
        REGISTER_BUFFER.vtcr_el2 = vtcr_el2;
        REGISTER_BUFFER.sctlr_el2 = sctlr_el2;
        REGISTER_BUFFER.vbar_el2 = vbar_el2;
        REGISTER_BUFFER.el1_entry_point = regs.x2;
        REGISTER_BUFFER.el1_context_id = regs.x3;
    }

    let hypervisor_registers_real_address = convert_virtual_address_to_physical_address_el2_read(
        unsafe { &REGISTER_BUFFER } as *const _ as usize,
    )
    .expect("Failed to convert virtual address to real address");
    let cpu_boot_address_real_address =
        convert_virtual_address_to_physical_address_el2_read(cpu_boot as *const fn() as usize)
            .expect("Failed to convert virtual address to real address");

    pr_debug!("{:#X?}", hypervisor_registers);

    regs.x0 = call_psci_function(
        PsciFunctionId::CpuOn,
        regs.x1,
        cpu_boot_address_real_address as u64,
        hypervisor_registers_real_address as u64,
    );
    if regs.x0 as i32 != PsciReturnCode::Success as i32 {
        handler_panic!(
            regs,
            "Failed to on the cpu (MPIDR: {:#X}): {:?}",
            regs.x1,
            PsciReturnCode::try_from(regs.x0 as i32)
        );
    }
    pr_debug!("The initialization completed.");
}

/* cpu_boot must use position-relative code */
#[naked]
extern "C" fn cpu_boot() {
    unsafe {
        asm!(
            "       // MIDR_EL1 & MPIDR_EL1
                    mrs x15, midr_el1
                    msr vpidr_el2, x15
                    mrs x16, mpidr_el1
                    msr vmpidr_el2, x16

                    // SVE
	                mrs	x17, id_aa64pfr0_el1
                    ubfx x18, x17, 32, 4
                    cbz x18, 1f
                    mov x15, {MAX_ZCR_EL2_LEN}
                    msr S3_4_C1_C2_0, x15 // ZCR_EL2

1:
                    // GICv3~
                    /*ubfx x18, x17, 24, 4
                    cbz  x18, 2f
                    mrs  x15, icc_sre_el2
                    orr  x15, x15, 1 << 0
                    orr  x15, x15, 1 << 3
                    msr  icc_sre_el2, x15
                    isb
                    mrs  x15, icc_sre_el2
                    tbz  x15, 0, 2f
                    msr  ich_hcr_el2, xzr*/

2:
                    // A64FX
                    mov x15, {A64FX}
                    cbz x15, 3f
                    msr S3_4_C11_C2_0, xzr // IMP_FJ_TAG_ADDRESS_CTRL_EL2
3:

                    ldp x1,   x2, [x0, 16 * 0]
                    ldp x3,   x4, [x0, 16 * 1]
                    ldp x5,   x6, [x0, 16 * 2]
                    ldp x7,   x8, [x0, 16 * 3]
                    ldp x9,  x10, [x0, 16 * 4]
                    ldp x11, x12, [x0, 16 * 5]
                    ldp x13, x14, [x0, 16 * 6]
                    mov x14, x0
                    add x14, x14, 8 * 13

                    mov sp, x1         
                    msr cnthctl_el2, x2
                    msr cntvoff_el2, xzr
                    msr cptr_el2, x3
                    msr mair_el2, x7
                    msr tcr_el2, x8
                    msr vtcr_el2, x9
                    msr ttbr0_el2, x6
                    msr hcr_el2, x4
                    msr sctlr_el2, x10
                    msr vbar_el2, x11
                    msr vttbr_el2, x5
                    mov x1, (1 << 7) |(1 << 6) | (1 << 2) | (1) // EL1h(EL1 + Use SP_EL1)
                    msr spsr_el2, x1
                    msr elr_el2, x12
                    mov x0, x13
                    str x14, [x14]
                    isb
                    eret
                    ",  MAX_ZCR_EL2_LEN = const MAX_ZCR_EL2_LEN, A64FX = const cfg!(feature = "a64fx") as u64,
                        options(noreturn))
    }
}
