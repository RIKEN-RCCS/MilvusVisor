//!
//! MultiCore Handling Functions
//!

use crate::{allocate_memory, StoredRegisters};

use crate::psci::{call_psci_function, PsciFunctionId, PsciReturnCode};

use common::cpu::convert_virtual_address_to_physical_address_el2_read;
use common::STACK_PAGES;

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

    let hypervisor_registers = HypervisorRegisters {
        stack_address,
        cnthctl_el2,
        cptr_el2,
        hcr_el2,
        vttbr_el2,
        ttbr0_el2,
        mair_el2,
        tcr_el2,
        vtcr_el2,
        sctlr_el2,
        vbar_el2,
        el1_entry_point: regs.x2,
        el1_context_id: regs.x3,
        complete_flag: AtomicU64::new(0),
    };

    let hypervisor_registers_real_address = convert_virtual_address_to_physical_address_el2_read(
        &hypervisor_registers as *const _ as usize,
    )
    .expect("Failed to convert virtual address to real address");
    let cpu_boot_address_real_address =
        convert_virtual_address_to_physical_address_el2_read(cpu_boot as *const fn() as usize)
            .expect("Failed to convert virtual address to real address");

    println!("{:#X?}", hypervisor_registers);

    regs.x0 = call_psci_function(
        PsciFunctionId::CpuOn,
        regs.x1,
        cpu_boot_address_real_address as u64,
        hypervisor_registers_real_address as u64,
    );
    if regs.x0 as i32 != PsciReturnCode::Success as i32 {
        panic!(
            "Failed to on the cpu (MPIDR: {:#X}): {:?}",
            regs.x1,
            PsciReturnCode::try_from(regs.x0 as i32)
        );
    }
    println!("Wait for completing the initialization.");
    while hypervisor_registers.complete_flag.load(Ordering::Relaxed) == 0 {
        core::hint::spin_loop()
    }
    println!("The initialization completed.");
}

/* cpu_boot must use position-relative code */
#[naked]
extern "C" fn cpu_boot() {
    unsafe {
        asm!(
            "
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
                    ",
            options(noreturn)
        )
    }
}
