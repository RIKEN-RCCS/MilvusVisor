use core::ptr::{read_volatile, write_volatile};

use crate::cpu::{dsb, isb};

/// Offset of the Hypervisor Control Register within the GICH window.
pub const GICH_HCR: usize = 0x0000;
/// Offset of the VGIC Type Register.
pub const GICH_VTR: usize = 0x0004;
/// Offset of the Virtual Machine Control Register.
pub const GICH_VMCR: usize = 0x0008;
/// Offset of the Maintenance Interrupt Status Register.
pub const GICH_MISR: usize = 0x0010;
/// Offset of the End of Interrupt Status Registers.
pub const GICH_EISR0: usize = 0x0020;
pub const GICH_EISR1: usize = 0x0024;
/// Offset of the Empty List Register Status Registers.
pub const GICH_ELRSR0: usize = 0x0030;
pub const GICH_ELRSR1: usize = 0x0034;
/// Base offset of the Active Priority Registers.
pub const GICH_APR0: usize = 0x0040;
/// Size in bytes between consecutive APR registers.
pub const GICH_APR_STRIDE: usize = 0x4;
/// Base offset of the List Registers array.
pub const GICH_LR0: usize = 0x0100;
/// Size in bytes between consecutive List Registers (64-bit each).
pub const GICH_LR_STRIDE: usize = 0x10;

/// `GICH_HCR` enable bit.
pub const GICH_HCR_EN: u32 = 1 << 0;

/// Architectural maximum number of virtualization List Registers.
pub const MAX_LIST_REGISTERS: usize = 16;
/// Architectural maximum number of Active Priority registers per group.
pub const MAX_AP_REGISTERS: usize = 4;

#[inline(always)]
pub fn read_hcr(base: usize) -> u32 {
    unsafe { read_volatile((base + GICH_HCR) as *const u32) }
}

#[inline(always)]
pub fn write_hcr(base: usize, value: u32) {
    unsafe { write_volatile((base + GICH_HCR) as *mut u32, value) }
}

#[inline(always)]
pub fn disable_delivery(base: usize) -> u32 {
    let hcr = read_hcr(base);
    if hcr & GICH_HCR_EN != 0 {
        dsb();
        write_hcr(base, hcr & !GICH_HCR_EN);
        isb();
    }
    hcr
}

#[inline(always)]
pub fn restore_delivery(base: usize, hcr: u32) {
    dsb();
    write_hcr(base, hcr);
    isb();
}

#[inline(always)]
pub fn read_vtr(base: usize) -> u32 {
    unsafe { read_volatile((base + GICH_VTR) as *const u32) }
}

#[inline(always)]
pub fn read_vmcr(base: usize) -> u32 {
    unsafe { read_volatile((base + GICH_VMCR) as *const u32) }
}

#[inline(always)]
pub fn write_vmcr(base: usize, value: u32) {
    unsafe { write_volatile((base + GICH_VMCR) as *mut u32, value) }
}

#[inline(always)]
pub fn read_misr(base: usize) -> u32 {
    unsafe { read_volatile((base + GICH_MISR) as *const u32) }
}

#[inline(always)]
pub fn read_eisr(base: usize, index: usize) -> u32 {
    debug_assert!(index < 2);
    let offset = match index {
        0 => GICH_EISR0,
        _ => GICH_EISR1,
    };
    unsafe { read_volatile((base + offset) as *const u32) }
}

#[inline(always)]
pub fn read_elrsr(base: usize, index: usize) -> u32 {
    debug_assert!(index < 2);
    let offset = match index {
        0 => GICH_ELRSR0,
        _ => GICH_ELRSR1,
    };
    unsafe { read_volatile((base + offset) as *const u32) }
}

#[inline(always)]
pub fn read_apr(base: usize, index: usize) -> u32 {
    debug_assert!(index < MAX_AP_REGISTERS);
    unsafe { read_volatile((base + GICH_APR0 + index * GICH_APR_STRIDE) as *const u32) }
}

#[inline(always)]
pub fn write_apr(base: usize, index: usize, value: u32) {
    debug_assert!(index < MAX_AP_REGISTERS);
    unsafe {
        write_volatile(
            (base + GICH_APR0 + index * GICH_APR_STRIDE) as *mut u32,
            value,
        )
    }
}

#[inline(always)]
pub fn read_lr(base: usize, index: usize) -> u64 {
    debug_assert!(index < MAX_LIST_REGISTERS);
    unsafe { read_volatile((base + GICH_LR0 + index * GICH_LR_STRIDE) as *const u64) }
}

#[inline(always)]
pub fn write_lr(base: usize, index: usize, value: u64) {
    debug_assert!(index < MAX_LIST_REGISTERS);
    unsafe {
        write_volatile(
            (base + GICH_LR0 + index * GICH_LR_STRIDE) as *mut u64,
            value,
        )
    }
}

#[inline(always)]
pub fn lr_count_from_vtr(vtr: u32) -> usize {
    let count = ((vtr & 0x3f) + 1) as usize;
    count.min(MAX_LIST_REGISTERS)
}

#[inline(always)]
pub fn apr_count_from_vtr(vtr: u32) -> usize {
    let raw = ((vtr >> 8) & 0x7) + 1;
    (raw as usize).min(MAX_AP_REGISTERS)
}
