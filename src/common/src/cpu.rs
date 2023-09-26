// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! CPU Specified Assembly functions
//!

use crate::{bitmask, PAGE_MASK, PAGE_SHIFT};

use core::arch::asm;

#[derive(Clone)]
pub struct InterruptFlag(u64);

pub const AA64_INSTRUCTION_SIZE: usize = 4;

/* DAIF */
pub const DAIF_IRQ_BIT: u64 = 7;
pub const DAIF_FIQ_BIT: u64 = 6;

/* CNTHCTL_EL2 */
pub const CNTHCTL_EL2_EL1PCEN: u64 = 1 << 1;
pub const CNTHCTL_EL2_EL1PCTEN: u64 = 1 << 0;

/* CPACR_EL1 */
pub const CPACR_EL1_TTA_BIT_OFFSET: u64 = 28;
//pub const CPACR_EL1_TTA: u64 = 1 << CPACR_EL1_TTA_BIT_OFFSET;
pub const CPACR_EL1_FPEN_BITS_OFFSET: u64 = 20;
//pub const CPACR_EL1_FPEN: u64 = 0b11 << CPACR_EL1_FPEN_BITS_OFFSET;
pub const CPACR_EL1_ZEN_BITS_OFFSET: u64 = 16;
//pub const CPACR_EL1_ZEN: u64 = 0b11 << CPACR_EL1_ZEN_BITS_OFFSET;

/* CPTR_EL2 */
pub const CPTR_EL2_TTA_BIT_OFFSET_WITH_E2H: u64 = 28;
pub const CPTR_EL2_TTA_WITH_E2H: u64 = 1 << CPTR_EL2_TTA_BIT_OFFSET_WITH_E2H;
pub const CPTR_EL2_TTA_BIT_OFFSET_WITHOUT_E2H: u64 = 20;
pub const CPTR_EL2_TTA_WITHOUT_E2H: u64 = 1 << CPTR_EL2_TTA_BIT_OFFSET_WITHOUT_E2H;
pub const CPTR_EL2_FPEN_BITS_OFFSET: u64 = 20;
pub const CPTR_EL2_FPEN: u64 = 0b11 << CPTR_EL2_FPEN_BITS_OFFSET;
pub const CPTR_EL2_FPEN_NO_TRAP: u64 = 0b11 << CPTR_EL2_FPEN_BITS_OFFSET;
pub const CPTR_EL2_ZEN_BITS_OFFSET: u64 = 16;
pub const CPTR_EL2_ZEN: u64 = 0b11 << CPTR_EL2_ZEN_BITS_OFFSET;
pub const CPTR_EL2_ZEN_NO_TRAP: u64 = 0b11 << CPTR_EL2_ZEN_BITS_OFFSET;
//pub const CPTR_EL2_RES1: u64 = 0b11111111 | (1 << 9) | (0b11 << 12);

/* TCR_EL2 */
pub const TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H: u64 = 32;
pub const TCR_EL2_DS_WITHOUT_E2H: u64 = 1 << TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_TCMA_BIT_OFFSET_WITHOUT_E2H: u64 = 30;
pub const TCR_EL2_TCMA_WITHOUT_E2H: u64 = 1 << TCR_EL2_TCMA_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_TBID_BIT_OFFSET_WITHOUT_E2H: u64 = 29;
pub const TCR_EL2_TBID_WITHOUT_E2H: u64 = 1 << TCR_EL2_TBID_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_HWU_BITS_OFFSET_WITHOUT_E2H: u64 = 25;
pub const TCR_EL2_HWU_WITHOUT_E2H: u64 = 0b1111 << TCR_EL2_HWU_BITS_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_HPD_BIT_OFFSET_WITHOUT_E2H: u64 = 24;
pub const TCR_EL2_HPD_WITHOUT_E2H: u64 = 1 << TCR_EL2_HPD_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_HD_BIT_OFFSET_WITHOUT_E2H: u64 = 22;
pub const TCR_EL2_HD_WITHOUT_E2H: u64 = 1 << TCR_EL2_HD_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_HA_BIT_OFFSET_WITHOUT_E2H: u64 = 21;
pub const TCR_EL2_HA_WITHOUT_E2H: u64 = 1 << TCR_EL2_HA_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_TBI_BIT_OFFSET_WITHOUT_E2H: u64 = 20;
pub const TCR_EL2_TBI_WITHOUT_E2H: u64 = 1 << TCR_EL2_TBI_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H: u64 = 16;
pub const TCR_EL2_PS_WITHOUT_E2H: u64 = 0b111 << TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H: u64 = 14;
pub const TCR_EL2_TG0_WITHOUT_E2H: u64 = 0b11 << TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H: u64 = 0;
pub const TCR_EL2_T0SZ_WITHOUT_E2H: u64 = 0b111111 << TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H;

/* TCR_EL1 */
pub const TCR_EL1_DS_BIT_OFFSET: u64 = 59;
//pub const TCR_EL1_DS: u64 = 1 << TCR_EL1_DS_BIT_OFFSET;
pub const TCR_EL1_TCMA0_BIT_OFFSET: u64 = 57;
//pub const TCR_EL1_TCMA0: u64 = 1 << TCR_EL1_TCMA0_BIT_OFFSET;
pub const TCR_EL1_TBID0_BIT_OFFSET: u64 = 51;
//pub const TCR_EL1_TBID0: u64 = 1 << TCR_EL1_TBID0_BIT_OFFSET;
pub const TCR_EL1_HWU_BITS_OFFSET: u64 = 43;
//pub const TCR_EL1_HWU: u64 = 0b11111111 << TCR_EL1_HWU_BITS_OFFSET;
pub const TCR_EL1_HPD0_BIT_OFFSET: u64 = 41;
//pub const TCR_EL1_HPD0: u64 = 1 << TCR_EL1_HPD0_BIT_OFFSET;
pub const TCR_EL1_HD_BIT_OFFSET: u64 = 40;
//pub const TCR_EL1_HD: u64 = 1 << TCR_EL1_HD_BIT_OFFSET;
pub const TCR_EL1_HA_BIT_OFFSET: u64 = 39;
//pub const TCR_EL1_HA: u64 = 1 << TCR_EL1_HA_BIT_OFFSET;
pub const TCR_EL1_TBI0_BIT_OFFSET: u64 = 37;
//pub const TCR_EL1_TBI0: u64 = 1 << TCR_EL1_TBI0_BIT_OFFSET;
pub const TCR_EL1_IPS_BITS_OFFSET: u64 = 32;
//pub const TCR_EL1_IPS: u64 = 0b111 << TCR_EL1_IPS_BITS_OFFSET;
pub const TCR_EL1_EPD1: u64 = 1 << 23;

/* HCR_EL2 */
pub const HCR_EL2_FIEN: u64 = 1 << 47;
pub const HCR_EL2_API: u64 = 1 << 41;
pub const HCR_EL2_APK: u64 = 1 << 40;
//pub const HCR_EL2_TEA: u64 = 1 << 37;
pub const HCR_EL2_E2H: u64 = 1 << 34;
pub const HCR_EL2_RW: u64 = 1 << 31;
pub const HCR_EL2_TSC: u64 = 1 << 19;
pub const HCR_EL2_VM: u64 = 1 << 0;

/* VTCR_EL2 */
pub const VTCR_EL2_SL2_BIT_OFFSET: u64 = 33;
pub const VTCR_EL2_SL2: u64 = 1 << VTCR_EL2_SL2_BIT_OFFSET;
pub const VTCR_EL2_RES1: u64 = 1 << 31;
pub const VTCR_EL2_HWU_BITS_OFFSET: u64 = 25;
pub const VTCR_EL2_PS_BITS_OFFSET: u64 = 16;
pub const VTCR_EL2_PS: u64 = 0b111 << VTCR_EL2_PS_BITS_OFFSET;
pub const VTCR_EL2_TG0_BITS_OFFSET: u64 = 14;
pub const VTCR_EL2_TG0: u64 = 0b11 << VTCR_EL2_TG0_BITS_OFFSET;
pub const VTCR_EL2_SH0_BITS_OFFSET: u64 = 12;
pub const VTCR_EL2_ORG0_BITS_OFFSET: u64 = 10;
pub const VTCR_EL2_IRG0_BITS_OFFSET: u64 = 8;
pub const VTCR_EL2_SL0_BITS_OFFSET: u64 = 6;
pub const VTCR_EL2_SL0: u64 = 0b11 << VTCR_EL2_SL0_BITS_OFFSET;
pub const VTCR_EL2_T0SZ_BITS_OFFSET: u64 = 0;
pub const VTCR_EL2_T0SZ: u64 = 0b111111 << VTCR_EL2_T0SZ_BITS_OFFSET;

/* SPSR_EL2 */
pub const SPSR_EL2_M: u64 = 0b1111;
pub const SPSR_EL2_M_EL0T: u64 = 0b0000;

/* ID_AA64PFR0_EL1 */
pub const ID_AA64PFR0_EL1_SVE: u64 = 0b1111 << 32;
pub const ID_AA64PFR0_EL1_GIC: u64 = 0b1111 << 24;

/* ID_AA64MMFR0_EL1 */
pub const ID_AA64MMFR0_EL1_PARANGE: u64 = 0b1111;

/* CLIDR_EL1 */
pub const CLIDR_EL1_LOC_BITS_OFFSET: u64 = 24;
pub const CLIDR_EL1_LOC: u64 = 0b111 << CLIDR_EL1_LOC_BITS_OFFSET;

/* CCSIDR_EL1 */
pub const CCSIDR_EL1_NUM_SETS_BITS_OFFSET: u64 = 13;
pub const CCSIDR_EL1_NUM_SETS: u64 = 0x7FFF << CCSIDR_EL1_NUM_SETS_BITS_OFFSET;
pub const CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET: u64 = 3;
pub const CCSIDR_EL1_ASSOCIATIVITY: u64 = 0x3FF << CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET;
pub const CCSIDR_EL1_LINE_SIZE_BITS_OFFSET: u64 = 0;
pub const CCSIDR_EL1_LINE_SIZE: u64 = 0b111 << CCSIDR_EL1_LINE_SIZE_BITS_OFFSET;

/* ZCR_EL2 */
pub const MAX_ZCR_EL2_LEN: u64 = 0x1ff;

/// Execute SMC #0 with SMC Calling Convention 1.2
pub fn secure_monitor_call(
    x0: &mut u64,
    x1: &mut u64,
    x2: &mut u64,
    x3: &mut u64,
    x4: &mut u64,
    x5: &mut u64,
    x6: &mut u64,
    x7: &mut u64,
    x8: &mut u64,
    x9: &mut u64,
    x10: &mut u64,
    x11: &mut u64,
    x12: &mut u64,
    x13: &mut u64,
    x14: &mut u64,
    x15: &mut u64,
    x16: &mut u64,
    x17: &mut u64,
) {
    unsafe {
        asm!(
            "smc 0",
            inout("x0") * x0,
            inout("x1") * x1,
            inout("x2") * x2,
            inout("x3") * x3,
            inout("x4") * x4,
            inout("x5") * x5,
            inout("x6") * x6,
            inout("x7") * x7,
            inout("x8") * x8,
            inout("x9") * x9,
            inout("x10") * x10,
            inout("x11") * x11,
            inout("x12") * x12,
            inout("x13") * x13,
            inout("x14") * x14,
            inout("x15") * x15,
            inout("x16") * x16,
            inout("x17") * x17,
            clobber_abi("C")
        )
    };
}

#[inline(always)]
pub fn get_ttbr0_el2() -> u64 {
    let ttbr0_el2: u64;
    unsafe { asm!("mrs {:x}, ttbr0_el2", out(reg) ttbr0_el2) };
    ttbr0_el2
}

#[inline(always)]
pub fn set_ttbr0_el2(ttbr0_el2: u64) {
    unsafe { asm!("msr ttbr0_el2, {:x}", in(reg) ttbr0_el2) };
}

#[inline(always)]
pub fn get_ttbr0_el1() -> u64 {
    let ttbr0_el1: u64;
    unsafe { asm!("mrs {:x}, ttbr0_el1", out(reg) ttbr0_el1) };
    ttbr0_el1
}

#[inline(always)]
pub fn set_ttbr0_el1(ttbr0_el1: u64) {
    unsafe { asm!("msr ttbr0_el1, {:x}", in(reg) ttbr0_el1) };
}

#[inline(always)]
pub fn get_tcr_el2() -> u64 {
    let tcr_el2: u64;
    unsafe { asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2) };
    tcr_el2
}

#[inline(always)]
pub fn set_tcr_el2(tcr_el2: u64) {
    unsafe { asm!("msr tcr_el2, {:x}", in(reg) tcr_el2) };
}

#[inline(always)]
pub fn get_tcr_el1() -> u64 {
    let tcr_el1: u64;
    unsafe { asm!("mrs {:x}, tcr_el1", out(reg) tcr_el1) };
    tcr_el1
}

#[inline(always)]
pub fn set_tcr_el1(tcr_el1: u64) {
    unsafe { asm!("msr tcr_el1, {:x}", in(reg) tcr_el1) };
}

#[inline(always)]
pub fn get_vttbr_el2() -> u64 {
    let vttbr_el2: u64;
    unsafe { asm!("mrs {:x}, vttbr_el2", out(reg) vttbr_el2) };
    vttbr_el2
}

#[inline(always)]
pub fn set_vttbr_el2(vttbr_el2: u64) {
    unsafe { asm!("msr vttbr_el2, {:x}", in(reg) vttbr_el2) };
    flush_tlb_el1(); /* May be needless */
}

#[inline(always)]
pub fn get_vtcr_el2() -> u64 {
    let vtcr_el2: u64;
    unsafe { asm!("mrs {:x}, vtcr_el2", out(reg) vtcr_el2) };
    vtcr_el2
}

#[inline(always)]
pub fn set_vtcr_el2(vtcr_el2: u64) {
    unsafe { asm!("msr vtcr_el2, {:x}", in(reg) vtcr_el2) };
}

#[inline(always)]
pub fn get_hcr_el2() -> u64 {
    let hcr_el2: u64;
    unsafe { asm!("mrs {:x}, hcr_el2", out(reg) hcr_el2) };
    hcr_el2
}

#[inline(always)]
pub fn set_hcr_el2(hcr_el2: u64) {
    unsafe { asm!("msr hcr_el2, {:x}", in(reg) hcr_el2) };
}

#[inline(always)]
pub fn get_current_el() -> u64 {
    let current_el: u64;
    unsafe { asm!("mrs {:x}, currentel", out(reg) current_el) };
    current_el
}

#[inline(always)]
pub fn set_icc_sgi1r_el1(icc_sgi1r_el1: u64) {
    unsafe { asm!("msr icc_sgi1r_el1, {:x}", in(reg) icc_sgi1r_el1) };
}

#[inline(always)]
pub fn set_icc_sgi0r_el1(icc_sgi0r_el1: u64) {
    unsafe { asm!("msr icc_sgi0r_el1, {:x}", in(reg) icc_sgi0r_el1) };
}

#[inline(always)]
pub fn set_cntp_ctl_el0(cntp_ctl_el0: u64) {
    unsafe { asm!("msr cntp_ctl_el0, {:x}", in(reg) cntp_ctl_el0) };
}

#[inline(always)]
pub fn get_icc_pmr_el1() -> u64 {
    let icc_pmr_el1: u64;
    unsafe { asm!("mrs {:x}, icc_pmr_el1", out(reg) icc_pmr_el1) };
    icc_pmr_el1
}

#[inline(always)]
pub fn set_icc_pmr_el1(icc_pmr_el1: u64) {
    unsafe { asm!("msr icc_pmr_el1, {:x}", in(reg) icc_pmr_el1) };
}

#[inline(always)]
pub fn get_icc_bpr0_el1() -> u64 {
    let icc_bpr0_el1: u64;
    unsafe { asm!("mrs {:x}, icc_bpr0_el1", out(reg) icc_bpr0_el1) };
    icc_bpr0_el1
}

#[inline(always)]
pub fn set_icc_bpr0_el1(icc_bpr0_el1: u64) {
    unsafe { asm!("msr icc_bpr0_el1, {:x}", in(reg) icc_bpr0_el1) };
}

#[inline(always)]
pub fn get_icc_bpr1_el1() -> u64 {
    let icc_bpr1_el1: u64;
    unsafe { asm!("mrs {:x}, icc_bpr1_el1", out(reg) icc_bpr1_el1) };
    icc_bpr1_el1
}

#[inline(always)]
pub fn set_icc_bpr1_el1(icc_bpr1_el1: u64) {
    unsafe { asm!("msr icc_bpr1_el1, {:x}", in(reg) icc_bpr1_el1) };
}

#[inline(always)]
pub fn get_icc_igrpen0_el1() -> u64 {
    let icc_igrpen0_el1: u64;
    unsafe { asm!("mrs {:x}, icc_igrpen0_el1", out(reg) icc_igrpen0_el1) };
    icc_igrpen0_el1
}

#[inline(always)]
pub fn set_icc_igrpen0_el1(icc_igrpen0_el1: u64) {
    unsafe { asm!("msr icc_igrpen0_el1, {:x}", in(reg) icc_igrpen0_el1) };
}

#[inline(always)]
pub fn get_icc_igrpen1_el1() -> u64 {
    let icc_igrpen1_el1: u64;
    unsafe { asm!("mrs {:x}, icc_igrpen1_el1", out(reg) icc_igrpen1_el1) };
    icc_igrpen1_el1
}

#[inline(always)]
pub fn set_icc_igrpen1_el1(icc_igrpen1_el1: u64) {
    unsafe { asm!("msr icc_igrpen1_el1, {:x}", in(reg) icc_igrpen1_el1) };
}

#[inline(always)]
pub fn get_mair_el2() -> u64 {
    let mair_el2: u64;
    unsafe { asm!("mrs {:x}, mair_el2", out(reg) mair_el2) };
    mair_el2
}

#[inline(always)]
pub fn get_mair_el1() -> u64 {
    let mair_el1: u64;
    unsafe { asm!("mrs {:x}, mair_el1", out(reg) mair_el1) };
    mair_el1
}

#[inline(always)]
pub fn set_mair_el1(mair_el1: u64) {
    unsafe { asm!("msr mair_el1, {:x}", in(reg) mair_el1) };
}

#[inline(always)]
pub fn get_cnthctl_el2() -> u64 {
    let cnthctl_el2: u64;
    unsafe { asm!("mrs {:x}, cnthctl_el2", out(reg) cnthctl_el2) };
    cnthctl_el2
}

#[inline(always)]
pub fn set_cnthctl_el2(cnthctl_el2: u64) {
    unsafe { asm!("msr cnthctl_el2, {:x}", in(reg) cnthctl_el2) };
}

#[inline(always)]
pub fn set_cntvoff_el2(cntvoff_el2: u64) {
    unsafe { asm!("msr cntvoff_el2, {:x}", in(reg) cntvoff_el2) };
}

#[inline(always)]
pub fn get_cptr_el2() -> u64 {
    let cptr_el2: u64;
    unsafe { asm!("mrs {:x}, cptr_el2", out(reg) cptr_el2) };
    cptr_el2
}

#[inline(always)]
pub fn set_cptr_el2(cptr_el2: u64) {
    unsafe { asm!("msr cptr_el2, {:x}", in(reg) cptr_el2) };
}

#[inline(always)]
pub fn get_cpacr_el1() -> u64 {
    let cpacr_el1: u64;
    unsafe { asm!("mrs {:x}, cpacr_el1", out(reg) cpacr_el1) };
    cpacr_el1
}

#[inline(always)]
pub fn set_cpacr_el1(cpacr_el1: u64) {
    unsafe { asm!("msr cpacr_el1, {:x}", in(reg) cpacr_el1) };
}

#[inline(always)]
pub fn get_sctlr_el2() -> u64 {
    let sctlr_el2: u64;
    unsafe { asm!("mrs {:x}, sctlr_el2", out(reg) sctlr_el2) };
    sctlr_el2
}

#[inline(always)]
pub fn set_sctlr_el2(sctlr_el2: u64) {
    unsafe { asm!("msr sctlr_el2, {:x}", in(reg) sctlr_el2) };
}

#[inline(always)]
pub fn get_sctlr_el1() -> u64 {
    let sctlr_el1: u64;
    unsafe { asm!("mrs {:x}, sctlr_el1", out(reg) sctlr_el1) };
    sctlr_el1
}

#[inline(always)]
pub fn set_sctlr_el1(sctlr_el1: u64) {
    unsafe { asm!("msr sctlr_el1, {:x}", in(reg) sctlr_el1) };
}

#[inline(always)]
pub fn get_vbar_el2() -> u64 {
    let vbar_el2: u64;
    unsafe { asm!("mrs {:x}, vbar_el2", out(reg) vbar_el2) };
    vbar_el2
}

#[inline(always)]
pub fn set_vbar_el2(vbar_el2: u64) {
    unsafe { asm!("msr vbar_el2, {:x}", in(reg) vbar_el2) };
}

#[inline(always)]
pub fn get_vbar_el1() -> u64 {
    let vbar_el1: u64;
    unsafe { asm!("mrs {:x}, vbar_el1", out(reg) vbar_el1) };
    vbar_el1
}

#[inline(always)]
pub fn set_vbar_el1(vbar_el1: u64) {
    unsafe { asm!("msr vbar_el1, {:x}", in(reg) vbar_el1) };
}

#[inline(always)]
pub fn get_esr_el2() -> u64 {
    let esr_el2: u64;
    unsafe { asm!("mrs {:x}, esr_el2", out(reg) esr_el2) };
    esr_el2
}

#[inline(always)]
pub fn get_far_el2() -> u64 {
    let far_el2: u64;
    unsafe { asm!("mrs {:x}, far_el2", out(reg) far_el2) };
    far_el2
}

#[inline(always)]
pub fn get_hpfar_el2() -> u64 {
    let hpfar_el2: u64;
    unsafe { asm!("mrs {:x}, hpfar_el2", out(reg) hpfar_el2) };
    hpfar_el2
}

#[inline(always)]
pub fn get_spsr_el2() -> u64 {
    let spsr_el2: u64;
    unsafe { asm!("mrs {:x}, spsr_el2", out(reg) spsr_el2) };
    spsr_el2
}

#[inline(always)]
pub fn set_spsr_el2(spsr_el2: u64) {
    unsafe { asm!("msr spsr_el2, {:x}", in(reg) spsr_el2) };
}

#[inline(always)]
pub fn get_elr_el2() -> u64 {
    let elr_el2: u64;
    unsafe { asm!("mrs {:x}, elr_el2", out(reg) elr_el2) };
    elr_el2
}

#[inline(always)]
pub fn set_elr_el2(elr_el2: u64) {
    unsafe { asm!("msr elr_el2, {:x}", in(reg) elr_el2) };
}

#[inline(always)]
pub fn get_sp() -> u64 {
    let sp: u64;
    unsafe { asm!("mov {:x}, sp", out(reg) sp) };
    sp
}

#[inline(always)]
pub fn get_sp_el1() -> u64 {
    let sp_el1: u64;
    unsafe { asm!("mrs {:x}, sp_el1", out(reg) sp_el1) };
    sp_el1
}

#[inline(always)]
pub fn set_sp_el1(sp_el1: u64) {
    unsafe { asm!("msr sp_el1, {:x}", in(reg) sp_el1) };
}

#[inline(always)]
pub fn get_id_aa64mmfr0_el1() -> u64 {
    let id_aa64mmfr0_el1: u64;
    unsafe { asm!("mrs {:x}, id_aa64mmfr0_el1", out(reg) id_aa64mmfr0_el1) };
    id_aa64mmfr0_el1
}

#[inline(always)]
pub fn get_id_aa64pfr0_el1() -> u64 {
    let id_aa64pfr0_el1: u64;
    unsafe { asm!("mrs {:x}, id_aa64pfr0_el1", out(reg) id_aa64pfr0_el1) };
    id_aa64pfr0_el1
}

#[inline(always)]
pub fn get_mpidr_el1() -> u64 {
    let mpidr_el1: u64;
    unsafe { asm!("mrs {:x}, mpidr_el1", out(reg) mpidr_el1) };
    mpidr_el1
}

#[inline(always)]
pub fn get_midr_el1() -> u64 {
    let midr_el1: u64;
    unsafe { asm!("mrs {:x}, midr_el1", out(reg) midr_el1) };
    midr_el1
}

#[inline(always)]
pub fn advance_elr_el2() {
    set_elr_el2(get_elr_el2() + AA64_INSTRUCTION_SIZE as u64);
}

#[inline(always)]
pub fn flush_tlb_el2() {
    unsafe {
        asm!(
            "
             dsb   ishst
             tlbi  alle2is
             dsb   sy
             isb"
        )
    };
}

#[inline(always)]
pub fn flush_tlb_el1() {
    unsafe {
        asm!(
            "
            dsb ishst
            tlbi alle1is
            dsb ish
            isb"
        )
    };
}

#[inline(always)]
pub fn dsb() {
    unsafe { asm!("dsb sy") }
}

#[inline(always)]
pub fn isb() {
    unsafe { asm!("isb") }
}

#[inline(always)]
pub fn flush_tlb_ipa_is(address: u64) {
    unsafe { asm!("TLBI IPAS2E1IS, {:x}", in(reg) address) };
}

#[inline(always)]
pub fn clear_instruction_cache_all() {
    unsafe { asm!("IC IALLUIS") };
}

#[inline(always)]
pub fn invalidate_data_cache(virtual_address: usize) {
    unsafe { asm!("DC IVAC, {:x}", in(reg) virtual_address) };
}

#[inline(always)]
pub fn clean_and_invalidate_data_cache(virtual_address: usize) {
    unsafe { asm!("DC CIVAC, {:x}", in(reg) virtual_address) };
}

pub fn clean_data_cache_all() {
    dsb();
    let clidr_el1: u64;
    unsafe { asm!("mrs {:x}, clidr_el1", out(reg) clidr_el1) };
    let loc = (clidr_el1 & CLIDR_EL1_LOC) >> CLIDR_EL1_LOC_BITS_OFFSET;
    for cache_level in 0..loc {
        let cache_type = (clidr_el1 >> (3 * cache_level)) & 0b111;
        let ccsidr_el1: u64;

        if cache_type <= 1 {
            /* Data Cache is not available */
            continue;
        }
        unsafe {
            asm!("
                    msr csselr_el1, {:x}
                    isb
                    mrs {:x}, ccsidr_el1
                ", in(reg) cache_level << 1, out(reg) ccsidr_el1)
        };

        let line_size =
            ((ccsidr_el1 & CCSIDR_EL1_LINE_SIZE) >> CCSIDR_EL1_LINE_SIZE_BITS_OFFSET) + 4;
        let associativity =
            ((ccsidr_el1 & CCSIDR_EL1_ASSOCIATIVITY) >> CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET) + 1;
        let num_sets = ((ccsidr_el1 & CCSIDR_EL1_NUM_SETS) >> CCSIDR_EL1_NUM_SETS_BITS_OFFSET) + 1;
        let set_way_a = (associativity as u32 - 1).leading_zeros();

        for set in 0..num_sets {
            for way in 0..associativity {
                /* C5.3.13 DC CISW, Data or unified Cache line Clean and Invalidate by Set/Way (ARM DDI 0487G.a ID011921)
                 *
                 * SetWay[31:4]
                 * * Way, bits[31:32-A], the number of the way to operate on.
                 * * Set, bits[B-1:L], the number of the set to operate on.
                 * Bits[L-1:4] are RES0.
                 * A = Log2(ASSOCIATIVITY), L = Log2(LINELEN), B = (L + S), S = Log2(NSETS).
                 *
                 * Level, bits [3:1]
                 */
                let set_way = (way << set_way_a) | (set << line_size) | (cache_level << 1);
                unsafe { asm!("DC CISW, {:x}", in(reg) set_way) };
            }
        }
    }
    dsb();
    isb();
    unsafe { asm!("msr csselr_el1, {:x}", in(reg) 0) }; /* Restore CSSELR_EL1 */
}

#[inline(always)]
pub fn send_event_all() {
    unsafe { asm!("SEV") };
}

/// Save current interrupt status and disable IRQ/FIQ
///
/// # Result
/// Saved interrupt status, should be used as the argument of [`local_irq_fiq_restore`]
pub fn local_irq_fiq_save() -> InterruptFlag {
    let mut daif: u64;
    unsafe { asm!("mrs {:x}, DAIF", out(reg) daif) };
    let flag = InterruptFlag(daif);
    daif |= (1 << DAIF_IRQ_BIT) | (1 << DAIF_FIQ_BIT);
    dsb();
    isb();
    unsafe { asm!("msr DAIF, {:x}", in(reg) daif) };
    flag
}

/// Restore interrupt
///
/// # Arguments
/// * f - InterruptFlag, the returned value of [`local_irq_fiq_restore`]
pub fn local_irq_fiq_restore(f: InterruptFlag) {
    dsb();
    isb();
    unsafe { asm!("msr DAIF, {:x}", in(reg) f.0) };
}

/// Convert virtual address of EL2 for read access to physical address
///
/// This function uses AT S1E2R instruction.
///
/// # Arguments
/// * virtual_address - the virtual address to convert
///
/// # Result
/// If succeeded, returns Ok(physical_address), otherwise(the address is not accessible) returns Err(())
pub fn convert_virtual_address_to_physical_address_el2_read(
    virtual_address: usize,
) -> Result<usize, ()> {
    let aligned_virtual_address = virtual_address & PAGE_MASK;
    let offset = virtual_address & !PAGE_MASK;
    let aligned_physical_address: usize;
    unsafe {
        asm!("  at S1E2R, {:x}
                mrs {:x}, par_el1",
        in(reg) (aligned_virtual_address),
        out(reg) aligned_physical_address)
    };

    if (aligned_physical_address & 1) == 0 {
        Ok((aligned_physical_address & bitmask!(51, PAGE_SHIFT)) + offset)
    } else {
        Err(())
    }
}

/// Convert virtual address of EL2 for write access to physical address
///
/// This function uses AT S1E2W instruction.
///
/// # Arguments
/// * virtual_address - the virtual address to convert
///
/// # Result
/// If succeeded, returns Ok(physical_address), otherwise(the address is not accessible) returns Err(())
pub fn convert_virtual_address_to_physical_address_el2_write(
    virtual_address: usize,
) -> Result<usize, ()> {
    let aligned_virtual_address = virtual_address & PAGE_MASK;
    let offset = virtual_address & !PAGE_MASK;
    let aligned_physical_address: usize;
    unsafe {
        asm!("  at S1E2W, {:x}
                mrs {:x}, par_el1",
        in(reg) (aligned_virtual_address),
        out(reg) aligned_physical_address)
    };

    if (aligned_physical_address & 1) == 0 {
        Ok((aligned_physical_address & bitmask!(51, PAGE_SHIFT)) + offset)
    } else {
        Err(())
    }
}

/// Convert virtual address of EL0 for read access to intermediate physical address
///
/// This function uses AT S1E0R instruction.
///
/// # Arguments
/// * virtual_address - **the virtual address of EL0** to convert
///
/// # Result
/// If succeeded, returns Ok(intermediate_physical_address),
///  otherwise(the address is not accessible) returns Err(())
pub fn convert_virtual_address_to_intermediate_physical_address_el0_read(
    virtual_address: usize,
) -> Result<usize, ()> {
    let aligned_virtual_address = virtual_address & PAGE_MASK;
    let offset = virtual_address & !PAGE_MASK;
    let aligned_physical_address: usize;
    unsafe {
        asm!("  at S1E0R, {:x}
                mrs {:x}, par_el1",
        in(reg) (aligned_virtual_address),
        out(reg) aligned_physical_address)
    };

    if (aligned_physical_address & 1) == 0 {
        Ok((aligned_physical_address & bitmask!(51, PAGE_SHIFT)) + offset)
    } else {
        Err(())
    }
}

/// Convert virtual address of EL1 for read access to intermediate physical address
///
/// This function uses AT S1E1R instruction.
///
/// # Arguments
/// * virtual_address - **the virtual address of EL1** to convert
///
/// # Result
/// If succeeded, returns Ok(intermediate_physical_address),
///  otherwise(the address is not accessible) returns Err(())
pub fn convert_virtual_address_to_intermediate_physical_address_el1_read(
    virtual_address: usize,
) -> Result<usize, ()> {
    let aligned_virtual_address = virtual_address & PAGE_MASK;
    let offset = virtual_address & !PAGE_MASK;
    let aligned_physical_address: usize;
    unsafe {
        asm!("  at S1E1R, {:x}
                mrs {:x}, par_el1",
        in(reg) (aligned_virtual_address),
        out(reg) aligned_physical_address)
    };

    if (aligned_physical_address & 1) == 0 {
        Ok((aligned_physical_address & bitmask!(51, PAGE_SHIFT)) + offset)
    } else {
        Err(())
    }
}

/// Convert virtual address of EL1 for write access to intermediate physical address
///
/// This function uses AT S1E1W instruction.
///
/// # Arguments
/// * `virtual_address` - **the virtual address of EL1** to convert
///
/// # Result
/// If succeeded, returns Ok(intermediate_physical_address),
///  otherwise(the address is not accessible) returns Err(())
pub fn convert_virtual_address_to_intermediate_physical_address_el1_write(
    virtual_address: usize,
) -> Result<usize, ()> {
    let aligned_virtual_address = virtual_address & PAGE_MASK;
    let offset = virtual_address & !PAGE_MASK;
    let aligned_physical_address: usize;
    unsafe {
        asm!("  at S1E1W, {:x}
                mrs {:x}, par_el1",
        in(reg) (aligned_virtual_address),
        out(reg) aligned_physical_address)
    };

    if (aligned_physical_address & 1) == 0 {
        Ok((aligned_physical_address & bitmask!(51, PAGE_SHIFT)) + offset)
    } else {
        Err(())
    }
}

/// Halt Loop
///
/// Stop the cpu.
/// This function does not support to stop all cpus.
pub fn halt_loop() -> ! {
    loop {
        unsafe { asm!("wfi") };
    }
}
