// Copyright (c) 2022 RIKEN
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

/* CPU Bit Fields */
pub const DAIF_IRQ_BIT: u64 = 7;
pub const DAIF_FIQ_BIT: u64 = 6;

/* CNTHCTL_EL2 Register */
pub const CNTHCTL_EL2_EL1PTEN: u64 = 1 << 11;
pub const CNTHCTL_EL2_EL1PCTEN: u64 = 1 << 10;
pub const CNTHCTL_EL2_EL0PTEN: u64 = 1 << 9;
pub const CNTHCTL_EL2_EL0PCTEN: u64 = 1 << 8;

/* CPACR_EL1 Register */
pub const CPACR_EL1_TTA_BIT_OFFSET: u64 = 28;
//pub const CPACR_EL1_TTA: u64 = 1 << CPACR_EL1_TTA_BIT_OFFSET;
pub const CPACR_EL1_FPEN_BITS_OFFSET: u64 = 20;
//pub const CPACR_EL1_FPEN: u64 = 0b11 << CPACR_EL1_FPEN_BITS_OFFSET;
pub const CPACR_EL1_ZEN_BITS_OFFSET: u64 = 16;
//pub const CPACR_EL1_ZEN: u64 = 0b11 << CPACR_EL1_ZEN_BITS_OFFSET;

/* CPTR_EL2 Register */
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

/* TCR_EL2 Register */
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

/* TCR_EL1 Register */
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

/* HCR_EL2 Register */
pub const HCR_EL2_FIEN: u64 = 1 << 47;
pub const HCR_EL2_API: u64 = 1 << 41;
pub const HCR_EL2_APK: u64 = 1 << 40;
//pub const HCR_EL2_TEA: u64 = 1 << 37;
pub const HCR_EL2_E2H: u64 = 1 << 34;
pub const HCR_EL2_RW: u64 = 1 << 31;
pub const HCR_EL2_TSC: u64 = 1 << 19;
pub const HCR_EL2_VM: u64 = 1 << 0;

/* VTCR_EL2 Register */
pub const VTCR_EL2_RES1: u64 = 1 << 31;
pub const VTCR_EL2_HWU_BITS_OFFSET: u64 = 25;
pub const VTCR_EL2_PS_BITS_OFFSET: u64 = 16;
pub const VTCR_EL2_TG0_BITS_OFFSET: u64 = 14;
pub const VTCR_EL2_SH0_BITS_OFFSET: u64 = 12;
pub const VTCR_EL2_ORG0_BITS_OFFSET: u64 = 10;
pub const VTCR_EL2_IRG0_BITS_OFFSET: u64 = 8;
pub const VTCR_EL2_SL0_BITS_OFFSET: u64 = 6;
pub const VTCR_EL2_SL0: u64 = 0b11 << VTCR_EL2_SL0_BITS_OFFSET;
pub const VTCR_EL2_T0SZ_BITS_OFFSET: u64 = 0;
pub const VTCR_EL2_T0SZ: u64 = 0b111111 << VTCR_EL2_T0SZ_BITS_OFFSET;

/// SMC Calling Convention 1.2に沿ったSMCを発行
///
/// 指定したレジスタの値をセットした状況でSMC #0を発行します。
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
    return ttbr0_el2;
}

#[inline(always)]
pub fn set_ttbr0_el2(ttbr0_el2: u64) {
    unsafe { asm!("msr ttbr0_el2, {:x}", in(reg) ttbr0_el2) };
}

#[inline(always)]
pub fn set_ttbr0_el1(ttbr0_el1: u64) {
    unsafe { asm!("msr ttbr0_el1, {:x}", in(reg) ttbr0_el1) };
}

#[inline(always)]
pub fn get_tcr_el2() -> u64 {
    let tcr_el2: u64;
    unsafe { asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2) };
    return tcr_el2;
}

#[inline(always)]
pub fn set_tcr_el2(tcr_el2: u64) {
    unsafe { asm!("msr tcr_el2, {:x}", in(reg) tcr_el2) };
}

#[inline(always)]
pub fn get_vttbr_el2() -> u64 {
    let vttbr_el2: u64;
    unsafe { asm!("mrs {:x}, vttbr_el2", out(reg) vttbr_el2) };
    return vttbr_el2;
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
    return vtcr_el2;
}

#[inline(always)]
pub fn set_vtcr_el2(vtcr_el2: u64) {
    unsafe { asm!("msr vtcr_el2, {:x}", in(reg) vtcr_el2) };
}

#[inline(always)]
pub fn get_mair_el2() -> u64 {
    let mair_el2: u64;
    unsafe { asm!("mrs {:x}, mair_el2",out(reg) mair_el2) };
    return mair_el2;
}

#[inline(always)]
pub fn get_id_aa64mmfr0_el1() -> u64 {
    let id_aa64mmfr0_el1: u64;
    unsafe { asm!("mrs {:x}, id_aa64mmfr0_el1",out(reg) id_aa64mmfr0_el1) };
    return id_aa64mmfr0_el1;
}

#[inline(always)]
pub fn flush_tlb_el2() {
    unsafe {
        asm!(
            "
             tlbi  alle2
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
            tlbi alle1
            dsb ish
            isb"
        )
    };
}

#[inline(always)]
pub fn flush_tlb_vmalls12e1() {
    unsafe { asm!("TLBI VMALLS12E1") };
}

/// 現時点の割り込み状況を保存し、IRQ/FIQを禁止
///
/// # Return Value
/// 保存された割り込み状況、 [`local_irq_fiq_restore`]の引数として使用
pub fn local_irq_fiq_save() -> InterruptFlag {
    let mut daif: u64;
    unsafe { asm!("mrs {:x}, DAIF",out(reg) daif) };
    let flag = InterruptFlag(daif);
    daif |= (1 << DAIF_IRQ_BIT) | (1 << DAIF_FIQ_BIT);
    unsafe {
        asm!("  dsb ish
                isb
                msr DAIF, {:x}", in(reg) daif)
    };
    flag
}

/// 割り込み状況を復元
///
/// # Arguments
/// * f: 保存された割り込み状況、 [`local_irq_fiq_save`]の戻り値
pub fn local_irq_fiq_restore(f: InterruptFlag) {
    unsafe {
        asm!("  dsb ish
                isb
                msr DAIF, {:x}", in(reg) f.0)
    };
}

/// 渡された仮想アドレスをEL2での仮想アドレスと解釈し、物理アドレスに変換
///
/// AT S1E2Rを使用して、物理アドレスに変換します。マップされてない場合などはErrを返します。
///
/// # Arguments
/// virtual_address: 変換を行う仮想アドレス
///
/// # Return Value
/// 変換に成功した場合はOk(physical_address)、失敗した場合はErr(())
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

/// 渡された仮想アドレスをEL2での仮想アドレスと解釈し、物理アドレスに変換
///
/// AT S1E2Wを使用して、物理アドレスに変換します。マップされてない場合などはErrを返します。
///
/// # Arguments
/// virtual_address: 変換を行う仮想アドレス
///
/// # Return Value
/// 変換に成功した場合はOk(physical_address)、失敗した場合はErr(())
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

/// 渡された仮想アドレスをEL1での仮想アドレスと解釈し、中間物理アドレス(IPA)に変換
///
/// AT S1E1Rを使用して、中間物理アドレスに変換します。マップされてない場合などはErrを返します。
///
/// # Arguments
/// virtual_address: 変換を行う仮想アドレス
///
/// # Return Value
/// 変換に成功した場合はOk(physical_address)、失敗した場合はErr(())
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

/// 渡された仮想アドレスをEL1での仮想アドレスと解釈し、中間物理アドレス(IPA)に変換
///
/// AT S1E1Wを使用して、中間物理アドレスに変換します。マップされてない場合などはErrを返します。
///
/// # Arguments
/// virtual_address: 変換を行う仮想アドレス
///
/// # Return Value
/// 変換に成功した場合はOk(physical_address)、失敗した場合はErr(())
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
/// CPUを待機状態にさせ停止させる
/// マルチコア制御には未対応
pub fn halt_loop() -> ! {
    loop {
        unsafe { asm!("wfi") };
    }
}
