//!
//! CPU Specified Assembly functions
//!

use crate::{bitmask, PAGE_MASK, PAGE_SHIFT};

#[derive(Clone)]
pub struct InterruptFlag(u64);

const DAIF_IRQ_BIT: u64 = 7;
const DAIF_FIQ_BIT: u64 = 6;

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
