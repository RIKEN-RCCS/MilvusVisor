use core::ptr;
use common::cpu;
use crate::drivers::shared_memory::SharedMemory;

pub const HVC_MIGRATION_START: u16 = 0xFFF2;

#[derive(Clone)]
struct SystemRegisters {
    cpacr_el1: u64,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    mair_el1: u64,
    sctlr_el1: u64,
    vbar_el1: u64,
    spsr_el2: u64,
    elr_el2: u64,
    sp_el1: u64,
}

struct MigrationData {
    system_registers: SystemRegisters,
}

// Ref: https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}

// 共有メモリにプログラムの状態を保存することでmigrationを開始する
pub fn start_migration() {
    println!("Starting migration...");

    // TODO: 今はアドレスを決め打ちしている
    let shared_memory: &mut SharedMemory = unsafe { ptr::with_exposed_provenance_mut::<SharedMemory>(0x8000000000).as_mut().unwrap()  };

    let r = SystemRegisters {
        cpacr_el1: cpu::get_cpacr_el1(),
        ttbr0_el1: cpu::get_ttbr0_el1(),
        ttbr1_el1: cpu::get_ttbr1_el1(),
        tcr_el1: cpu::get_tcr_el1(),
        mair_el1: cpu::get_mair_el1(),
        sctlr_el1: cpu::get_sctlr_el1(),
        vbar_el1: cpu::get_vbar_el1(),
        spsr_el2: cpu::get_spsr_el2(),
        elr_el2: cpu::get_elr_el2(),
        sp_el1: cpu::get_sp_el1(),
    };
    let migration_data = MigrationData {
        system_registers: r,
    };
    shared_memory.write(unsafe { any_as_u8_slice(&migration_data)});
}
