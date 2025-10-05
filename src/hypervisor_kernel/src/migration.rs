use crate::drivers::shared_memory::SharedMemory;
use crate::temporary_mapping::{create_temporary_mapping, remove_temporary_mapping};
use common::{GeneralPurposeRegisters, HYPERVISOR_SERIAL_BASE_ADDRESS, PAGE_SIZE, cpu};
use core::mem::MaybeUninit;
use core::ptr;

pub const HVC_MIGRATION_START: u16 = 0xFFF2;
pub const HVC_MIGRATION_RECEIVE: u16 = 0xFFF3;

#[derive(Clone)]
struct SystemRegisters {
    cpacr_el1: u64,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    mair_el1: u64,
    sctlr_el1: u64,
    vbar_el1: u64,
    elr_el1: u64,
    contextidr_el1: u64,
    tpidr_el0: u64,
    tpidr_el1: u64,
    afsr0_el1: u64,
    afsr1_el1: u64,
    spsr_el2: u64,
    spsr_el1: u64,
    elr_el2: u64,
    sp_el1: u64,
    sp_el0: u64,
    esr_el1: u64,
    far_el1: u64,
}

// Only for arm_pl011
#[derive(Clone)]
struct SerialState {
    rsr: u8,
    ibrd: u16,
    fbrd: u8,
    lcr_h: u8,
    cr: u16,
    ifls: u8,
    imsc: u16,
    ris: u16,
    dmacr: u8,
    ilpr: u8,
}

const UART_RSR_OFFSET: usize = 0x004;
const UART_ILPR_OFFSET: usize = 0x020;
const UART_IBRD_OFFSET: usize = 0x024;
const UART_FBRD_OFFSET: usize = 0x028;
const UART_LCRH_OFFSET: usize = 0x02C;
const UART_CR_OFFSET: usize = 0x030;
const UART_IFLS_OFFSET: usize = 0x034;
const UART_IMSC_OFFSET: usize = 0x038;
const UART_RIS_OFFSET: usize = 0x03C;
const UART_DMACR_OFFSET: usize = 0x048;

struct MigrationData {
    general_purpose_registers: GeneralPurposeRegisters,
    system_registers: SystemRegisters,
    hypervisor_mem_start: usize,
    hypervisor_mem_end: usize,
    serial_state: SerialState,
}

unsafe fn write_serial_u32(offset: usize, value: u32) {
    ptr::write_volatile((HYPERVISOR_SERIAL_BASE_ADDRESS + offset) as *mut u32, value);
}

// Ref: https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}

const MEM_START: usize = 0x4000_0000;
const MEM_END: usize = MEM_START + 0x4000_0000;

unsafe fn read_serial_register<T>(offset: usize) -> T {
    let base = HYPERVISOR_SERIAL_BASE_ADDRESS as *const u8;
    unsafe { ptr::read_volatile(base.add(offset).cast::<T>()) }
}

// 共有メモリにプログラムの状態を保存することでmigrationを開始する
pub fn start_migration(
    regs: &GeneralPurposeRegisters,
    el2_memory_start: usize,
    el2_memory_end: usize,
) -> Result<(), ()> {
    println!("Starting migration...");

    // TODO: 今はアドレスを決め打ちしている
    let shared_memory: &mut SharedMemory = unsafe {
        ptr::with_exposed_provenance_mut::<SharedMemory>(0x80_0000_0000)
            .as_mut()
            .unwrap()
    };

    let r = SystemRegisters {
        cpacr_el1: cpu::get_cpacr_el1(),
        ttbr0_el1: cpu::get_ttbr0_el1(),
        ttbr1_el1: cpu::get_ttbr1_el1(),
        tcr_el1: cpu::get_tcr_el1(),
        mair_el1: cpu::get_mair_el1(),
        sctlr_el1: cpu::get_sctlr_el1(),
        vbar_el1: cpu::get_vbar_el1(),
        elr_el1: cpu::get_elr_el1(),
        contextidr_el1: cpu::get_contextidr_el1(),
        tpidr_el0: cpu::get_tpidr_el0(),
        tpidr_el1: cpu::get_tpidr_el1(),
        afsr0_el1: cpu::get_afsr0_el1(),
        afsr1_el1: cpu::get_afsr1_el1(),
        spsr_el2: cpu::get_spsr_el2(),
        spsr_el1: cpu::get_spsr_el1(),
        elr_el2: cpu::get_elr_el2(),
        sp_el1: cpu::get_sp_el1(),
        sp_el0: cpu::get_sp_el0(),
        esr_el1: cpu::get_esr_el1(),
        far_el1: cpu::get_far_el1(),
    };

    // シリアルの状態を保存する
    let serial_state = unsafe {
        SerialState {
            rsr: read_serial_register(UART_RSR_OFFSET),
            ibrd: read_serial_register(UART_IBRD_OFFSET),
            fbrd: read_serial_register(UART_FBRD_OFFSET),
            lcr_h: read_serial_register(UART_LCRH_OFFSET),
            cr: read_serial_register(UART_CR_OFFSET),
            ifls: read_serial_register(UART_IFLS_OFFSET),
            imsc: read_serial_register(UART_IMSC_OFFSET),
            ris: read_serial_register(UART_RIS_OFFSET),
            dmacr: read_serial_register(UART_DMACR_OFFSET),
            ilpr: read_serial_register(UART_ILPR_OFFSET),
        }
    };

    let migration_data = MigrationData {
        general_purpose_registers: regs.clone(),
        system_registers: r,
        hypervisor_mem_start: el2_memory_start,
        hypervisor_mem_end: el2_memory_end,
        serial_state,
    };
    println!("Sending base information");
    shared_memory.clear();
    shared_memory.write(unsafe { any_as_u8_slice(&migration_data) });
    println!("Sending memory");

    //　メモリ領域をまるごとコピーする
    let mut addr = MEM_START;
    while addr < MEM_END {
        // el2領域はPAGE_SIZEでアラインされていることを仮定
        if addr < el2_memory_start || addr >= el2_memory_end {
            let target_phys_addr = addr;
            // 読み込み対象の物理アドレスに対して一時ページテーブルをつくる
            let target_virt_addr = create_temporary_mapping(target_phys_addr, PAGE_SIZE)?;
            //println!("addr: {:x} {:x}", target_phys_addr, target_virt_addr);
            // 読み込まれるのを待つ
            while !shared_memory.is_ready_to_write() {}
            //println!("addr: {:x} is ready", target_phys_addr);
            shared_memory.modify(
                |dst| unsafe {
                    core::ptr::copy_nonoverlapping(
                        target_virt_addr as *const u8,
                        dst.as_mut_ptr(),
                        PAGE_SIZE,
                    );
                },
                PAGE_SIZE,
            );
            //println!("addr: {:x} modified", target_phys_addr);
            // 一時テーブルを削除
            remove_temporary_mapping(target_virt_addr, PAGE_SIZE)?;
            if target_phys_addr & 0xffffff == 0 {
                println!("addr: {:x} remove temp table", target_phys_addr);
            }
        }
        addr += PAGE_SIZE;
    }
    println!("End migration");
    Ok(())
}

pub fn receive_migration(regs: &mut GeneralPurposeRegisters) -> Result<(), ()> {
    println!("Receiving migration...");
    // TODO: 今はアドレスを決め打ちしている
    let shared_memory: &mut SharedMemory = unsafe {
        ptr::with_exposed_provenance_mut::<SharedMemory>(0x80_0000_0000)
            .as_mut()
            .unwrap()
    };
    // まずはレジスタ情報がやってくるはず
    let mut migration_data = MaybeUninit::<MigrationData>::uninit();
    loop {
        if let Some(data) = shared_memory.read() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    migration_data.as_mut_ptr() as *mut u8,
                    size_of::<MigrationData>(),
                );
            }
            shared_memory.clear();
            break;
        }
    }
    println!("Received base information");
    let migration_data = unsafe { migration_data.assume_init() };
    println!("Got migration data");
    let SystemRegisters {
        cpacr_el1,
        ttbr0_el1,
        ttbr1_el1,
        tcr_el1,
        mair_el1,
        sctlr_el1,
        vbar_el1,
        elr_el1,
        contextidr_el1,
        tpidr_el0,
        tpidr_el1,
        afsr0_el1,
        afsr1_el1,
        spsr_el2,
        spsr_el1,
        elr_el2,
        sp_el1,
        sp_el0,
        esr_el1,
        far_el1,
    } = migration_data.system_registers;
    cpu::set_cpacr_el1(cpacr_el1);
    cpu::set_ttbr0_el1(ttbr0_el1);
    cpu::set_ttbr1_el1(ttbr1_el1);
    cpu::set_tcr_el1(tcr_el1);
    cpu::set_mair_el1(mair_el1);
    // Restore SCTLR_EL1 after TTBR/TCR/MAIR with barriers
    // Ensure ordering before changing EL1 control state
    cpu::dsb();
    cpu::isb();
    cpu::set_sctlr_el1(sctlr_el1);
    // Ensure the new control settings take effect
    cpu::isb();
    // Be conservative: refresh TLB and I-Cache for EL1 context
    cpu::flush_tlb_el1();
    cpu::clear_instruction_cache_all();
    cpu::set_vbar_el1(vbar_el1);
    // Restore EL1 context registers
    cpu::set_contextidr_el1(contextidr_el1);
    cpu::set_tpidr_el0(tpidr_el0);
    cpu::set_tpidr_el1(tpidr_el1);
    cpu::set_afsr0_el1(afsr0_el1);
    cpu::set_afsr1_el1(afsr1_el1);
    cpu::set_spsr_el2(spsr_el2);
    cpu::set_spsr_el1(spsr_el1);
    cpu::set_elr_el1(elr_el1);
    cpu::set_elr_el2(elr_el2);
    cpu::set_sp_el1(sp_el1);
    cpu::set_sp_el0(sp_el0);
    cpu::set_esr_el1(esr_el1);
    cpu::set_far_el1(far_el1);
    println!("Done");

    // restore serial state
    let serial_state = migration_data.serial_state;
    unsafe {
        let SerialState {
            rsr,
            ibrd,
            fbrd,
            lcr_h,
            cr,
            ifls,
            imsc,
            ris: _,
            dmacr,
            ilpr,
        } = serial_state;

        // Disable while programming configuration
        write_serial_u32(UART_CR_OFFSET, 0);
        write_serial_u32(UART_ILPR_OFFSET, ilpr as u32);
        write_serial_u32(UART_IBRD_OFFSET, ibrd as u32);
        write_serial_u32(UART_FBRD_OFFSET, fbrd as u32);
        write_serial_u32(UART_LCRH_OFFSET, lcr_h as u32);
        write_serial_u32(UART_IFLS_OFFSET, ifls as u32);
        write_serial_u32(UART_IMSC_OFFSET, imsc as u32);
        write_serial_u32(UART_DMACR_OFFSET, dmacr as u32);
        if rsr != 0 {
            // Writing to RSR clears latched errors
            write_serial_u32(UART_RSR_OFFSET, rsr as u32);
        }
        write_serial_u32(UART_CR_OFFSET, cr as u32);
    }

    let src_regs = migration_data.general_purpose_registers;
    regs.copy_from_slice(src_regs.as_slice());

    println!("hyp_mem_start: {:x}", migration_data.hypervisor_mem_start);
    println!("hyp_mem_end: {:x}", migration_data.hypervisor_mem_end);
    // 次はメモリ情報を読み込んでいく
    let mut addr = MEM_START;

    println!("Receiving memory");
    while addr < MEM_END {
        if addr < migration_data.hypervisor_mem_start || addr >= migration_data.hypervisor_mem_end {
            let target_phys_addr = addr;
            // 読み込み対象の物理アドレスに対して一時ページテーブルをつくる
            let target_virt_addr = create_temporary_mapping(target_phys_addr, PAGE_SIZE)?;
            loop {
                if let Some(data) = shared_memory.read() {
                    //println!("addr: {:x} data[0]: {:x}", target_phys_addr, data[0]);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr(),
                            target_virt_addr as *mut u8,
                            PAGE_SIZE,
                        );
                    }
                    //println!("addr: {:x} copied", target_phys_addr);
                    shared_memory.clear();
                    if target_phys_addr & 0xffffff == 0 {
                        println!("addr: {:x} cleared", target_phys_addr);
                    }
                    break;
                }
            }
            remove_temporary_mapping(target_virt_addr, PAGE_SIZE)?;
        }
        addr += PAGE_SIZE;
    }
    println!("End migration");
    Ok(())
}
