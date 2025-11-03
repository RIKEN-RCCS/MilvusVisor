use crate::drivers::shared_memory::SharedMemory;
use crate::gic;
use crate::temporary_mapping::{create_temporary_mapping, remove_temporary_mapping};
use common::acpi::{get_acpi_table, madt::MADT};
use common::gic::{
    MAX_AP_REGISTERS, MAX_LIST_REGISTERS, apr_count_from_vtr, disable_delivery, lr_count_from_vtr,
    read_apr, read_eisr, read_elrsr, read_lr, read_misr, read_vmcr, read_vtr, restore_delivery,
    write_apr, write_lr, write_vmcr,
};
use common::{GeneralPurposeRegisters, HYPERVISOR_SERIAL_BASE_ADDRESS, PAGE_MASK, PAGE_SIZE, cpu};
use core::mem::{MaybeUninit, size_of};
use core::ptr;

pub const HVC_MIGRATION_START: u16 = 0xFFF2;
pub const HVC_MIGRATION_RECEIVE: u16 = 0xFFF3;

#[repr(C)]
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
    zcr_el1: u64,
}

// Only for arm_pl011
#[repr(C)]
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

#[repr(C)]
struct MigrationData {
    general_purpose_registers: GeneralPurposeRegisters,
    system_registers: SystemRegisters,
    hypervisor_mem_start: usize,
    hypervisor_mem_end: usize,
    serial_state: SerialState,
    gic_state: Gicv2State,
    gic_distributor_state: GicDistributorState,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Gicv2State {
    present: u8,
    lr_count: u8,
    apr_count: u8,
    _reserved: u8,
    hcr: u32,
    vtr: u32,
    vmcr: u32,
    misr: u32,
    eisr: [u32; 2],
    elrsr: [u32; 2],
    apr: [u32; MAX_AP_REGISTERS],
    lrs: [u64; MAX_LIST_REGISTERS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GicDistributorState {
    ctlr: u32,
    statusr: u32,
    igroupr: [u32; 32],
    isenabler: [u32; 32],
    ispendr: [u32; 32],
    isactiver: [u32; 32],
    ipriorityr: [u32; 255],
    itargetsr: [u32; 254], // itargetsr[0]はROなので省略している
    icfgr: [u32; 64],
    nsacr: [u32; 64],
    cpendsgir: [u32; 4],
    inmir: [u32; 32],
}

impl Default for Gicv2State {
    fn default() -> Self {
        Self {
            present: 0,
            lr_count: 0,
            apr_count: 0,
            _reserved: 0,
            hcr: 0,
            vtr: 0,
            vmcr: 0,
            misr: 0,
            eisr: [0; 2],
            elrsr: [0; 2],
            apr: [0; MAX_AP_REGISTERS],
            lrs: [0; MAX_LIST_REGISTERS],
        }
    }
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
const GICH_MAPPING_SIZE: usize = PAGE_SIZE;
const GICD_MAPPING_SIZE: usize = PAGE_SIZE;
const GICD_CTLR_OFFSET: usize = 0x000;
const GICD_TYPER_OFFSET: usize = 0x004;
const GICD_IIDR_OFFSET: usize = 0x008;

fn locate_gic_distributor() -> Option<(u8, usize)> {
    if let Some(base) = gic::distributor_base_address() {
        let version = gic::distributor_version().unwrap_or(0);
        return Some((version, base));
    }

    let rsdp = unsafe { crate::ACPI_RSDP? };
    let madt_ptr = get_acpi_table(rsdp.get(), &MADT::SIGNATURE).ok()?;
    let madt = unsafe { &*(madt_ptr as *const MADT) };
    madt.get_gic_distributor_address()
}

fn snapshot_gic_distributor_state() -> GicDistributorState {
    let mut state = GicDistributorState::default();

    let Some((version, base)) = locate_gic_distributor() else {
        println!("GIC distributor base not found");
        return state;
    };

    let gicd_page = base & PAGE_MASK;
    let gicd_offset = base - gicd_page;

    match create_temporary_mapping(gicd_page, GICD_MAPPING_SIZE) {
        Ok(temp_base) => {
            let gicd_virt = temp_base + gicd_offset;
            unsafe {
                state.ctlr = ptr::read_volatile((gicd_virt + GICD_CTLR_OFFSET) as *const u32);
            }

            if let Err(()) = remove_temporary_mapping(temp_base, GICD_MAPPING_SIZE) {
                println!(
                    "Failed to remove temporary mapping for GICD base {:x}",
                    base
                );
            }
        }
        Err(()) => println!("Failed to map GICD base {:x}", base),
    }

    state
}

fn restore_gic_distributor_state(state: &GicDistributorState) {
    let Some((_version, base)) = locate_gic_distributor() else {
        println!("Local GIC distributor base not found");
        return;
    };

    let gicd_page = base & PAGE_MASK;
    let gicd_offset = base - gicd_page;

    match create_temporary_mapping(gicd_page, GICD_MAPPING_SIZE) {
        Ok(temp_base) => {
            let gicd_virt = temp_base + gicd_offset;
            unsafe {
                // Only CTLR is writable; remaining fields are read-only discovery registers.
                ptr::write_volatile((gicd_virt + GICD_CTLR_OFFSET) as *mut u32, state.ctlr);
            }

            if let Err(()) = remove_temporary_mapping(temp_base, GICD_MAPPING_SIZE) {
                println!(
                    "Failed to remove temporary mapping for GICD base {:x}",
                    base
                );
            }
        }
        Err(()) => println!("Failed to map GICD base {:x} for restore", base),
    }
}

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

    let id_aa64pfr0_el1 = cpu::get_id_aa64pfr0_el1();
    let mut zcr_el1 = 0;
    if (id_aa64pfr0_el1 & cpu::ID_AA64PFR0_EL1_SVE) != 0 {
        println!("SVE is enabled");
        zcr_el1 = cpu::get_zcr_el1();
    }

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
        zcr_el1,
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
    println!("uartcr: {:b}", serial_state.cr);
    println!("uartimsc: {:b}", serial_state.imsc);

    let mut gic_state = Gicv2State::default();
    let mpidr = cpu::get_mpidr_el1();
    if let Some((_gicv_base, gich_base)) = gic::find_vgic_base(mpidr) {
        let gich_page = gich_base & PAGE_MASK;
        let gich_offset = gich_base - gich_page;
        match create_temporary_mapping(gich_page, GICH_MAPPING_SIZE) {
            Ok(temp_base) => {
                let gich_virt = temp_base + gich_offset;
                let original_hcr = disable_delivery(gich_virt);
                let vtr = read_vtr(gich_virt);
                gic_state.present = 1;
                gic_state.hcr = original_hcr;
                gic_state.vtr = vtr;
                gic_state.vmcr = read_vmcr(gich_virt);
                gic_state.misr = read_misr(gich_virt);
                for idx in 0..2 {
                    gic_state.eisr[idx] = read_eisr(gich_virt, idx);
                    gic_state.elrsr[idx] = read_elrsr(gich_virt, idx);
                }

                let lr_count = lr_count_from_vtr(vtr);
                gic_state.lr_count = lr_count as u8;
                for idx in 0..lr_count {
                    gic_state.lrs[idx] = read_lr(gich_virt, idx);
                }

                let apr_count = apr_count_from_vtr(vtr);
                gic_state.apr_count = apr_count as u8;
                for idx in 0..apr_count {
                    gic_state.apr[idx] = read_apr(gich_virt, idx);
                }

                restore_delivery(gich_virt, original_hcr);
                if let Err(()) = remove_temporary_mapping(temp_base, GICH_MAPPING_SIZE) {
                    println!(
                        "Failed to remove temporary mapping for GICH base {:x}",
                        gich_base
                    );
                }
            }
            Err(()) => {
                println!("Failed to map GICH base for MPIDR {:x}", mpidr);
            }
        }
    } else {
        println!("GICH base not found for MPIDR {:x}", mpidr);
    }

    let gic_distributor_state = snapshot_gic_distributor_state();
    println!(
        "GIC distributor: ctlr {:#x}",
        gic_distributor_state.ctlr,
    );

    let migration_data = MigrationData {
        general_purpose_registers: regs.clone(),
        system_registers: r,
        hypervisor_mem_start: el2_memory_start,
        hypervisor_mem_end: el2_memory_end,
        serial_state,
        gic_state,
        gic_distributor_state,
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
        zcr_el1,
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

    let id_aa64pfr0_el1 = cpu::get_id_aa64pfr0_el1();
    if (id_aa64pfr0_el1 & cpu::ID_AA64PFR0_EL1_SVE) != 0 {
        cpu::set_zcr_el1(zcr_el1);
        cpu::isb();
    }

    let gic_state = migration_data.gic_state;
    if gic_state.present != 0 {
        let mpidr = cpu::get_mpidr_el1();
        match gic::find_vgic_base(mpidr) {
            Some((_gicv_base, gich_base)) => {
                let gich_page = gich_base & PAGE_MASK;
                let gich_offset = gich_base - gich_page;
                match create_temporary_mapping(gich_page, GICH_MAPPING_SIZE) {
                    Ok(temp_base) => {
                        let gich_virt = temp_base + gich_offset;
                        let previous_hcr = disable_delivery(gich_virt);
                        let local_vtr = read_vtr(gich_virt);
                        let local_lr_capacity = lr_count_from_vtr(local_vtr);
                        let local_apr_capacity = apr_count_from_vtr(local_vtr);
                        let required_lr = usize::from(gic_state.lr_count);
                        let required_apr = usize::from(gic_state.apr_count);

                        if required_lr <= local_lr_capacity && required_apr <= local_apr_capacity {
                            write_vmcr(gich_virt, gic_state.vmcr);

                            for idx in 0..local_apr_capacity {
                                let value = if idx < required_apr {
                                    gic_state.apr[idx]
                                } else {
                                    0
                                };
                                write_apr(gich_virt, idx, value);
                            }

                            for idx in 0..local_lr_capacity {
                                let value = if idx < required_lr {
                                    gic_state.lrs[idx]
                                } else {
                                    0
                                };
                                write_lr(gich_virt, idx, value);
                            }

                            restore_delivery(gich_virt, gic_state.hcr);
                        } else {
                            println!(
                                "VGIC resources insufficient: need LR {} APR {}, have LR {} APR {}",
                                required_lr, required_apr, local_lr_capacity, local_apr_capacity
                            );
                            restore_delivery(gich_virt, previous_hcr);
                        }

                        if let Err(()) = remove_temporary_mapping(temp_base, GICH_MAPPING_SIZE) {
                            println!(
                                "Failed to remove temporary mapping for GICH base {:x}",
                                gich_base
                            );
                        }
                    }
                    Err(()) => println!("Failed to map GICH base for MPIDR {:x}", mpidr),
                }
            }
            None => println!("GICH base not found for MPIDR {:x}", mpidr),
        }
    }

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
