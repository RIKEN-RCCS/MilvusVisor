use crate::drivers::shared_memory::SharedMemory;
use crate::gic;
use crate::serial::{
    self, SerialState, UART_CR_OFFSET, UART_DMACR_OFFSET, UART_FBRD_OFFSET, UART_FR_OFFSET,
    UART_IBRD_OFFSET, UART_IFLS_OFFSET, UART_ILPR_OFFSET, UART_IMSC_OFFSET, UART_LCRH_OFFSET,
    UART_RIS_OFFSET, UART_RSR_OFFSET,
};
use crate::temporary_mapping::{
    create_device_temporary_mapping, create_temporary_mapping, remove_temporary_mapping,
};
use common::acpi::{get_acpi_table, madt::MADT};
use common::gic::{
    MAX_AP_REGISTERS, MAX_LIST_REGISTERS, apr_count_from_vtr, disable_delivery, lr_count_from_vtr,
    read_apr, read_eisr, read_elrsr, read_lr, read_misr, read_vmcr, read_vtr, restore_delivery,
    write_apr, write_lr, write_vmcr,
};
use common::{GeneralPurposeRegisters, PAGE_MASK, PAGE_SIZE, cpu};
use core::hint::spin_loop;
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

impl Default for GicDistributorState {
    fn default() -> Self {
        Self {
            ctlr: 0,
            statusr: 0,
            igroupr: [0; 32],
            isenabler: [0; 32],
            ispendr: [0; 32],
            isactiver: [0; 32],
            ipriorityr: [0; 255],
            itargetsr: [0; 254],
            icfgr: [0; 64],
            nsacr: [0; 64],
            cpendsgir: [0; 4],
            inmir: [0; 32],
        }
    }
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
const GICD_STATUSR_OFFSET: usize = 0x010;
const GICD_IGROUPR_OFFSET: usize = 0x080;
const GICD_ISENABLER_OFFSET: usize = 0x100;
const GICD_ICENABLER_OFFSET: usize = 0x180;
const GICD_ISPENDR_OFFSET: usize = 0x200;
const GICD_ICPENDR_OFFSET: usize = 0x280;
const GICD_ISACTIVER_OFFSET: usize = 0x300;
const GICD_ICACTIVER_OFFSET: usize = 0x380;
const GICD_IPRIORITYR_OFFSET: usize = 0x400;
const GICD_ITARGETSR_OFFSET: usize = 0x800;
const GICD_ICFGR_OFFSET: usize = 0xC00;
const GICD_NSACR_OFFSET: usize = 0xE00;
const GICD_CPENDSGIR_OFFSET: usize = 0xF10;
const GICD_SPENDSGIR_OFFSET: usize = 0xF20;
const GICD_INMIR_OFFSET: usize = 0xF80;

/// Wait until the distributor reports that all pending register writes are complete.
fn wait_for_gicd_rwp(gicd_virt: usize, version: u8) {
    if version >= 3 {
        while unsafe {
            ptr::read_volatile((gicd_virt + GICD_CTLR_OFFSET) as *const u32) & (1 << 31)
        } != 0
        {
            spin_loop();
        }
    }
}

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

    match create_device_temporary_mapping(gicd_page, GICD_MAPPING_SIZE) {
        Ok(temp_base) => {
            let gicd_virt = temp_base + gicd_offset;
            cpu::dsb();
            cpu::isb();
            unsafe {
                state.ctlr = ptr::read_volatile((gicd_virt + GICD_CTLR_OFFSET) as *const u32);
                if version >= 3 {
                    state.statusr =
                        ptr::read_volatile((gicd_virt + GICD_STATUSR_OFFSET) as *const u32);
                }

                let typer = ptr::read_volatile((gicd_virt + GICD_TYPER_OFFSET) as *const u32);
                let max_interrupts = state.ipriorityr.len() * 4;
                let num_interrupts =
                    core::cmp::min((((typer & 0x1F) + 1) * 32) as usize, max_interrupts);
                let igroup_regs = ((num_interrupts + 31) / 32).min(state.igroupr.len());
                let priority_regs = ((num_interrupts + 3) / 4).min(state.ipriorityr.len());
                let config_regs = ((num_interrupts + 15) / 16).min(state.icfgr.len());
                let inmir_regs = ((num_interrupts + 31) / 32).min(state.inmir.len());
                let itarget_regs = priority_regs.saturating_sub(1).min(state.itargetsr.len());
                let stride = size_of::<u32>();

                for idx in 0..igroup_regs {
                    state.igroupr[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_IGROUPR_OFFSET + idx * stride) as *const u32,
                    );
                    state.isenabler[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_ISENABLER_OFFSET + idx * stride) as *const u32,
                    );
                    state.ispendr[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_ISPENDR_OFFSET + idx * stride) as *const u32,
                    );
                    state.isactiver[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_ISACTIVER_OFFSET + idx * stride) as *const u32,
                    );
                }

                for idx in 0..priority_regs {
                    state.ipriorityr[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_IPRIORITYR_OFFSET + idx * stride) as *const u32,
                    );
                }

                for offset_idx in 0..itarget_regs {
                    let reg_index = offset_idx + 1; // itargetsr0はROなのでスキップ
                    state.itargetsr[offset_idx] = ptr::read_volatile(
                        (gicd_virt + GICD_ITARGETSR_OFFSET + reg_index * stride) as *const u32,
                    );
                }

                for idx in 0..config_regs {
                    state.icfgr[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_ICFGR_OFFSET + idx * stride) as *const u32,
                    );
                    state.nsacr[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_NSACR_OFFSET + idx * stride) as *const u32,
                    );
                }

                for idx in 0..state.cpendsgir.len() {
                    state.cpendsgir[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_CPENDSGIR_OFFSET + idx * stride) as *const u32,
                    );
                }

                for idx in 0..inmir_regs {
                    state.inmir[idx] = ptr::read_volatile(
                        (gicd_virt + GICD_INMIR_OFFSET + idx * stride) as *const u32,
                    );
                }
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
    let Some((version, base)) = locate_gic_distributor() else {
        println!("Local GIC distributor base not found");
        return;
    };

    let gicd_page = base & PAGE_MASK;
    let gicd_offset = base - gicd_page;

    match create_device_temporary_mapping(gicd_page, GICD_MAPPING_SIZE) {
        Ok(temp_base) => {
            let gicd_virt = temp_base + gicd_offset;
            unsafe {
                let typer = ptr::read_volatile((gicd_virt + GICD_TYPER_OFFSET) as *const u32);
                let max_interrupts = state.ipriorityr.len() * 4;
                let num_interrupts =
                    core::cmp::min((((typer & 0x1F) + 1) * 32) as usize, max_interrupts);
                let igroup_regs = ((num_interrupts + 31) / 32).min(state.igroupr.len());
                let priority_regs = ((num_interrupts + 3) / 4).min(state.ipriorityr.len());
                let config_regs = ((num_interrupts + 15) / 16).min(state.icfgr.len());
                let inmir_regs = ((num_interrupts + 31) / 32).min(state.inmir.len());
                let itarget_regs = priority_regs.saturating_sub(1).min(state.itargetsr.len());
                let stride = size_of::<u32>();

                let mask_for_register = |idx: usize| -> u32 {
                    let base = idx * 32;
                    if num_interrupts <= base {
                        0
                    } else {
                        let remaining = num_interrupts - base;
                        if remaining >= 32 {
                            u32::MAX
                        } else {
                            (1u32 << remaining) - 1
                        }
                    }
                };

                ptr::write_volatile((gicd_virt + GICD_CTLR_OFFSET) as *mut u32, 0);
                cpu::dsb();
                wait_for_gicd_rwp(gicd_virt, version);
                cpu::isb();

                if version >= 3 {
                    ptr::write_volatile(
                        (gicd_virt + GICD_STATUSR_OFFSET) as *mut u32,
                        state.statusr,
                    );
                }

                for idx in 0..igroup_regs {
                    let mask = mask_for_register(idx);
                    ptr::write_volatile(
                        (gicd_virt + GICD_IGROUPR_OFFSET + idx * stride) as *mut u32,
                        state.igroupr[idx] & mask,
                    );
                }

                for idx in 0..igroup_regs {
                    let mask = mask_for_register(idx);
                    if mask == 0 {
                        continue;
                    }

                    let enable_bits = state.isenabler[idx] & mask;
                    let disable_bits = mask & !enable_bits;

                    if disable_bits != 0 {
                        ptr::write_volatile(
                            (gicd_virt + GICD_ICENABLER_OFFSET + idx * stride) as *mut u32,
                            disable_bits,
                        );
                    }
                    if enable_bits != 0 {
                        ptr::write_volatile(
                            (gicd_virt + GICD_ISENABLER_OFFSET + idx * stride) as *mut u32,
                            enable_bits,
                        );
                    }
                }

                for idx in 0..igroup_regs {
                    let mask = mask_for_register(idx);
                    if mask == 0 {
                        continue;
                    }

                    ptr::write_volatile(
                        (gicd_virt + GICD_ICPENDR_OFFSET + idx * stride) as *mut u32,
                        mask,
                    );

                    let pending = state.ispendr[idx] & mask;
                    if pending != 0 {
                        ptr::write_volatile(
                            (gicd_virt + GICD_ISPENDR_OFFSET + idx * stride) as *mut u32,
                            pending,
                        );
                    }
                }

                for idx in 0..igroup_regs {
                    let mask = mask_for_register(idx);
                    if mask == 0 {
                        continue;
                    }

                    ptr::write_volatile(
                        (gicd_virt + GICD_ICACTIVER_OFFSET + idx * stride) as *mut u32,
                        mask,
                    );

                    let active = state.isactiver[idx] & mask;
                    if active != 0 {
                        ptr::write_volatile(
                            (gicd_virt + GICD_ISACTIVER_OFFSET + idx * stride) as *mut u32,
                            active,
                        );
                    }
                }

                for idx in 0..priority_regs {
                    ptr::write_volatile(
                        (gicd_virt + GICD_IPRIORITYR_OFFSET + idx * stride) as *mut u32,
                        state.ipriorityr[idx],
                    );
                }

                for offset_idx in 0..itarget_regs {
                    let reg_index = offset_idx + 1; // itargetsr0はROなのでスキップ
                    ptr::write_volatile(
                        (gicd_virt + GICD_ITARGETSR_OFFSET + reg_index * stride) as *mut u32,
                        state.itargetsr[offset_idx],
                    );
                }

                for idx in 0..config_regs {
                    ptr::write_volatile(
                        (gicd_virt + GICD_ICFGR_OFFSET + idx * stride) as *mut u32,
                        state.icfgr[idx],
                    );
                    ptr::write_volatile(
                        (gicd_virt + GICD_NSACR_OFFSET + idx * stride) as *mut u32,
                        state.nsacr[idx],
                    );
                }

                for idx in 0..state.cpendsgir.len() {
                    let value = state.cpendsgir[idx];
                    if value != 0 {
                        ptr::write_volatile(
                            (gicd_virt + GICD_SPENDSGIR_OFFSET + idx * stride) as *mut u32,
                            value,
                        );
                    }
                }

                for idx in 0..inmir_regs {
                    ptr::write_volatile(
                        (gicd_virt + GICD_INMIR_OFFSET + idx * stride) as *mut u32,
                        state.inmir[idx],
                    );
                }

                cpu::dsb();
                wait_for_gicd_rwp(gicd_virt, version);
                ptr::write_volatile((gicd_virt + GICD_CTLR_OFFSET) as *mut u32, state.ctlr);
                cpu::dsb();
                cpu::isb();
                wait_for_gicd_rwp(gicd_virt, version);

                println!("==== GICD Restore Complete ====");
                println!("GICD CTLR: {:#x}", state.ctlr);
                println!("GICD STATUSR: {:#x}", state.statusr);
                println!("===============================");
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
    let serial_state = unsafe { SerialState::read_from_hardware() };
    serial_state.dump("Migration capture");
    let uart_fr: u16 = unsafe { serial::read_serial_register(UART_FR_OFFSET) };
    println!("UART FR (Flag Register): {:#x} ({:#b})", uart_fr, uart_fr);

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
    println!("==== GICD Migration State ====");
    println!("GICD CTLR: {:#x}", gic_distributor_state.ctlr);
    println!("GICD STATUSR: {:#x}", gic_distributor_state.statusr);
    for idx in 0..gic_distributor_state.igroupr.len() {
        println!(
            "GICD IGROUPR[{}]: {:#x}",
            idx, gic_distributor_state.igroupr[0]
        );
    }
    for idx in 0..gic_distributor_state.ipriorityr.len() {
        println!(
            "GICD ISENABLER[{}]: {:#x}",
            idx, gic_distributor_state.isenabler[0]
        );
    }
    for idx in 0..gic_distributor_state.icfgr.len() {
        println!(
            "GICD ISPENDR[{}]: {:#x}",
            idx, gic_distributor_state.ispendr[0]
        );
    }
    for idx in 0..gic_distributor_state.isactiver.len() {
        println!(
            "GICD ISACTIVER[{}]: {:#x}",
            idx, gic_distributor_state.isactiver[0]
        );
    }
    println!("============================");

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

    // Restore GIC distributor state
    println!("==== GICD Received State ====");
    println!(
        "GICD CTLR: {:#x}",
        migration_data.gic_distributor_state.ctlr
    );
    println!(
        "GICD STATUSR: {:#x}",
        migration_data.gic_distributor_state.statusr
    );
    println!(
        "GICD IGROUPR[0]: {:#x}",
        migration_data.gic_distributor_state.igroupr[0]
    );
    println!(
        "GICD ISENABLER[0]: {:#x}",
        migration_data.gic_distributor_state.isenabler[0]
    );
    println!(
        "GICD ISPENDR[0]: {:#x}",
        migration_data.gic_distributor_state.ispendr[0]
    );
    println!(
        "GICD ISACTIVER[0]: {:#x}",
        migration_data.gic_distributor_state.isactiver[0]
    );
    println!("============================");
    restore_gic_distributor_state(&migration_data.gic_distributor_state);

    // restore serial state
    let serial_state = migration_data.serial_state;
    serial_state.dump("Migration restore input");
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
        serial::write_serial_u32(UART_CR_OFFSET, 0);
        serial::write_serial_u32(UART_ILPR_OFFSET, ilpr as u32);
        serial::write_serial_u32(UART_IBRD_OFFSET, ibrd as u32);
        serial::write_serial_u32(UART_FBRD_OFFSET, fbrd as u32);
        serial::write_serial_u32(UART_LCRH_OFFSET, lcr_h as u32);
        serial::write_serial_u32(UART_IFLS_OFFSET, ifls as u32);
        serial::write_serial_u32(UART_IMSC_OFFSET, imsc as u32);
        serial::write_serial_u32(UART_DMACR_OFFSET, dmacr as u32);
        if rsr != 0 {
            // Writing to RSR clears latched errors
            serial::write_serial_u32(UART_RSR_OFFSET, rsr as u32);
        }
        serial::write_serial_u32(UART_CR_OFFSET, cr as u32);
    }
    serial::dump_live_serial_state("Migration restore result");

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
