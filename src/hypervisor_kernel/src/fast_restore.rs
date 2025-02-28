// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use crate::paging::{
    add_memory_access_trap, map_address, remake_stage2_page_table, remove_memory_access_trap,
};
use crate::{BSP_MPIDR, allocate_memory, free_memory, gic, multi_core, psci, smmu};

use common::{
    GeneralPurposeRegisters, MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG, MemorySaveListEntry, PAGE_MASK,
    PAGE_SHIFT, PAGE_SIZE, STACK_PAGES, cpu, paging,
};

use core::mem::MaybeUninit;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{AtomicBool, Ordering};

static IS_RESTORE_NEEDED: AtomicBool = AtomicBool::new(false);
static mut MEMORY_SAVE_LIST: MaybeUninit<&'static mut [MemorySaveListEntry]> =
    MaybeUninit::uninit();
static mut SAVED_SYSTEM_REGISTERS: SavedSystemRegisters = SavedSystemRegisters::new();
static mut SAVED_REGISTERS: GeneralPurposeRegisters = [0; 32];
static mut ORIGINAL_VTTBR_EL2: u64 = 0;

pub const HVC_EXIT_BOOT_SERVICE_TRAP: u16 = 0xFFF0;
pub const HVC_AFTER_EXIT_BOOT_SERVICE_TRAP: u16 = 0xFFF1;

#[derive(Clone)]
struct SavedSystemRegisters {
    cpacr_el1: u64,
    ttbr0_el1: u64,
    /*ttbr1_el1: u64,*/
    tcr_el1: u64,
    mair_el1: u64,
    sctlr_el1: u64,
    vbar_el1: u64,
    spsr_el2: u64,
    elr_el2: u64,
    sp_el1: u64,
}

impl SavedSystemRegisters {
    const fn new() -> Self {
        Self {
            cpacr_el1: 0,
            ttbr0_el1: 0,
            tcr_el1: 0,
            mair_el1: 0,
            sctlr_el1: 0,
            vbar_el1: 0,
            spsr_el2: 0,
            elr_el2: 0,
            sp_el1: 0,
        }
    }
}

pub fn add_memory_save_list(list: *mut [MemorySaveListEntry]) {
    unsafe {
        (&raw mut MEMORY_SAVE_LIST)
            .as_mut()
            .unwrap()
            .write(&mut *list)
    };
}

pub fn create_memory_trap_for_save_memory() {
    unsafe { ORIGINAL_VTTBR_EL2 = cpu::get_vttbr_el2() };
    let page_table = remake_stage2_page_table().expect("Failed to remake page table.");
    cpu::set_vttbr_el2(page_table as u64);
    let list = unsafe {
        (&raw const MEMORY_SAVE_LIST)
            .as_ref()
            .unwrap()
            .assume_init_read()
    };
    for e in list {
        if e.num_of_pages == 0 && e.memory_start == 0 {
            break;
        }
        if e.saved_address == MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG {
            /* OnDemand Save */
            add_memory_access_trap(
                e.memory_start,
                (e.num_of_pages as usize) << PAGE_SHIFT,
                true,
                false,
            )
            .expect("Failed to add memory trap");
        }
    }
}

#[inline(always)]
pub fn check_memory_access_for_memory_save_list(ec: u8, far_el2: u64) -> bool {
    if unsafe { ORIGINAL_VTTBR_EL2 != 0 } && ec == crate::EC_DATA_ABORT {
        add_memory_area_to_memory_save_list(far_el2);
        return true;
    }
    false
}

fn compress_memory_save_list(list: &mut [MemorySaveListEntry]) -> Option<usize> {
    for i in 0..list.len() {
        if (list[i].memory_start == 0 && list[i].num_of_pages == 0)
            || list[i].saved_address == MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG
        {
            return Some(i);
        }
        let start_address = list[i].memory_start;
        let next_address = start_address + ((list[i].num_of_pages as usize) << PAGE_SHIFT);

        for t in (i + 1)..list.len() {
            if (list[t].memory_start == 0 && list[t].num_of_pages == 0)
                || list[t].saved_address == MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG
            {
                return Some(t);
            }
            if (list[t].memory_start == next_address)
                || ((list[t].memory_start + ((list[t].num_of_pages as usize) << PAGE_SHIFT))
                    == start_address)
            {
                if list[i].memory_start > list[t].memory_start {
                    list[i].memory_start = list[t].memory_start;
                }
                list[i].num_of_pages += list[t].num_of_pages;
                return Some(t);
            }
        }
    }
    None
}

#[inline(never)]
fn add_memory_area_to_memory_save_list(far_el2: u64) {
    let fault_address =
        cpu::convert_virtual_address_to_intermediate_physical_address_el1_write(far_el2 as usize)
            .unwrap_or_else(|_| panic!("Failed to convert FAR_EL2({:#X})", far_el2))
            & PAGE_MASK;

    pr_debug!("Fault Address: {:#X}", fault_address);
    let mut available_entry: Option<*mut MemorySaveListEntry> = None;
    let list_ptr = &raw const MEMORY_SAVE_LIST;
    let mut is_registered = false;
    let mut should_clear_next = false;

    for e in unsafe { list_ptr.as_ref().unwrap().assume_init_read() } {
        if should_clear_next {
            *e = MemorySaveListEntry {
                memory_start: 0,
                saved_address: 0,
                num_of_pages: 0,
            };
            assert!(is_registered);
            break;
        }
        if e.num_of_pages == 0 && e.memory_start == 0 {
            let new_entry = MemorySaveListEntry {
                memory_start: fault_address,
                saved_address: 0,
                num_of_pages: 1,
            };
            if let Some(available_entry) = available_entry {
                unsafe { *available_entry = new_entry };
                is_registered = true;
                break;
            } else {
                *e = new_entry;
                is_registered = true;
                should_clear_next = true;
                continue;
            }
        }
        if e.saved_address == MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG {
            available_entry = Some(e);
        } else if e.memory_start == fault_address + PAGE_SIZE {
            e.memory_start = fault_address;
            e.num_of_pages += 1;
            is_registered = true;
            break;
        } else if e.memory_start + ((e.num_of_pages as usize) << PAGE_SHIFT) == fault_address {
            e.num_of_pages += 1;
            is_registered = true;
            break;
        }
    }
    if !is_registered {
        if let Some(i) =
            compress_memory_save_list(unsafe { list_ptr.as_ref().unwrap().assume_init_read() })
        {
            unsafe {
                list_ptr.as_ref().unwrap().assume_init_read()[i] = MemorySaveListEntry {
                    memory_start: fault_address,
                    saved_address: 0,
                    num_of_pages: 1,
                }
            };
        } else {
            panic!("There is no available entry");
        }
    }
    remove_memory_access_trap(fault_address, PAGE_SIZE).expect("Failed to remove memory trap");
}

fn save_memory(list: &mut [MemorySaveListEntry]) {
    for e in list {
        if e.num_of_pages == 0 && e.memory_start == 0 {
            break;
        }
        if e.saved_address != usize::MAX {
            let allocated_memory =
                allocate_memory(e.num_of_pages as usize, None).expect("Failed to allocate memory");
            unsafe {
                copy_nonoverlapping(
                    e.memory_start as *const u8,
                    allocated_memory as *mut u8,
                    (e.num_of_pages << PAGE_SHIFT) as usize,
                )
            };
            e.saved_address = allocated_memory;
        }
    }
}

fn restore_memory(list: &[MemorySaveListEntry]) {
    for e in list {
        if e.num_of_pages == 0 && e.memory_start == 0 {
            break;
        }
        if e.saved_address != MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG {
            pr_debug!("Restore {:#X} from {:#X}", e.memory_start, e.saved_address);
            //if cpu::convert_virtual_address_to_physical_address_el2_write(e.memory_start).is_err() {
            map_address(
                e.memory_start,
                e.memory_start,
                (e.num_of_pages << PAGE_SHIFT) as usize,
                true,
                true,
                false,
                false,
            )
            .expect("Failed to map memory");
            //}
            unsafe {
                copy_nonoverlapping(
                    e.saved_address as *const u8,
                    e.memory_start as *mut u8,
                    (e.num_of_pages << PAGE_SHIFT) as usize,
                )
            };
        }
    }
}

static mut ORIGINAL_INSTRUCTION: u32 = 0;

pub fn save_original_instruction_and_insert_hvc(address: usize, hvc_number: u16) {
    if cpu::convert_virtual_address_to_physical_address_el2_write(address & PAGE_MASK).is_err() {
        map_address(
            address & PAGE_MASK,
            address & PAGE_MASK,
            PAGE_SIZE,
            true,
            true,
            false,
            false,
        )
        .expect("Failed to map memory");
    }
    let hvc_instruction = (0b11010100000 << 21) | ((hvc_number as u32) << 5) | 0b00010;
    unsafe {
        ORIGINAL_INSTRUCTION = *(address as *const u32);
        *(address as *mut u32) = hvc_instruction;
    }
    cpu::flush_tlb_el1();
    cpu::clear_instruction_cache_all();
}

pub fn add_trap_to_exit_boot_service(address: usize) {
    assert_ne!(address, 0);
    save_original_instruction_and_insert_hvc(address, HVC_EXIT_BOOT_SERVICE_TRAP);
}

pub fn exit_boot_service_trap_main(regs: &mut GeneralPurposeRegisters, elr: u64) {
    if unsafe { ORIGINAL_INSTRUCTION } == 0 {
        return;
    }
    assert_ne!(elr, 0);
    let hvc_address = elr as usize - cpu::AA64_INSTRUCTION_SIZE;
    unsafe { *(hvc_address as *mut u32) = ORIGINAL_INSTRUCTION };
    cpu::set_elr_el2(hvc_address as u64);
    save_original_instruction_and_insert_hvc(regs[30] as usize, HVC_AFTER_EXIT_BOOT_SERVICE_TRAP);
}

pub fn after_exit_boot_service_trap_main(regs: &mut GeneralPurposeRegisters, elr: u64) {
    if unsafe { ORIGINAL_INSTRUCTION } == 0 {
        return;
    }
    assert_ne!(elr, 0);
    let hvc_address = elr as usize - cpu::AA64_INSTRUCTION_SIZE;
    unsafe {
        *(hvc_address as *mut u32) = ORIGINAL_INSTRUCTION;
        ORIGINAL_INSTRUCTION = 0;
    }
    cpu::set_elr_el2(hvc_address as u64);
    cpu::flush_tlb_el1();
    cpu::clear_instruction_cache_all();
    pr_debug!("ExitBootServiceStatus: {:#X}", regs[0]);
    if regs[0] != 0 {
        panic!("ExitBootService is failed(TODO: reset trap point and continue...)");
    }

    /* Save current status */
    save_memory(unsafe {
        (&raw mut MEMORY_SAVE_LIST)
            .as_ref()
            .unwrap()
            .assume_init_read()
    });
    /* Store registers */
    let r = SavedSystemRegisters {
        cpacr_el1: cpu::get_cpacr_el1(),
        ttbr0_el1: cpu::get_ttbr0_el1(),
        tcr_el1: cpu::get_tcr_el1(),
        mair_el1: cpu::get_mair_el1(),
        sctlr_el1: cpu::get_sctlr_el1(),
        vbar_el1: cpu::get_vbar_el1(),
        spsr_el2: cpu::get_spsr_el2(),
        elr_el2: cpu::get_elr_el2(),
        sp_el1: cpu::get_sp_el1(),
    };
    unsafe { *(&raw mut SAVED_SYSTEM_REGISTERS).as_mut().unwrap() = r };
    unsafe { *(&raw mut SAVED_REGISTERS).as_mut().unwrap() = *regs };
    cpu::set_vttbr_el2(unsafe { ORIGINAL_VTTBR_EL2 }); /* TODO: free old page table */
    unsafe { ORIGINAL_VTTBR_EL2 = 0 };
    pr_debug!("Remove page table for memory save");
}

/// If you disable all entries of Stage2 Page Table,
/// don't call [`add_memory_access_trap`] and [`remove_memory_access_trap`]
/// until you re-enable the entries.
fn modify_all_enable_bit_of_stage2_top_level_entries(is_enabled: bool) {
    let stage_2_page_table = paging::TTBR::new(cpu::get_vttbr_el2()).get_base_address();
    let vtcr_el2 = cpu::get_vtcr_el2();
    let vtcr_el2_sl0 = ((vtcr_el2 & cpu::VTCR_EL2_SL0) >> cpu::VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & cpu::VTCR_EL2_T0SZ) >> cpu::VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };
    let num_of_pages =
        paging::calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level);

    let table = unsafe {
        core::slice::from_raw_parts_mut(
            stage_2_page_table as *mut u64,
            (paging::PAGE_TABLE_SIZE / size_of::<u64>()) * num_of_pages as usize,
        )
    };
    if is_enabled {
        for e in table {
            *e |= 1;
        }
    } else {
        for e in table {
            *e &= !1;
        }
    }
}

/// This function will be called when the guest OS requested power off or reboot
pub fn enter_restore_process() -> ! {
    pr_debug!("Fast Restore is requested.");
    cpu::local_irq_fiq_save();
    IS_RESTORE_NEEDED.store(true, Ordering::SeqCst);

    modify_all_enable_bit_of_stage2_top_level_entries(false);
    /*
        After this point, we must not modify stage2 page table
        including add_memory_access_trap/remove_memory_access_trap
    */

    cpu::clean_data_cache_all();
    cpu::flush_tlb_el1();
    cpu::clear_instruction_cache_all();

    /* wake all CPUs up from WFI/WFE */
    gic::broadcast_sgi();
    cpu::send_event_all();

    restore_main()
}

#[inline(always)]
pub fn perform_restore_if_needed() {
    if IS_RESTORE_NEEDED.load(Ordering::Relaxed) {
        restore_main();
    }
}

#[inline(never)]
fn restore_main() -> ! {
    cpu::local_irq_fiq_save();
    if unsafe { BSP_MPIDR } != cpu::get_mpidr_el1() {
        pr_debug!(
            "This CPU(MPIDR: {:#X}) is not BSP, currently perform CPU_OFF(TODO: use AP to copy memory)",
            cpu::get_mpidr_el1()
        );
        let result = multi_core::power_off_cpu();
        panic!(
            "Failed to call CPU_OFF: {:#X?}",
            psci::PsciReturnCode::try_from(result)
        );
    }
    println!("BSP entered the restore process.");
    println!("Wait until all APs are powered off...");
    cpu::dsb();
    cpu::isb();
    while multi_core::NUMBER_OF_RUNNING_AP.load(Ordering::Relaxed) != 0 {
        core::hint::spin_loop();
    }
    println!("All APs are powered off.");

    modify_all_enable_bit_of_stage2_top_level_entries(true);
    /* Now, we can call add_memory_access_trap/remove_memory_access_trap */
    gic::remove_sgi();

    /* Free last one AP's stack if needed */
    let old_stack = multi_core::STACK_TO_FREE_LATER.load(Ordering::Relaxed);
    if old_stack != 0 {
        if let Err(err) = free_memory(old_stack, STACK_PAGES) {
            println!("Failed to free stack: {:?}", err);
        }
        multi_core::STACK_TO_FREE_LATER.store(0, Ordering::Relaxed);
    }

    /* Restore GIC */
    if let Some(acpi_rsdp) = unsafe { crate::ACPI_RSDP } {
        gic::restore_gic(acpi_rsdp.get());
    }

    #[cfg(feature = "smmu")]
    smmu::restore_smmu_status();

    /* Restore saved registers */
    let saved_registers = unsafe {
        (&raw const SAVED_SYSTEM_REGISTERS)
            .as_ref()
            .unwrap()
            .clone()
    };
    cpu::set_cpacr_el1(saved_registers.cpacr_el1);
    cpu::set_ttbr0_el1(saved_registers.ttbr0_el1);
    cpu::set_tcr_el1(saved_registers.tcr_el1);
    cpu::set_mair_el1(saved_registers.mair_el1);
    cpu::set_sctlr_el1(saved_registers.sctlr_el1);
    cpu::set_vbar_el1(saved_registers.vbar_el1);
    cpu::set_spsr_el2(saved_registers.spsr_el2);
    cpu::set_elr_el2(saved_registers.elr_el2);
    cpu::set_sp_el1(saved_registers.sp_el1);
    cpu::set_cntp_ctl_el0(0);

    /* Restore memory */
    pr_debug!("Restore the memory");
    restore_memory(unsafe {
        (&raw const MEMORY_SAVE_LIST)
            .as_ref()
            .unwrap()
            .assume_init_read()
    });

    cpu::flush_tlb_el1();
    cpu::clear_instruction_cache_all();
    pr_debug!("ERET");
    IS_RESTORE_NEEDED.store(false, Ordering::SeqCst);
    unsafe {
        core::arch::asm!("
            ldp x30, xzr, [x0, #( 15 * 16)]
            ldp x28, x29, [x0, #( 14 * 16)]
            ldp x26, x27, [x0, #( 13 * 16)]
            ldp x24, x25, [x0, #( 12 * 16)]
            ldp x22, x23, [x0, #( 11 * 16)]
            ldp x20, x21, [x0, #( 10 * 16)]
            ldp x18, x19, [x0, #(  9 * 16)]
            ldp x16, x17, [x0, #(  8 * 16)]
            ldp x14, x15, [x0, #(  7 * 16)]
            ldp x12, x13, [x0, #(  6 * 16)]
            ldp x10, x11, [x0, #(  5 * 16)]
            ldp  x8,  x9, [x0, #(  4 * 16)]
            ldp  x6,  x7, [x0, #(  3 * 16)]
            ldp  x4,  x5, [x0, #(  2 * 16)]
            ldp  x2,  x3, [x0, #(  1 * 16)]
            ldp  x0,  x1, [x0, #(  0 * 16)]
            eret", in("x0") (&raw const SAVED_REGISTERS) as usize, options(noreturn))
    }
}
