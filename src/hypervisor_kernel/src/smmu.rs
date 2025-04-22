// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! System Memory Management Unit
//!

use common::cpu::{dsb, get_vtcr_el2, get_vttbr_el2};
use common::paging::{page_align_up, stage2_page_align_up};
use common::smmu::*;
use common::{GeneralPurposeRegisters, STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE, bitmask};

use crate::emulation;
use crate::memory_hook::*;
use crate::paging::{add_memory_access_trap, map_address, remove_memory_access_trap};

#[inline(always)]
fn read_smmu_register<T>(base: usize, offset: usize) -> T {
    assert!(offset < SMMU_MEMORY_MAP_SIZE);
    dsb();
    unsafe { core::ptr::read_volatile((base + offset) as *const T) }
}

#[inline(always)]
fn write_smmu_register<T>(base: usize, offset: usize, data: T) {
    assert!(offset < SMMU_MEMORY_MAP_SIZE);
    unsafe { core::ptr::write_volatile((base + offset) as *mut T, data) }
    dsb();
}

/// # ATTENTION
/// If you add the member of SmmuSavedRegisters,
/// please modify [`backup_default_smmu_settings`] and [`restore_smmu_status`]
struct SmmuSavedRegisters {
    cr0: u32,
    cr1: u32,
    cr2: u32,
    gbpa: u32,
    agbpa: u32,
    irq_ctrl: u32,
    gerrorn: u32,
    strtab_base: u64,
    strtab_base_cfg: u32,
    gatos_ctrl: u32,
}

impl SmmuSavedRegisters {
    const fn new() -> Self {
        Self {
            cr0: 0,
            cr1: 0,
            cr2: 0,
            gbpa: 0,
            agbpa: 0,
            irq_ctrl: 0,
            gerrorn: 0,
            strtab_base: 0,
            strtab_base_cfg: 0,
            gatos_ctrl: 0,
        }
    }
}

static mut DEFAULT_SMMU_STATUS: SmmuSavedRegisters = SmmuSavedRegisters::new();
static mut CURRENT_SMMU_STATUS: SmmuSavedRegisters = SmmuSavedRegisters::new();
#[cfg(feature = "fast_restore")]
static mut SMMU_BASE_ADDRESS: usize = 0;

/// Set up SMMU registers, and mapping of it.
///
/// This function sets up to trap the access of SMMU registers from EL1/EL0
/// EL1 will recognize that the SMMU is supported only Stage1 translation.
///
/// # Panics
/// If adding memory access handler is failed, this function panics.
///
/// # Arguments
/// * `smmu_registers_base_address` - The base address of SMMU registers([`SMMU_MEMORY_MAP_SIZE`] must be mapped and accessible)
/// * `iort_address` - The address of IORT(Optional)
pub fn init_smmu(smmu_base_address: usize, _iort_address: Option<usize>) {
    #[cfg(feature = "fast_restore")]
    unsafe {
        SMMU_BASE_ADDRESS = smmu_base_address
    };

    backup_default_smmu_settings(smmu_base_address);

    add_memory_access_trap(smmu_base_address, SMMU_MEMORY_MAP_SIZE, false, false)
        .expect("Failed to trap the memory access to SMMU");

    add_memory_load_access_handler(LoadAccessHandlerEntry::new(
        smmu_base_address,
        SMMU_MEMORY_MAP_SIZE,
        0,
        smmu_registers_load_handler,
    ))
    .expect("Failed to add the load handler");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        smmu_base_address,
        SMMU_MEMORY_MAP_SIZE,
        0,
        smmu_registers_store_handler,
    ))
    .expect("Failed to add the store handler");
}

fn backup_default_smmu_settings(base_address: usize) {
    let default_smmu_settings = SmmuSavedRegisters {
        cr0: read_smmu_register(base_address, SMMU_CR0),
        cr1: read_smmu_register(base_address, SMMU_CR1),
        cr2: read_smmu_register(base_address, SMMU_CR2),
        gbpa: read_smmu_register(base_address, SMMU_GBPA),
        agbpa: read_smmu_register(base_address, SMMU_AGBPA),
        irq_ctrl: read_smmu_register(base_address, SMMU_IRQ_CTRL),
        gerrorn: read_smmu_register(base_address, SMMU_GERRORN),
        strtab_base: read_smmu_register(base_address, SMMU_STRTAB_BASE),
        strtab_base_cfg: read_smmu_register(base_address, SMMU_STRTAB_BASE_CFG),
        gatos_ctrl: read_smmu_register(base_address, SMMU_GATOS_CTRL),
    };

    unsafe { DEFAULT_SMMU_STATUS = default_smmu_settings };
}

fn smmu_registers_load_handler(
    accessing_memory_address: usize,
    _: &mut GeneralPurposeRegisters,
    _: u8,
    _: bool,
    _: bool,
    entry: &LoadAccessHandlerEntry,
) -> LoadHookResult {
    let base_address = entry.get_target_address();
    let register_offset = accessing_memory_address - base_address;
    pr_debug!("SMMU Load Access Handler: Offset: {:#X}", register_offset);
    match register_offset {
        SMMU_IDR0 => LoadHookResult::Data(
            (read_smmu_register::<u32>(base_address, SMMU_IDR0)
                & (!(SMMU_IDR0_S2P
                    | SMMU_IDR0_HYP
                    | SMMU_IDR0_CD2L
                    | SMMU_IDR0_VMID16
                    | SMMU_IDR0_VATOS))) as u64,
        ),
        SMMU_IDR2 => LoadHookResult::Data(0),
        SMMU_CR0 | SMMU_CR0ACK => LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.cr0 } as u64),
        SMMU_CR1 => LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.cr1 } as u64),
        SMMU_CR2 => LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.cr2 } as u64),
        SMMU_STRTAB_BASE => LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.strtab_base }),
        SMMU_STRTAB_BASE_HIGH => {
            LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.strtab_base } >> 32)
        }
        SMMU_STRTAB_BASE_CFG => {
            LoadHookResult::Data(unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg } as u64)
        }
        _ => LoadHookResult::PassThrough,
    }
}

fn smmu_registers_store_handler(
    accessing_memory_address: usize,
    _regs: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
    entry: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    let base_address = entry.get_target_address();
    let register_offset = accessing_memory_address - base_address;
    pr_debug!(
        "SMMU Store Access Handler: Offset: {:#X}, Data: {:#X}",
        register_offset,
        data
    );
    if access_size != 0b10
        && (register_offset != SMMU_STRTAB_BASE
            && register_offset != SMMU_GERROR_IRQ_CFG0
            && register_offset != SMMU_CMDQ_BASE
            && register_offset != SMMU_EVENTQ_BASE
            && register_offset != SMMU_EVENTQ_IRQ_CFG0
            && register_offset != SMMU_PRIQ_BASE
            && register_offset != SMMU_PRIQ_IRQ_CFG0
            && register_offset != SMMU_GATOS_SID
            && register_offset != SMMU_GATOS_ADDR
            && register_offset != SMMU_GATOS_PAR
            && !(SMMU_CMDQ_CONTROL_PAGE_BASE..=SMMU_CMDQ_CONTROL_PAGE_BASE_END)
                .contains(&register_offset)/*&& &&register_offset != (vatos_offset + SMMU_VATOS_SID)
        && register_offset != (vatos_offset + SMMU_VATOS_ADDR)
        && register_offset != (vatos_offset + SMMU_VATOS_PAR)*/)
    {
        println!("Invalid Access size: {:#X}", access_size);
        return StoreHookResult::Cancel;
    }

    match register_offset {
        SMMU_CR0 => {
            let old_smmu_en = (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) != 0;
            let new_smmu_en = ((data as u32) & SMMU_CR0_SMMUEN) != 0;
            pr_debug!(
                "SMMU_CR0: {:#X}(SMMUEN: {} => {})",
                data,
                old_smmu_en,
                new_smmu_en
            );
            if old_smmu_en == new_smmu_en {
                unsafe { CURRENT_SMMU_STATUS.cr0 = data as u32 };
                if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_EVENTQEN) == 0
                    && ((data as u32) & SMMU_CR0_EVENTQEN) != 0
                {
                    let mask = SMMU_CR1_QUEUE_IC | SMMU_CR1_QUEUE_OC | SMMU_CR1_QUEUE_SH;
                    write_smmu_register(
                        base_address,
                        SMMU_CR1,
                        ((data as u32) & mask)
                            | (read_smmu_register::<u32>(base_address, SMMU_CR1) & !mask),
                    );
                }
                return StoreHookResult::Data(data | (SMMU_CR0_SMMUEN as u64));
            }
            if !new_smmu_en {
                /*Check SMMU_GBPA Status*/
                while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
                    core::hint::spin_loop();
                }
                if (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_ABORT) != 0 {
                    /* Disable SMMUEN */
                    disable_smmu(base_address, old_smmu_en, true);
                    unsafe { CURRENT_SMMU_STATUS.cr0 = data as u32 };
                    return StoreHookResult::PassThrough;
                }
                set_default_smmu_settings(base_address, old_smmu_en, true, Some(data as u32));
            } else {
                apply_current_smmu_settings(base_address, Some(data as u32));
            }
            /* Set CR0 (SMMU_CR0ACK will return the new value) */
            unsafe { CURRENT_SMMU_STATUS.cr0 = data as u32 };
            StoreHookResult::Cancel
        }
        SMMU_GBPA => {
            let data = data as u32;
            if (data & SMMU_GBPA_UPDATE) != 0 {
                if (data & SMMU_GBPA_ABORT) == 0
                    && ((read_smmu_register::<u32>(base_address, SMMU_CR0) & SMMU_CR0_SMMUEN) == 0)
                {
                    /* When Abort will be disabled and SMMUEN is disabled, all translations will be bypassed.
                    To avoid it, we must set default smmu settings */
                    set_default_smmu_settings(base_address, false, false, None);
                } else if (data & SMMU_GBPA_ABORT) != 0
                    && ((read_smmu_register::<u32>(base_address, SMMU_CR0) & SMMU_CR0_SMMUEN) != 0)
                {
                    /*
                      When Abort will be enabled and SMMUEN is enabled, all translations will not be bypassed.
                      To avoid it, we must disable smmu.
                    */

                    /* To avoid bypass translation while disabling smmu, write abort at first. */
                    write_smmu_register(
                        base_address,
                        SMMU_GBPA,
                        SMMU_GBPA_UPDATE | SMMU_GBPA_ABORT,
                    );
                    while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE)
                        != 0
                    {
                        core::hint::spin_loop();
                    }
                    disable_smmu(base_address, false, false);
                }
            }
            StoreHookResult::PassThrough
        }
        SMMU_CR1 => {
            if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) == 0 {
                unsafe { CURRENT_SMMU_STATUS.cr1 = data as u32 }
            }
            StoreHookResult::Cancel
        }
        SMMU_CR2 => {
            if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) == 0 {
                unsafe { CURRENT_SMMU_STATUS.cr2 = (data as u32) & !SMMU_CR2_E2H }
            }
            StoreHookResult::Cancel
        }
        SMMU_STRTAB_BASE => {
            if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) == 0 {
                if access_size != 0b11 {
                    /* Store lower 32bit */
                    unsafe {
                        CURRENT_SMMU_STATUS.strtab_base =
                            (CURRENT_SMMU_STATUS.strtab_base & !(u32::MAX as u64)) | data
                    };
                } else {
                    unsafe { CURRENT_SMMU_STATUS.strtab_base = data };
                }
            }
            StoreHookResult::Cancel
        }
        SMMU_STRTAB_BASE_HIGH => {
            if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) == 0 {
                unsafe {
                    CURRENT_SMMU_STATUS.strtab_base =
                        (data << 32) | (CURRENT_SMMU_STATUS.strtab_base & u32::MAX as u64)
                }
            }
            StoreHookResult::Cancel
        }
        SMMU_STRTAB_BASE_CFG => {
            if (unsafe { CURRENT_SMMU_STATUS.cr0 } & SMMU_CR0_SMMUEN) == 0 {
                unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg = data as u32 }
            }
            StoreHookResult::Cancel
        }
        _ => StoreHookResult::PassThrough,
    }
}

fn remove_current_stream_table_traps() {
    assert_ne!(
        unsafe { CURRENT_SMMU_STATUS.strtab_base } & SMMU_STRTAB_BASE_ADDRESS,
        unsafe { DEFAULT_SMMU_STATUS.strtab_base } & SMMU_STRTAB_BASE_ADDRESS
    );

    let smmu_status = unsafe { &*core::ptr::addr_of!(CURRENT_SMMU_STATUS) };
    let split = (smmu_status.strtab_base_cfg & SMMU_STRTAB_BASE_CFG_SPLIT)
        >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET;
    let log2_size = (smmu_status.strtab_base_cfg & SMMU_STRTAB_BASE_CFG_LOG2SIZE)
        >> SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET;
    let table_base_address = (smmu_status.strtab_base & SMMU_STRTAB_BASE_ADDRESS) as usize;
    let split = if split != 6 && split != 8 && split != 10 {
        6
    } else {
        split
    };
    let level1_table_size = get_level1_table_size(log2_size, split);

    remove_memory_access_trap(table_base_address, stage2_page_align_up(level1_table_size))
        .expect("Failed to remove trap of SMMU table");
    remove_memory_store_access_handler(StoreAccessHandlerEntry::new(
        table_base_address,
        level1_table_size,
        0,
        level1_table_store_handler,
    ))
    .expect("Failed to remove store handler");

    for i in 0..(level1_table_size / size_of::<u64>()) {
        remove_trap_of_level1_entry(
            unsafe { *((table_base_address + (i * size_of::<u64>())) as *const u64) },
            split,
        );
    }
    /*unmap_address(table_base_address, page_align_up(level1_table_size))
    .expect("Failed to unmap address");*/
}

fn remove_trap_of_level1_entry(entry: u64, split: u32) {
    let span = entry & bitmask!(4, 0);
    if span == 0 || span > 12 {
        return;
    }

    let level2_table_address = (entry & bitmask!(51, 5 + (span as usize/* -1 + 1*/))) as usize;
    let level2_table_size = get_level2_table_size(span, split);
    remove_memory_access_trap(
        level2_table_address,
        stage2_page_align_up(level2_table_size),
    )
    .expect("Failed to remove trap of SMMU table");
    remove_memory_load_access_handler(LoadAccessHandlerEntry::new(
        level2_table_address,
        level2_table_size,
        0,
        level2_table_load_handler,
    ))
    .expect("Failed to remove load handler");
    remove_memory_store_access_handler(StoreAccessHandlerEntry::new(
        level2_table_address,
        level2_table_size,
        0,
        level2_table_store_handler,
    ))
    .expect("Failed to remove store handler");
    /*unmap_address(level2_table_address, page_align_up(level2_table_size))
    .expect("Failed to unmap address");*/
}

fn disable_smmu(
    base_address: usize,
    should_remove_current_trap: bool,
    should_apply_current_smmu_settings: bool,
) {
    if should_apply_current_smmu_settings {
        write_smmu_register(base_address, SMMU_CR1, unsafe { CURRENT_SMMU_STATUS.cr1 });
        write_smmu_register(base_address, SMMU_CR2, unsafe { CURRENT_SMMU_STATUS.cr2 });
    }
    write_smmu_register(
        base_address,
        SMMU_CR0,
        read_smmu_register::<u32>(base_address, SMMU_CR0) & !SMMU_CR0_SMMUEN,
    );

    while (read_smmu_register::<u32>(base_address, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) != 0 {
        core::hint::spin_loop();
    }

    if should_remove_current_trap {
        remove_current_stream_table_traps();
    }
}

fn set_default_smmu_settings(
    base_address: usize,
    should_remove_current_trap: bool,
    should_apply_current_smmu_settings: bool,
    new_smmu_cr0: Option<u32>,
) {
    /* To avoid bypass translation while disabling smmu, write abort at first. */
    while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }
    let default_gbpa: u32 = read_smmu_register(base_address, SMMU_GBPA);
    write_smmu_register(base_address, SMMU_GBPA, SMMU_GBPA_UPDATE | SMMU_GBPA_ABORT);
    while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }

    /* Disable SMMUEN */
    write_smmu_register(
        base_address,
        SMMU_CR0,
        read_smmu_register::<u32>(base_address, SMMU_CR0) & !SMMU_CR0_SMMUEN,
    );
    while (read_smmu_register::<u32>(base_address, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) != 0 {
        core::hint::spin_loop();
    }

    /* Set default value */
    write_smmu_register(base_address, SMMU_STRTAB_BASE_CFG, unsafe {
        DEFAULT_SMMU_STATUS.strtab_base_cfg
    });
    write_smmu_register(base_address, SMMU_STRTAB_BASE, unsafe {
        DEFAULT_SMMU_STATUS.strtab_base
    });

    if should_apply_current_smmu_settings {
        write_smmu_register(base_address, SMMU_CR1, unsafe { CURRENT_SMMU_STATUS.cr1 });
        write_smmu_register(base_address, SMMU_CR2, unsafe { CURRENT_SMMU_STATUS.cr2 });
        write_smmu_register(
            base_address,
            SMMU_CR0,
            new_smmu_cr0.unwrap_or(unsafe { CURRENT_SMMU_STATUS.cr0 }),
        );
    }

    /* Enable SMMUEN */
    write_smmu_register(
        base_address,
        SMMU_CR0,
        read_smmu_register::<u32>(base_address, SMMU_CR0) | SMMU_CR0_SMMUEN,
    );
    while (read_smmu_register::<u32>(base_address, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) == 0 {
        core::hint::spin_loop();
    }

    /* Restore GBPA */
    write_smmu_register(base_address, SMMU_GBPA, default_gbpa | SMMU_GBPA_UPDATE);

    if should_remove_current_trap {
        remove_current_stream_table_traps()
    }
}

fn apply_current_smmu_settings(base_address: usize, new_smmu_cr0: Option<u32>) {
    /* To avoid bypass translation while disabling smmu, write abort at first. */
    while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }
    let default_gbpa: u32 = read_smmu_register(base_address, SMMU_GBPA);
    write_smmu_register(base_address, SMMU_GBPA, SMMU_GBPA_UPDATE | SMMU_GBPA_ABORT);
    while (read_smmu_register::<u32>(base_address, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }

    /* Disable SMMUEN */
    write_smmu_register(
        base_address,
        SMMU_CR0,
        read_smmu_register::<u32>(base_address, SMMU_CR0) & !SMMU_CR0_SMMUEN,
    );
    while (read_smmu_register::<u32>(base_address, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) != 0 {
        core::hint::spin_loop();
    }

    /* Set default value */
    write_smmu_register(base_address, SMMU_STRTAB_BASE_CFG, unsafe {
        CURRENT_SMMU_STATUS.strtab_base_cfg
    });
    write_smmu_register(base_address, SMMU_STRTAB_BASE, unsafe {
        CURRENT_SMMU_STATUS.strtab_base
    });
    write_smmu_register(base_address, SMMU_CR1, unsafe { CURRENT_SMMU_STATUS.cr1 });
    write_smmu_register(base_address, SMMU_CR2, unsafe { CURRENT_SMMU_STATUS.cr2 });
    /* Analysis new settings */
    add_trap_of_current_stream_table();

    write_smmu_register(
        base_address,
        SMMU_CR0,
        new_smmu_cr0.unwrap_or(unsafe { CURRENT_SMMU_STATUS.cr0 }),
    );
    while (read_smmu_register::<u32>(base_address, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) == 0 {
        core::hint::spin_loop();
    }

    /* Restore GBPA */
    write_smmu_register(base_address, SMMU_GBPA, default_gbpa | SMMU_GBPA_UPDATE);
}

fn add_trap_of_current_stream_table() {
    let smmu_status = unsafe { &*core::ptr::addr_of!(CURRENT_SMMU_STATUS) };
    let fmt = (smmu_status.strtab_base_cfg & SMMU_STRTAB_BASE_CFG_FMT)
        >> SMMU_STRTAB_BASE_CFG_FMT_BITS_OFFSET;
    let split = (smmu_status.strtab_base_cfg & SMMU_STRTAB_BASE_CFG_SPLIT)
        >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET;
    let log2size = (smmu_status.strtab_base_cfg & SMMU_STRTAB_BASE_CFG_LOG2SIZE)
        >> SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET;
    let level1_table_address = (smmu_status.strtab_base & SMMU_STRTAB_BASE_ADDRESS) as usize;
    pr_debug!(
        "SMMU: {{BASE: {:#X}, CFG: {:#X}(FMT: {:#b}, SPLIT: {}, SIZE:2^{})}}",
        level1_table_address,
        smmu_status.strtab_base_cfg,
        fmt,
        split,
        log2size
    );

    if fmt != 0b01 {
        panic!("Only 2Level Stream Table is supported");
    }

    let split = if split != 6 && split != 8 && split != 10 {
        println!("SMMU Split is invalid, behave as 6");
        unsafe {
            CURRENT_SMMU_STATUS.strtab_base_cfg = (CURRENT_SMMU_STATUS.strtab_base_cfg
                & !SMMU_STRTAB_BASE_CFG_SPLIT)
                | (6 << SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET)
        };
        6
    } else {
        split
    };

    pr_debug!("L1STD[{}:{}] -> L2STD[{}:0]", log2size - 1, split, split);
    if split >= log2size {
        panic!("Unsupported Split and Log2Size");
    }

    let level1_table_size = get_level1_table_size(log2size, split);
    let aligned_level1_table_size = stage2_page_align_up(level1_table_size);

    assert_eq!(level1_table_address & !STAGE_2_PAGE_MASK, 0);
    map_address(
        level1_table_address,
        level1_table_address,
        page_align_up(level1_table_size),
        true,
        true,
        false,
        false,
    )
    .expect("Failed to map address");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        level1_table_address,
        level1_table_size,
        0,
        level1_table_store_handler,
    ))
    .expect("Failed to add store handler");
    add_memory_access_trap(level1_table_address, aligned_level1_table_size, true, false)
        .expect("Failed to map SMMU table");

    for i in 0..(level1_table_size / size_of::<u64>()) {
        process_level1_table_entry(
            unsafe { *((level1_table_address + (i * size_of::<u64>())) as *const u64) },
            (i << split) as u32,
            split,
        );
    }
}

fn process_level1_table_entry(entry: u64, base_id: u32, split: u32) {
    let span = entry & bitmask!(4, 0);
    if span == 0 || span > 12 {
        pr_debug!(
            "Level2 Table: {:#X}(Span: {}, Id: {:#X} ~ )",
            entry,
            span,
            base_id
        );
        return;
    }

    let span_mask = bitmask!(51, 5 + (span as usize/* -1 + 1*/));
    let table_address = (entry & span_mask) as usize;
    let table_size = get_level2_table_size(span, split);

    pr_debug!(
        "Level2 Table: {:#X}(Span: {}, Address: {:#X}, TableSize: {:#X}, Id: {:#X} ~ )",
        entry,
        span,
        table_address,
        table_size,
        base_id
    );

    map_address(
        table_address,
        table_address,
        page_align_up(table_size),
        true,
        true,
        false,
        false,
    )
    .expect("Failed to map address");
    add_memory_load_access_handler(LoadAccessHandlerEntry::new(
        table_address,
        table_size,
        0,
        level2_table_load_handler,
    ))
    .expect("Failed to add load handler");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        table_address,
        table_size,
        0,
        level2_table_store_handler,
    ))
    .expect("Failed to add store handler");
    add_memory_access_trap(
        table_address,
        stage2_page_align_up(table_size),
        false,
        false,
    )
    .expect("Failed to map SMMU table");

    for i in 0..(1u32 << (span - 1)) {
        process_level2_table_entry(
            table_address + ((i as usize) * size_of::<StreamTableEntry>()),
            base_id + i,
            true,
        );
    }
}

fn process_level2_table_entry(entry_base: usize, _id: u32, should_check_entry: bool) {
    let ste = unsafe { &mut *(entry_base as *mut StreamTableEntry) };
    if should_check_entry {
        if !ste.is_validated() {
            //pr_debug!("STE(id: {:#X}) is not validated", id);
            return;
        }
        if !ste.is_traffic_can_pass() {
            //pr_debug!("STE(id: {:#X}) is not configured yet, ignore", id);
            return;
        }
    }
    ste.set_stage2_settings(
        get_vtcr_el2(),
        get_vttbr_el2(),
        ste.is_traffic_can_pass(),
        ste.is_stage1_bypassed(),
    );
}

fn level1_table_store_handler(
    accessing_address: usize,
    _: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    assert_eq!(STAGE_2_PAGE_SIZE, 0x1000);
    if access_size != 0b11 {
        panic!("unsupported Access Size: {:#b}", access_size);
    }
    let id = (accessing_address
        - (unsafe { CURRENT_SMMU_STATUS.strtab_base } & SMMU_STRTAB_BASE_ADDRESS) as usize)
        >> 3;
    pr_debug!("Level1 table ID: {}", id);
    let smmu_split = (unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg } & SMMU_STRTAB_BASE_CFG_SPLIT)
        >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET;

    remove_trap_of_level1_entry(unsafe { *(accessing_address as *mut u64) }, smmu_split);
    process_level1_table_entry(data, (id << smmu_split) as u32, smmu_split);

    StoreHookResult::PassThrough
}

fn level2_table_load_handler(
    accessing_address: usize,
    _: &mut GeneralPurposeRegisters,
    access_size: u8,
    _: bool,
    _: bool,
    _: &LoadAccessHandlerEntry,
) -> LoadHookResult {
    let ste_base = accessing_address & !(size_of::<StreamTableEntry>() - 1);
    let ste_offset = accessing_address - ste_base;
    let read_mask = !create_bitmask_of_stage2_configurations(ste_offset);
    let original_data = emulation::read_memory(accessing_address, access_size);
    LoadHookResult::Data(original_data & read_mask)
}

fn level2_table_store_handler(
    accessing_address: usize,
    _: &mut GeneralPurposeRegisters,
    access_size: u8,
    data: u64,
    _: &StoreAccessHandlerEntry,
) -> StoreHookResult {
    let ste_base_address = accessing_address & !(size_of::<StreamTableEntry>() - 1);
    let ste_offset = accessing_address - ste_base_address;
    let ste_offset_per_ste_base_type = ste_offset / size_of::<SteArrayBaseType>();

    let stream_id = get_stream_id(
        accessing_address,
        (unsafe { CURRENT_SMMU_STATUS.strtab_base } & SMMU_STRTAB_BASE_ADDRESS) as usize,
        get_level1_table_size(
            (unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg } & SMMU_STRTAB_BASE_CFG_LOG2SIZE)
                >> SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET,
            (unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg } & SMMU_STRTAB_BASE_CFG_SPLIT)
                >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET,
        ),
        (unsafe { CURRENT_SMMU_STATUS.strtab_base_cfg } & SMMU_STRTAB_BASE_CFG_SPLIT)
            >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET,
    );
    assert_eq!(STE_V_INDEX, 0);
    assert_eq!(STE_CONFIG_INDEX, 0);
    if ste_offset_per_ste_base_type == 0 {
        process_level2_table_entry(ste_base_address, stream_id, false);
    }
    let data = if unsafe { &*(ste_base_address as *const StreamTableEntry) }.is_validated()
        || (ste_offset_per_ste_base_type == 0 && ((data as SteArrayBaseType & STE_V) != 0))
    {
        let mask = create_bitmask_of_stage2_configurations(ste_offset);
        let original_data = emulation::read_memory(accessing_address, access_size);
        (data & !mask) | (original_data & mask)
    } else {
        data
    };
    //dump_level2_table_entry(ste_base_address, stream_id);
    StoreHookResult::Data(data)
}

fn get_stream_id(
    accessing_address: usize,
    level1_table_base_address: usize,
    level1_table_size: usize,
    split: u32,
) -> u32 {
    let mut upper_id = 0;

    while level1_table_size > (upper_id << 3) {
        let entry = unsafe { *((level1_table_base_address + (upper_id << 3)) as *const u64) };
        let span = entry & bitmask!(4, 0);
        if span > 0 && span < 12 {
            let span_mask = bitmask!(51, 5 + (span as usize/* -1 + 1*/));
            if (accessing_address & span_mask) == (entry as usize & span_mask) {
                /* Found */
                return ((upper_id << split)
                    | ((accessing_address - (accessing_address & span_mask))
                        / size_of::<StreamTableEntry>())) as u32;
            }
        }
        upper_id += 1;
    }
    panic!("Not Found");
}

#[cfg(feature = "fast_restore")]
pub fn restore_smmu_status() {
    let status = unsafe { &*core::ptr::addr_of!(DEFAULT_SMMU_STATUS) };
    let base = unsafe { SMMU_BASE_ADDRESS };
    if base == 0 {
        return;
    }
    /* Restore GBPA */
    while (read_smmu_register::<u32>(base, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }
    write_smmu_register(base, SMMU_GBPA, status.gbpa | SMMU_GBPA_UPDATE);
    while (read_smmu_register::<u32>(base, SMMU_GBPA) & SMMU_GBPA_UPDATE) != 0 {
        core::hint::spin_loop();
    }

    write_smmu_register(base, SMMU_CR0, 0u32);
    while (read_smmu_register::<u32>(base, SMMU_CR0ACK) & SMMU_CR0_SMMUEN) != 0 {
        core::hint::spin_loop();
    }

    /* Restore SMMU settings */
    write_smmu_register(base, SMMU_CR1, status.cr1);
    write_smmu_register(base, SMMU_CR2, status.cr2);
    write_smmu_register(base, SMMU_AGBPA, status.agbpa);
    write_smmu_register(base, SMMU_IRQ_CTRL, status.irq_ctrl);
    write_smmu_register(base, SMMU_GERRORN, status.gerrorn);
    write_smmu_register(base, SMMU_STRTAB_BASE, status.strtab_base);
    write_smmu_register(base, SMMU_STRTAB_BASE_CFG, status.strtab_base_cfg);
    write_smmu_register(base, SMMU_GATOS_CTRL, status.gatos_ctrl);
    write_smmu_register(base, SMMU_GBPA, status.gbpa | SMMU_GBPA_UPDATE);
    write_smmu_register(base, SMMU_CR0, status.cr0);

    if unsafe { CURRENT_SMMU_STATUS.cr0 & SMMU_CR0_SMMUEN } != 0 {
        remove_current_stream_table_traps();
    }
    unsafe { CURRENT_SMMU_STATUS = SmmuSavedRegisters::new() };
}

#[allow(dead_code)]
pub fn dump_stream_table(smmu_base_address: usize) {
    let table_base_address = (read_smmu_register::<u64>(smmu_base_address, SMMU_STRTAB_BASE)
        & SMMU_STRTAB_BASE_ADDRESS) as usize;
    let strtab_base_cfg = read_smmu_register::<u32>(smmu_base_address, SMMU_STRTAB_BASE_CFG);
    let split =
        (strtab_base_cfg & SMMU_STRTAB_BASE_CFG_SPLIT) >> SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET;
    let log2size = (strtab_base_cfg & SMMU_STRTAB_BASE_CFG_LOG2SIZE)
        >> SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET;
    let level1_table_size = get_level1_table_size(log2size, split);
    for i in 0..(level1_table_size >> 3) {
        dump_level1_table_entry(
            unsafe { *((table_base_address + (i << 3)) as *const u64) },
            (i << split) as u32,
            split,
        );
    }
}

#[allow(dead_code)]
fn dump_level1_table_entry(entry: u64, base_id: u32, split: u32) {
    let span = entry & bitmask!(4, 0);
    if span == 0 || span > 12 {
        println!(
            "Level1(ID: {:#X} ~ ): {:#X}(Invalid, Span:{})",
            base_id, entry, span
        );
        return;
    }

    let span_mask = bitmask!(51, 5 + (span as usize/* -1 + 1*/));
    let table_address = (entry & span_mask) as usize;
    let table_size = get_level2_table_size(span, split);
    println!(
        "Level1(ID: {:#X} ~ ): {:#X}(Span: {}, L2Ptr: {:#X}, TableSize: {:#X})",
        base_id, entry, span, table_address, table_size
    );

    for i in 0..(1u32 << (span - 1)) {
        dump_level2_table_entry(
            table_address + ((i as usize) * size_of::<StreamTableEntry>()),
            base_id + i,
        );
    }
}

#[allow(dead_code)]
fn dump_level2_table_entry(entry_base: usize, id: u32) {
    println!("  STE(id: {:#X}):", id);
    for i in 0..(size_of::<StreamTableEntry>() / size_of::<u32>()) {
        println!("    {:#X}: {:#X}", i * size_of::<u32>(), unsafe {
            *((entry_base + i * size_of::<u32>()) as *const u32)
        });
    }
}
