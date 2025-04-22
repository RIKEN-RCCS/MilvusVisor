// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! System Memory Management Unit Initialization
//!
//! Supported SMMU: SMMUv3.0 ~ SMMUv3.3
//!

use crate::allocate_memory;
use crate::paging::map_address;

use common::cpu::{get_vtcr_el2, get_vttbr_el2};
use common::{PAGE_SHIFT, acpi, paging::page_align_up, smmu::*};

use core::ptr::{read_volatile, write_volatile};

/// Initialize SMMUv3 and setup Stage2 only STE
///
/// This function searches SMMUv3 base address from ACPI IORT and setup it.
///
/// # Setup Processes
/// 1. Map SMMUv3 Register Map(Size: [`SMMU_MEMORY_MAP_SIZE`])
/// 2. Check if SMMU supports Stage2 Paging and 2Level Stream Table
/// 3. Create STE from CPU's VTTBR_EL2 and VTCR_EL2
/// 4. Build a Level2 Stream Table by cloning the created STE(SPAN: STREAM_TABLE_SPLIT)
/// 5. Find max value of stream id by parsing IORT
/// 6. Build Level1 Stream Table based on max stream id and set same L2Ptr and Span to all entries
/// 7. Enable SMMU
///
/// # Arguments
/// * acpi_address: RSDP of ACPI 2.0 or later
///
/// # Result
/// If the initialization is succeeded, return Some(smmuv3_base_address), otherwise none
pub fn detect_smmu(acpi_address: usize) -> Option<usize> {
    let iort = match acpi::get_acpi_table(acpi_address, &acpi::iort::IORT::SIGNATURE) {
        Ok(address) => unsafe { &*(address as *const acpi::iort::IORT) },
        Err(acpi::AcpiError::TableNotFound) => {
            println!("IORT is not found.");
            return None;
        }
        Err(e) => {
            println!("Failed to parse ACPI table: {:?}", e);
            return None;
        }
    };
    let Some(smmu_v3) = iort.get_smmu_v3_information() else {
        println!("SMMUv3 is not found");
        return None;
    };
    let base_address = smmu_v3.get_base_address();
    println!("SMMUv3 BaseAddress: {:#X}", base_address);

    map_address(
        base_address,
        base_address,
        SMMU_MEMORY_MAP_SIZE,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map SMMU Memory Area");

    /* Check SMMU functions */
    let smmu_idr0 = unsafe { read_volatile((base_address + SMMU_IDR0) as *const u32) };
    let s2p = (smmu_idr0 & SMMU_IDR0_S2P) != 0;
    let is_supported_2level_stream_table = (smmu_idr0 & SMMU_IDR0_ST_LEVEL) != 0;
    println!(
        "SMMU_IDR0: {:#X}(2Level: {}, S2P: {})",
        smmu_idr0, is_supported_2level_stream_table, s2p
    );
    if ((smmu_idr0 & SMMU_IDR0_TTENDIAN) >> SMMU_IDR0_TTENDIAN_BITS_OFFSET) == 0b11 {
        println!("SMMU does not support Little Endian.");
        return None;
    } else if !s2p {
        println!("Stage 2 paging is not supported.");
        return None;
    } else if !is_supported_2level_stream_table {
        println!("2Level stream table is not supported.");
        return None;
    }
    let smmu_idr5 = unsafe { read_volatile((base_address + SMMU_IDR5) as *const u32) };
    if (smmu_idr5 & SMMU_IDR5_GRAN4K) == 0 {
        println!("4K Paging is not supported.");
        return None;
    }
    let smmu_cr0 = unsafe { read_volatile((base_address + SMMU_CR0) as *const u32) };
    if (smmu_cr0 & SMMU_CR0_SMMUEN) != 0 {
        println!("SMMU is already enabled.");
        return None;
    }

    let mut smmu_cr1 = unsafe { read_volatile((base_address + SMMU_CR1) as *const u32) };
    smmu_cr1 |= (0b11) << SMMU_CR1_TABLE_SH_BITS_OFFSET;
    unsafe { write_volatile((base_address + SMMU_CR1) as *mut u32, smmu_cr1) };

    /* Create STE */
    let mut ste = StreamTableEntry::new();
    ste.set_stage2_settings(get_vtcr_el2(), get_vttbr_el2(), true, true);
    ste.validate();

    /* Create Stream Table (Level2)*/
    const STREAM_TABLE_SPLIT: u32 = 6;

    let level2_table_address = allocate_memory(
        page_align_up((1 << STREAM_TABLE_SPLIT) * size_of::<StreamTableEntry>()) >> PAGE_SHIFT,
        None,
    )
    .expect("Failed to allocate memory for Level2 Stream Table");
    let level2_table =
        unsafe { &mut *(level2_table_address as *mut [StreamTableEntry; 1 << STREAM_TABLE_SPLIT]) };
    for e in level2_table {
        *e = ste;
    }

    /* Find max_stream_id */
    let mut max_stream_id = 0;
    for e in smmu_v3.get_array_of_id_mappings() {
        if e.is_single_map() {
            println!("Single Map StreamID: {:#X}", e.get_output_base());
            if e.get_output_base() > max_stream_id {
                max_stream_id = e.get_output_base();
            }
        } else {
            let array_max_stream_id = e.get_output_base() + e.get_number_of_ids() - 1;
            println!(
                "StreamID: {:#X}~{:#X}",
                e.get_output_base(),
                array_max_stream_id
            );
            if array_max_stream_id > max_stream_id {
                max_stream_id = array_max_stream_id;
            }
        }
    }

    /* Create Stream Table (Level1)*/
    let number_of_level1_context_descriptors = (max_stream_id + 1) >> STREAM_TABLE_SPLIT;
    let level1_table_address = allocate_memory(
        page_align_up(number_of_level1_context_descriptors * size_of::<u64>()) >> PAGE_SHIFT,
        None,
    )
    .expect("Failed to allocate memory for Level1 Stream Table");

    for e in unsafe {
        core::slice::from_raw_parts_mut(
            level1_table_address as *mut u64,
            number_of_level1_context_descriptors,
        )
    } {
        *e = level2_table_address as u64 | (STREAM_TABLE_SPLIT as u64 - 1);
    }

    let log2_size: u32 = (max_stream_id + 1).ilog2();

    println!(
        "Level1 Table Entries: {:#X}, Max Stream Id: {:#X}, LOG2SIZE: {log2_size}",
        number_of_level1_context_descriptors, max_stream_id
    );

    unsafe {
        write_volatile(
            (base_address + SMMU_STRTAB_BASE_CFG) as *mut u32,
            SMMU_STRTAB_BASE_CFG_FMT_2LEVEL
                | (STREAM_TABLE_SPLIT << SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET)
                | log2_size,
        )
    };
    unsafe {
        write_volatile(
            (base_address + SMMU_STRTAB_BASE) as *mut u64,
            (level1_table_address as u64) & SMMU_STRTAB_BASE_ADDRESS,
        )
    };

    /* Enable SMMU */
    unsafe { write_volatile((base_address + SMMU_CR0) as *mut u32, SMMU_CR0_SMMUEN) };

    while unsafe { read_volatile((base_address + SMMU_CR0ACK) as *const u32) & SMMU_CR0_SMMUEN }
        == 0
    {
        core::hint::spin_loop();
    }

    unsafe {
        write_volatile(
            (base_address + SMMU_GBPA) as *mut u32,
            SMMU_GBPA_UPDATE | SMMU_GBPA_SHCFG_INCOMING,
        )
    };
    Some(base_address)
}
