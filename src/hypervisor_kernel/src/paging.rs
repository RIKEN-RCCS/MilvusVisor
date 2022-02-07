// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Paging
//!

use super::allocate_memory;

use common::cpu::{
    flush_tlb_el2, flush_tlb_vmalls12e1, get_tcr_el2, get_ttbr0_el2, get_vtcr_el2, get_vttbr_el2,
    set_tcr_el2, TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_T0SZ_WITHOUT_E2H, VTCR_EL2_SL0,
    VTCR_EL2_SL0_BITS_OFFSET, VTCR_EL2_T0SZ, VTCR_EL2_T0SZ_BITS_OFFSET,
};
use common::paging::{
    calculate_number_of_concatenated_page_tables, create_attributes_for_stage_1,
    create_attributes_for_stage_2, extract_output_address,
    get_initial_page_table_level_and_bits_to_shift,
    get_suitable_memory_attribute_index_from_mair_el2, is_block_descriptor,
    is_descriptor_table_or_level_3_descriptor, table_level_to_table_shift,
    MEMORY_PERMISSION_EXECUTABLE_BIT, MEMORY_PERMISSION_READABLE_BIT,
    MEMORY_PERMISSION_WRITABLE_BIT, PAGE_DESCRIPTORS_CONTIGUOUS, PAGE_DESCRIPTORS_NT,
    PAGE_TABLE_SIZE, TTBR,
};
use common::{PAGE_SHIFT, PAGE_SIZE, STAGE_2_PAGE_SHIFT, STAGE_2_PAGE_SIZE};

/// Map physical Address Recursively
///
/// permission: Bit0:Readable, Bit1: Writable, Bit2: Executable
fn map_address_recursive(
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    permission: u8,
    memory_attribute: u8, /* MemAttr */
    t0sz: u8,
) -> Result<(), ()> {
    let shift_level = table_level_to_table_shift(PAGE_SHIFT, table_level);
    let mut table_index = (*virtual_address >> shift_level) & 0x1FF;

    if table_level == 3 {
        let current_table = unsafe {
            &mut *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
        };
        let num_of_pages = if *num_of_remaining_pages + table_index > 512 {
            512 - table_index
        } else {
            *num_of_remaining_pages
        };
        let attributes = create_attributes_for_stage_1(permission, memory_attribute, false);

        for index in table_index..(table_index + num_of_pages) {
            current_table[index] = *physical_address as u64 | attributes;
            *physical_address += PAGE_SIZE;
            *virtual_address += PAGE_SIZE;
        }
        *num_of_remaining_pages -= num_of_pages;
        return Ok(());
    }
    let current_table = unsafe {
        &mut *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };

    while *num_of_remaining_pages != 0 {
        pr_debug!(
            "{:#X}: Level{}'s Table Index: {:#X}",
            *virtual_address,
            table_level,
            table_index
        );
        if table_index >= 512 {
            break;
        }
        let target_descriptor = &mut current_table[table_index];

        if table_level > 1
            && (*physical_address & ((1usize << shift_level) - 1)) == 0
            && (*virtual_address & ((1usize << shift_level) - 1)) == 0
            && *num_of_remaining_pages >= 512usize.pow((3 - table_level) as u32)
        {
            pr_debug!(
                "Creating BlockEntry: VA: {:#X}, PA: {:#X}, TableLevel: {}",
                *virtual_address,
                *physical_address,
                table_level
            );
            if is_descriptor_table_or_level_3_descriptor(*target_descriptor) {
                pr_debug!(
                    "PageTable:({:#X}) will be deleted.",
                    extract_output_address(*target_descriptor, PAGE_SHIFT)
                );
                /* TODO: free page table */
            }
            let attributes = create_attributes_for_stage_1(permission, memory_attribute, true);
            *target_descriptor = *physical_address as u64 | attributes;
            *physical_address += 1 << shift_level;
            *virtual_address += 1 << shift_level;
            *num_of_remaining_pages -= 512usize.pow((3 - table_level) as u32);
        } else {
            let mut created_entry: Option<u64> = None;

            if !is_descriptor_table_or_level_3_descriptor(*target_descriptor) {
                let allocated_table_address =
                    allocate_page_table_for_stage_1(table_level, t0sz, false)?;

                if is_block_descriptor(*target_descriptor) {
                    pr_debug!(
                        "Convert the block descriptor({:#b}) to table descriptor",
                        *target_descriptor
                    );

                    let mut block_physical_address =
                        extract_output_address(*target_descriptor, PAGE_SHIFT);
                    let mut descriptor_attribute =
                        *target_descriptor ^ (block_physical_address as u64);
                    let next_level_page = unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    };

                    if table_level + 1 == 3 {
                        descriptor_attribute |= 0b11;
                        descriptor_attribute &= !PAGE_DESCRIPTORS_NT;
                    }

                    for e in next_level_page {
                        *e = (block_physical_address as u64) | descriptor_attribute;
                        block_physical_address += 1 << (shift_level - 9);
                    }
                } else {
                    /* set_mem */
                    for e in unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    } {
                        *e = 0;
                    }
                }

                /* TODO: 52bit OA support */
                created_entry = Some(allocated_table_address as u64 | 0b11);
                pr_debug!("Allocated: {:#X}", allocated_table_address);
            }
            map_address_recursive(
                physical_address,
                virtual_address,
                num_of_remaining_pages,
                extract_output_address(created_entry.unwrap_or(*target_descriptor), PAGE_SHIFT),
                table_level + 1,
                permission,
                memory_attribute,
                t0sz,
            )?;

            if let Some(new_descriptor) = created_entry {
                *target_descriptor = new_descriptor;
            }
        }
        table_index += 1;
    }
    return Ok(());
}

pub fn map_address(
    mut physical_address: usize,
    mut virtual_address: usize,
    size: usize,
    readable: bool,
    writable: bool,
    executable: bool,
    is_device: bool,
) -> Result<(), ()> {
    if (physical_address & ((1usize << PAGE_SHIFT) - 1)) != 0 {
        println!("Physical Address is not aligned.");
        return Err(());
    }
    let aligned_size = if (size & ((1usize << PAGE_SHIFT) - 1)) != 0 {
        (size & ((1usize << PAGE_SHIFT) - 1)) + PAGE_SIZE
    } else {
        size
    };
    let mut num_of_needed_pages = aligned_size >> PAGE_SHIFT;
    let tcr_el2 = get_tcr_el2();

    let mut tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as u32;

    let (table_level, _) = get_initial_page_table_level_and_bits_to_shift(tcr_el2);
    pr_debug!("Initial Page Table Level: {}", table_level);
    let min_t0sz = (virtual_address + size).leading_zeros();
    if min_t0sz < tcr_el2_t0sz {
        pr_debug!(
            "TCR_EL2::T0SZ will be changed to {} from {}, this may cause panic.",
            min_t0sz,
            tcr_el2_t0sz
        );
        let new_tcr_el2 = (tcr_el2 ^ tcr_el2_t0sz as u64) | min_t0sz as u64;
        let (new_table_level, _) = get_initial_page_table_level_and_bits_to_shift(new_tcr_el2);
        if new_table_level != table_level {
            panic!(
                "Paging Table Level is to be changed. {} => {}",
                table_level, new_table_level
            );
            /* TODO: adjust process */
        } else {
            set_tcr_el2(new_tcr_el2);
            tcr_el2_t0sz = min_t0sz;
        }
    }

    map_address_recursive(
        &mut physical_address,
        &mut virtual_address,
        &mut num_of_needed_pages,
        TTBR::new(get_ttbr0_el2()).get_base_address(),
        table_level,
        (readable as u8) << MEMORY_PERMISSION_READABLE_BIT
            | (writable as u8) << MEMORY_PERMISSION_WRITABLE_BIT
            | (executable as u8) << MEMORY_PERMISSION_EXECUTABLE_BIT,
        get_suitable_memory_attribute_index_from_mair_el2(is_device),
        tcr_el2_t0sz as u8,
    )?;

    if num_of_needed_pages != 0 {
        println!(
            "Failed to map address(remaining_pages:{} != 0",
            num_of_needed_pages
        );
        return Err(());
    }
    flush_tlb_el2();
    pr_debug!(
        "Mapped {:#X} Bytes({} Pages)",
        aligned_size,
        aligned_size >> PAGE_SHIFT
    );
    return Ok(());
}

/// Map physical Address Recursively into Stage2 translation table
///
/// permission: Bit0:Readable, Bit1: Writable, Bit2: Executable
fn map_address_recursive_stage2(
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    is_unmap: bool,
    permission: u8,
    concatenated_tables: u8,
    t0sz: u8,
    is_dummy_page: bool,
) -> Result<(), ()> {
    let shift_level = table_level_to_table_shift(STAGE_2_PAGE_SHIFT, table_level);
    let mut table_index =
        (*virtual_address >> shift_level) & (0x200 * (concatenated_tables as usize) - 1);

    if table_level == 3 {
        let table_len =
            (PAGE_TABLE_SIZE * (concatenated_tables as usize)) / core::mem::size_of::<u64>();

        let current_table =
            unsafe { core::slice::from_raw_parts_mut(table_address as *mut u64, table_len) };

        let num_of_pages = if *num_of_remaining_pages + table_index > table_len {
            table_len - table_index
        } else {
            *num_of_remaining_pages
        };
        if STAGE_2_PAGE_SIZE == 0x1000 {
            let contiguous_first_entry = &mut current_table[table_index & !0xF];
            *contiguous_first_entry &= !PAGE_DESCRIPTORS_CONTIGUOUS;
        }
        let attributes = create_attributes_for_stage_2(permission, is_dummy_page, is_unmap, false);
        let end_index = table_index + num_of_pages;
        for index in table_index..end_index {
            if STAGE_2_PAGE_SIZE == 0x1000
                && (index & 0xF) == 0
                && !is_dummy_page
                && (end_index - index) >= 16
            {
                println!(
                    "Enable CONTIGUOUS_BIT(index: {:#X}, end_index: {:#X}",
                    index, end_index
                );
                current_table[index] =
                    *physical_address as u64 | attributes | PAGE_DESCRIPTORS_CONTIGUOUS;
            } else {
                current_table[index] = *physical_address as u64 | attributes;
            }
            if !is_dummy_page {
                *physical_address += STAGE_2_PAGE_SIZE;
            }
            *virtual_address += STAGE_2_PAGE_SIZE;
        }
        *num_of_remaining_pages -= num_of_pages;
        return Ok(());
    }
    let current_table = unsafe {
        core::slice::from_raw_parts_mut(
            table_address as *mut u64,
            (PAGE_TABLE_SIZE * concatenated_tables as usize) / core::mem::size_of::<u64>(),
        )
    };

    while *num_of_remaining_pages != 0 {
        pr_debug!(
            "{:#X}: Level{}'s Table Index: {:#X}",
            *virtual_address,
            table_level,
            table_index
        );
        if table_index >= (512 * concatenated_tables as usize) {
            break;
        }
        let target_descriptor = &mut current_table[table_index];
        if !is_dummy_page
            && table_level > 1
            && (*physical_address & ((1usize << shift_level) - 1)) == 0
            && (*virtual_address & ((1usize << shift_level) - 1)) == 0
            && *num_of_remaining_pages >= 512usize.pow((3 - table_level) as u32)
        {
            pr_debug!(
                "Creating BlockEntry: VA: {:#X}, PA: {:#X}, TableLevel: {}(Stage 2)",
                *virtual_address,
                *physical_address,
                table_level
            );
            if is_descriptor_table_or_level_3_descriptor(*target_descriptor) {
                pr_debug!(
                    "PageTable:({:#X}) will be deleted.",
                    extract_output_address(*target_descriptor, STAGE_2_PAGE_SHIFT)
                );
                /* TODO: free page table */
            }
            let attributes =
                create_attributes_for_stage_2(permission, is_dummy_page, is_unmap, true);

            *target_descriptor = *physical_address as u64 | attributes;

            *physical_address += 1 << shift_level;
            *virtual_address += 1 << shift_level;
            *num_of_remaining_pages -= 512usize.pow((3 - table_level) as u32);
        } else {
            let mut created_entry: Option<u64> = None;

            if *target_descriptor & 0b11 != 0b11 {
                let allocated_table_address =
                    allocate_page_table_for_stage_2(table_level, t0sz, false, 1)?;

                if *target_descriptor & 0b11 == 0b01 {
                    pr_debug!(
                        "Convert the block descriptor({:#b}) to table descriptor",
                        *target_descriptor
                    );

                    let mut block_physical_address =
                        extract_output_address(*target_descriptor, STAGE_2_PAGE_SHIFT);
                    let mut descriptor_attribute =
                        *target_descriptor ^ (block_physical_address as u64);
                    let next_level_page = unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    };

                    if table_level + 1 == 3 {
                        descriptor_attribute |= 0b11;
                        descriptor_attribute &= !PAGE_DESCRIPTORS_NT; /* Clear nT Bit */
                    }

                    for e in next_level_page {
                        *e = (block_physical_address as u64) | descriptor_attribute;
                        block_physical_address += 1 << (shift_level - 9);
                    }
                } else {
                    /* set_mem */
                    for e in unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    } {
                        *e = 0;
                    }
                }

                /* TODO: 52bit OA support */
                created_entry = Some(allocated_table_address as u64 | 0b11);
                pr_debug!("Allocated: {:#X}", allocated_table_address);
            }
            map_address_recursive_stage2(
                physical_address,
                virtual_address,
                num_of_remaining_pages,
                extract_output_address(
                    created_entry.unwrap_or(*target_descriptor),
                    STAGE_2_PAGE_SHIFT,
                ),
                table_level + 1,
                is_unmap,
                permission,
                1,
                t0sz,
                is_dummy_page,
            )?;
            if let Some(d) = created_entry {
                *target_descriptor = d;
            }
        }
        table_index += 1;
    }
    flush_tlb_vmalls12e1();
    return Ok(());
}

#[allow(dead_code)]
pub fn map_dummy_page_into_vttbr_el2(
    mut virtual_address: usize,
    size: usize,
    mut dummy_page: usize, /*4 KiB Page Physical Address*/
) -> Result<(), ()> {
    if (size & ((1usize << STAGE_2_PAGE_SHIFT) - 1)) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
    let vtcr_el2 = get_vtcr_el2();
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };

    let original_dummy_page = dummy_page;
    map_address_recursive_stage2(
        &mut dummy_page,
        &mut virtual_address,
        &mut num_of_needed_pages,
        TTBR::new(get_vttbr_el2()).get_base_address(),
        initial_look_up_level,
        false,
        (1 << MEMORY_PERMISSION_READABLE_BIT)
            | (1 << MEMORY_PERMISSION_WRITABLE_BIT)
            | (1 << MEMORY_PERMISSION_EXECUTABLE_BIT),
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level),
        vtcr_el2_t0sz,
        true,
    )?;

    assert_eq!(num_of_needed_pages, 0);
    assert_eq!(original_dummy_page, dummy_page);
    return Ok(());
}

/// VTTBR_EL2の該当アドレス範囲をトラップできるようにする。
/// 現在はInitial Table Levelは0までのみの対応
pub fn add_memory_access_trap(
    mut address: usize,
    size: usize,
    allow_read_access: bool,
    allow_write_access: bool,
) -> Result<(), ()> {
    if (size & ((1usize << STAGE_2_PAGE_SHIFT) - 1)) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    if allow_write_access && allow_read_access {
        println!("Invalid access control.");
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
    let vtcr_el2 = get_vtcr_el2();
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };

    assert!(address < (1 << (64 - vtcr_el2_t0sz)));

    let mut physical_address = address;
    map_address_recursive_stage2(
        &mut physical_address,
        &mut address,
        &mut num_of_needed_pages,
        TTBR::new(get_vttbr_el2()).get_base_address(),
        initial_look_up_level,
        false,
        ((allow_read_access as u8) << MEMORY_PERMISSION_READABLE_BIT)
            | ((allow_write_access as u8) << MEMORY_PERMISSION_WRITABLE_BIT),
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level),
        vtcr_el2_t0sz,
        false,
    )?;
    assert_eq!(num_of_needed_pages, 0);
    assert_eq!(physical_address, address);
    pr_debug!("Unmapped {:#X} Bytes({} Pages)", size, size >> PAGE_SHIFT);
    return Ok(());
}

/// VTTBR_EL2の該当アドレス範囲をトラップできないようにする。
/// 現在はInitial Table Levelは0までのみの対応
pub fn remove_memory_access_trap(mut address: usize, size: usize) -> Result<(), ()> {
    if (size & ((1usize << STAGE_2_PAGE_SHIFT) - 1)) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
    let vtcr_el2 = get_vtcr_el2();
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };

    assert!(address < (1 << (64 - vtcr_el2_t0sz)));
    let mut physical_address = address;

    map_address_recursive_stage2(
        &mut physical_address,
        &mut address,
        &mut num_of_needed_pages,
        TTBR::new(get_vttbr_el2()).get_base_address(),
        initial_look_up_level,
        false,
        (1 << MEMORY_PERMISSION_READABLE_BIT)
            | (1 << MEMORY_PERMISSION_WRITABLE_BIT)
            | (1 << MEMORY_PERMISSION_EXECUTABLE_BIT),
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level),
        vtcr_el2_t0sz,
        false,
    )?;
    assert_eq!(num_of_needed_pages, 0);
    pr_debug!("Unmapped {:#X} Bytes({} Pages)", size, size >> PAGE_SHIFT);
    return Ok(());
}

/// Allocate page table for stage 1 with suitable address alignment
#[inline(always)]
fn allocate_page_table_for_stage_1(
    look_up_level: i8,
    t0sz: u8,
    is_for_ttbr: bool,
) -> Result<usize, ()> {
    let table_address_alignment = if is_for_ttbr {
        ((64 - ((PAGE_SHIFT - 3) as u8 * (4 - look_up_level) as u8) - t0sz).max(4)).min(12)
    } else {
        PAGE_SHIFT as u8
    };
    loop {
        match allocate_memory(1) {
            Ok(address) => {
                if (address & ((1 << table_address_alignment) - 1)) != 0 {
                    pr_debug!(
                        "The table address is not alignment with {}, {:#X} will be wasted.",
                        table_address_alignment,
                        address
                    );
                    /* TODO: アライメントを指定してメモリを確保できるようにし、無駄をなくす。 */
                } else {
                    return Ok(address);
                }
            }
            Err(e) => {
                println!("Failed to allocate memory for the paging table: {:?}", e);
                return Err(e);
            }
        };
    }
}

/// Allocate page table for stage 2 with suitable address alignment
#[inline(always)]
fn allocate_page_table_for_stage_2(
    look_up_level: i8,
    t0sz: u8,
    is_for_ttbr: bool,
    number_of_tables: u8,
) -> Result<usize, ()> {
    assert_ne!(number_of_tables, 0);
    let table_address_alignment = if is_for_ttbr {
        ((64 - ((PAGE_SHIFT - 3) as u8 * (4 - look_up_level) as u8) - t0sz).max(4)).min(12)
            + (number_of_tables - 1)
    } else {
        assert_eq!(number_of_tables, 1);
        STAGE_2_PAGE_SHIFT as u8
    };
    loop {
        match allocate_memory(number_of_tables as usize) {
            Ok(address) => {
                if (address & ((1 << table_address_alignment) - 1)) != 0 {
                    pr_debug!(
                        "The table address is not alignment with {}, {:#X} will be wasted.",
                        table_address_alignment,
                        address
                    );
                    /* TODO: アライメントを指定してメモリを確保できるようにし、無駄をなくす。 */
                    if number_of_tables != 1 {
                        let _ = allocate_memory(1);
                    }
                } else {
                    return Ok(address);
                }
            }
            Err(e) => {
                println!("Failed to allocate memory for the paging table: {:?}", e);
                return Err(());
            }
        };
    }
}
