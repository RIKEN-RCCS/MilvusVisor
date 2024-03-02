// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Paging
//!

use common::cpu::*;
use common::paging::*;
use common::{PAGE_SHIFT, PAGE_SIZE, STAGE_2_PAGE_SHIFT, STAGE_2_PAGE_SIZE};

use crate::{allocate_memory, free_memory};

fn _remake_stage2_page_table(
    table_address: usize,
    physical_address: &mut usize,
    table_level: i8,
    number_of_tables: usize,
    vtcr_el2_t0sz: u8,
) -> Result<(), ()> {
    let page_table = unsafe {
        core::slice::from_raw_parts_mut(
            table_address as *mut u64,
            (PAGE_TABLE_SIZE * number_of_tables) / core::mem::size_of::<u64>(),
        )
    };
    let shift_level = table_level_to_table_shift(STAGE_2_PAGE_SHIFT, table_level);
    if table_level >= 1 {
        for e in page_table {
            let attribute = create_attributes_for_stage_2(
                (1 << MEMORY_PERMISSION_EXECUTABLE_BIT)
                    | (1 << MEMORY_PERMISSION_WRITABLE_BIT)
                    | (1 << MEMORY_PERMISSION_READABLE_BIT),
                false,
                false,
                true,
            );
            *e = (*physical_address as u64) | attribute;
            *physical_address += 1 << shift_level;
        }
    } else {
        for e in page_table {
            let next_table_address =
                allocate_page_table_for_stage_2(table_level + 1, vtcr_el2_t0sz, false, 1)?;
            _remake_stage2_page_table(
                next_table_address,
                physical_address,
                table_level + 1,
                1,
                vtcr_el2_t0sz,
            )?;
            *e = (next_table_address as u64) | 0b11;
        }
    }
    return Ok(());
}

pub fn remake_stage2_page_table() -> Result<usize, ()> {
    let vtcr_el2 = get_vtcr_el2();
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_sl2 = ((vtcr_el2 & VTCR_EL2_SL2) >> VTCR_EL2_SL2_BIT_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match (vtcr_el2_sl0, vtcr_el2_sl2) {
        (0b01u8, 0b0u8) => 1,
        (0b10u8, 0b0u8) => 0,
        (0b00u8, 0b1u8) => -1,
        _ => unreachable!(),
    };
    let number_of_tables =
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level) as usize;

    let mut physical_address = 0;
    let table_address = allocate_page_table_for_stage_2(
        initial_look_up_level,
        vtcr_el2_t0sz,
        true,
        number_of_tables as u8,
    )?;

    _remake_stage2_page_table(
        table_address,
        &mut physical_address,
        initial_look_up_level,
        number_of_tables,
        vtcr_el2_t0sz,
    )?;

    return Ok(table_address);
}

/// Map physical address recursively
///
/// This will map memory area upto `num_of_remaining_pages`.
/// This will call itself recursively, and map address until `num_of_remaining_pages` == 0 or reached the end of table.
/// When all page is mapped successfully, `num_of_remaining_pages` has been 0.
///
/// # Arguments
/// * `physical_address` - The address to map
/// * `virtual_address` - The address to associate with `physical_address`
/// * `num_of_remaining_pages` - The number of page entries to be mapped, this value will be changed
/// * `table_address` - The table address to set up in this function
/// * `table_level` -  The tree level of `table_address`, the max value is 3
/// * `permission` - The attribute for memory, Bit0: is_readable, Bit1: is_writable, Bit2: is_executable
/// * `memory_attribute` - The index of MAIR_EL2 to apply the mapping area
/// * `t0sz` - The value of TCR_EL2::T0SZ
fn map_address_recursive(
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    permission: u8,
    memory_attribute: u8,
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
            "{:#X}: Level{table_level}'s Table Index: {:#X}",
            *virtual_address,
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

            let old_descriptor = core::mem::replace(
                target_descriptor,
                *physical_address as u64
                    | create_attributes_for_stage_1(permission, memory_attribute, true),
            );

            if is_descriptor_table_or_level_3_descriptor(old_descriptor) {
                let old_table = extract_output_address(old_descriptor, PAGE_SHIFT);
                pr_debug!("PageTable:({:#X}) will be deleted.", old_table);
                let _ = free_memory(old_table, 1);
            }

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
                    descriptor_attribute &= !PAGE_DESCRIPTORS_CONTIGUOUS; /* Currently, needless */

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
                flush_tlb_el2();
            }
        }
        table_index += 1;
    }
    return Ok(());
}

/// Map address
///
/// This will map virtual address into physical address
/// The virtual address is for EL2.
///
/// # Arguments
/// * `physical_address` - The address to map
/// * `virtual_address` - The address to associate with `physical_address`
/// * `size` - The map size
/// * `readable` - If true, the memory area will be readable
/// * `writable` - If true, the memory area will be writable
/// * `executable` - If true, the memory area will be executable
/// * `is_device` - If true, the cache control of the memory area will become for device memory
///
/// # Result
/// If mapping is succeeded, returns Ok(()), otherwise returns Err(())
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
        println!("Physical Address({:#X}) is not aligned.", physical_address);
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
    pr_debug!("Initial Page Table Level: {table_level}");
    let min_t0sz = (virtual_address + size).leading_zeros();
    if min_t0sz < tcr_el2_t0sz {
        pr_debug!("T0SZ will be changed to {min_t0sz} from {tcr_el2_t0sz}, this may cause panic.");
        let new_tcr_el2 = (tcr_el2 ^ tcr_el2_t0sz as u64) | min_t0sz as u64;
        let (new_table_level, _) = get_initial_page_table_level_and_bits_to_shift(new_tcr_el2);
        if new_table_level != table_level {
            panic!("Paging Table Level is to be changed. {table_level} => {new_table_level}");
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
        println!("Failed to map address(remaining_pages: {num_of_needed_pages} != 0");
        return Err(());
    }
    pr_debug!(
        "Mapped {:#X} Bytes({} Pages)",
        aligned_size,
        aligned_size >> PAGE_SHIFT
    );
    flush_tlb_el2();
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
                && (*physical_address & ((16 * STAGE_2_PAGE_SIZE) - 1)) == 0
                && cfg!(feature = "contiguous_bit")
            {
                pr_debug!("Enable CONTIGUOUS_BIT({:#X} ~ {:#X})", index, end_index);
                current_table[index] =
                    *physical_address as u64 | attributes | PAGE_DESCRIPTORS_CONTIGUOUS;
            } else {
                current_table[index] = *physical_address as u64 | attributes;
            }
            if !is_dummy_page {
                *physical_address += STAGE_2_PAGE_SIZE;
            }
            //flush_tlb_ipa_is(*virtual_address as u64);
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
            "{:#X}: Level{table_level}'s Table Index: {:#X}",
            *virtual_address,
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

            let old_descriptor = core::mem::replace(
                target_descriptor,
                *physical_address as u64
                    | create_attributes_for_stage_2(permission, is_dummy_page, is_unmap, true),
            );

            if is_descriptor_table_or_level_3_descriptor(old_descriptor) {
                let old_table = extract_output_address(old_descriptor, STAGE_2_PAGE_SHIFT);
                pr_debug!("PageTable:({:#X}) will be deleted.", old_table);
                let _ = free_memory(old_table, 1);
            }

            *physical_address += 1 << shift_level;
            /*for i in 0..(1 << (shift_level - STAGE_2_PAGE_SHIFT)) {
                flush_tlb_ipa_is((*virtual_address + (i << STAGE_2_PAGE_SHIFT)) as u64);
            }*/
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
                    descriptor_attribute &= !PAGE_DESCRIPTORS_CONTIGUOUS; /* Currently, needless */

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
    return Ok(());
}

/// Set up to trap memory access from EL1/EL0
///
/// This will modify the stage2 page table to trap the access of (`address` ~ (`address` + `size`))
/// from EL1/EL0.
///
/// This function should be called after calling [`crate::memory_hook::add_memory_load_hook_handler`]
/// and/or [`crate::memory_hook::add_memory_store_hook_handler`].
///
/// # Arguments
/// * `address` - The physical address to trap
/// * `size` - The trap size
/// * `allow_read_access` - If true, read access from EL1/EL0 will not be trapped
/// * `allow_write_access` - If true, write access from EL1/EL0 will not be trapped
///
/// # Attention
/// If call this function with (`allow_read_access` == true) && (`allow_write_access` == true),
/// it returns Err(()). If you want to remove the trap, call [`remove_memory_access_trap`]
///
/// # Result
/// If the setting is succeeded, returns Ok(()), otherwise returns Err(())
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
    flush_tlb_el1();
    return Ok(());
}

/// Remove the trap of memory access from EL1/EL0
///
/// This will modify the stage2 page table to remove the access trap of (`address` ~ (`address` + `size`))
/// from EL1/EL0.
///
/// This function should be called before calling [`crate::memory_hook::remove_memory_load_hook_handler`]
/// and/or [`crate::memory_hook::remove_memory_store_hook_handler`].
///
/// # Arguments
/// * `address` - The physical address to remove trapping
/// * `size` - The trap size
///
/// # Result
/// If the setting is succeeded, returns Ok(()), otherwise returns Err(())
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
    flush_tlb_el1();
    return Ok(());
}

/// Allocate page table for stage 1 with suitable address alignment
#[inline(always)]
fn allocate_page_table_for_stage_1(
    look_up_level: i8,
    t0sz: u8,
    is_for_ttbr: bool,
) -> Result<usize, ()> {
    let alignment = if is_for_ttbr {
        ((64 - ((PAGE_SHIFT - 3) * (4 - look_up_level) as usize) - t0sz as usize).max(4)).min(12)
    } else {
        PAGE_SHIFT
    };
    match allocate_memory(1, Some(alignment)) {
        Ok(address) => Ok(address),
        Err(err) => {
            println!("Failed to allocate the page table: {:?}", err);
            Err(())
        }
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
    let alignment = if is_for_ttbr {
        ((64 - ((PAGE_SHIFT - 3) as usize * (4 - look_up_level) as usize) - t0sz as usize).max(4))
            .min(12)
            + (number_of_tables as usize - 1)
    } else {
        assert_eq!(number_of_tables, 1);
        STAGE_2_PAGE_SHIFT
    };
    match allocate_memory(number_of_tables as usize, Some(alignment)) {
        Ok(address) => Ok(address),
        Err(err) => {
            println!("Failed to allocate the page table: {:?}", err);
            Err(())
        }
    }
}

#[allow(dead_code)]
pub fn dump_page_table_el2(
    start_address: Option<usize>,
    end_address: Option<usize>,
    should_dump_table_only: bool,
) {
    let tcr_el2 = get_tcr_el2();
    let tcr_el2_ds =
        ((tcr_el2 & TCR_EL2_DS_WITHOUT_E2H) >> TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H) as u8;
    let tcr_el2_tg0 =
        ((tcr_el2 & TCR_EL2_TG0_WITHOUT_E2H) >> TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H) as u8;
    let tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as u8;
    let tcr_el2_ps =
        ((tcr_el2 & TCR_EL2_PS_WITHOUT_E2H) >> TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H) as u8;
    let page_shift = 12 + (tcr_el2_tg0 << 1);
    let output_address_size = match tcr_el2_ps {
        0b000 => 32,
        0b001 => 36,
        0b010 => 40,
        0b011 => 42,
        0b100 => 44,
        0b101 => 48,
        0b110 => 52,
        _ => unreachable!(),
    };
    let paging_level = 4 - get_initial_page_table_level_and_bits_to_shift(tcr_el2).0;
    let mut base_address: usize = 1 << page_shift;
    let mut current_level = 3i8;
    let page_table_address = TTBR::new(get_ttbr0_el2()).get_base_address();

    if page_shift == 16 {
        println!("64KiB Paging is not supported.");
        return;
    }

    if !should_dump_table_only {
        println!(
            "TCR_EL2: {:#b}\n   DS: {}, TG0: {:#b}({} KiB), T0SZ: {}, PS: {:#b}({} bits)",
            tcr_el2,
            tcr_el2_ds,
            tcr_el2_tg0,
            (1 << page_shift) >> 10,
            tcr_el2_t0sz,
            tcr_el2_ps,
            output_address_size,
        );
        println!("PageTable: {:#X}", page_table_address);
        println!(
            "MAIR: {:#X}(Using MemAttr: {})",
            get_mair_el2(),
            get_suitable_memory_attribute_index_from_mair_el2(false)
        );
        println!("Lookup: {} Level", paging_level);
        println!(
            "  {} KiB: Level {} Descriptor",
            base_address >> 10,
            current_level
        );
    }
    for _ in 0..(paging_level - 1) {
        base_address <<= 9; /*512Entry*/
        current_level -= 1;
        if !should_dump_table_only {
            if (base_address >> 10) < 1024 {
                print!("  {} KiB", base_address >> 10)
            } else if (base_address >> 20) < 1024 {
                print!("  {} MiB", base_address >> 20);
            } else {
                print!("  {} GiB", base_address >> 30);
            }
            println!(": Level {} Descriptor", current_level);
        }
    }

    dump_page_table_recursive(
        page_table_address,
        start_address.unwrap_or(0),
        end_address.unwrap_or(usize::MAX),
        &mut 0,
        paging_level as u8,
        0,
        base_address,
        512,
    );
}

#[allow(dead_code)]
pub fn dump_page_table_stage2(
    start_address: Option<usize>,
    end_address: Option<usize>,
    should_dump_table_only: bool,
) {
    let vtcr_el2 = get_vtcr_el2();
    let vtcr_el2_ps = (vtcr_el2 & VTCR_EL2_PS) >> VTCR_EL2_PS_BITS_OFFSET;
    let vtcr_el2_tg0 = (vtcr_el2 & VTCR_EL2_TG0) >> VTCR_EL2_TG0_BITS_OFFSET;
    let vtcr_el2_sl0 = (vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET;
    let vtcr_el2_t0sz = (vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET;
    let page_shift = match vtcr_el2_tg0 {
        0b00 => 12,
        0b01 => 16,
        0b10 => 14,
        _ => unimplemented!(),
    };
    let paging_level = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 3,
        0b10 => 4,
        0b11 => 1,
        _ => unreachable!(),
    };
    let output_address_size = match vtcr_el2_ps {
        0b000 => 32,
        0b001 => 36,
        0b010 => 40,
        0b011 => 42,
        0b100 => 44,
        0b101 => 48,
        0b110 => 52,
        _ => unimplemented!(),
    };
    let number_of_concatenated_page_tables =
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz as u8, 3 - (paging_level - 1));
    let mut base_address: usize = 1 << page_shift;
    let mut current_level = 3i8;
    let page_table_address = TTBR::new(get_vttbr_el2()).get_base_address();

    if page_shift == 16 || page_shift == 14 {
        println!("16/64KiB Paging is not supported.");
        return;
    }

    if !should_dump_table_only {
        println!(
            "VTCR_EL2: {:#b}\n  TG0: {:#b}({} KiB), T0SZ: {}, PS: {:#b}({} bits)",
            vtcr_el2,
            vtcr_el2_tg0,
            (1 << page_shift) >> 10,
            vtcr_el2_t0sz,
            vtcr_el2_ps,
            output_address_size,
        );
        println!("PageTable: {:#X}", page_table_address);
        println!(
            "Lookup: {} Level(Number of concatenated pages: {})",
            paging_level, number_of_concatenated_page_tables
        );
        println!(
            "  {} KiB: Level {} Descriptor",
            base_address >> 10,
            current_level
        );
    }
    if !should_dump_table_only {
        for _ in 0..(paging_level - 1) {
            base_address <<= 9; /* 512Entry */
            current_level -= 1;
            if !should_dump_table_only {
                if (base_address >> 10) < 1024 {
                    print!("  {} KiB", base_address >> 10)
                } else if (base_address >> 20) < 1024 {
                    print!("  {} MiB", base_address >> 20);
                } else {
                    print!("  {} GiB", base_address >> 30);
                }
                println!(": Level {} Descriptor", current_level);
            }
        }
    }

    dump_page_table_recursive(
        page_table_address,
        start_address.unwrap_or(0),
        end_address.unwrap_or(usize::MAX),
        &mut 0,
        paging_level as u8,
        0,
        base_address,
        (number_of_concatenated_page_tables as usize) * 512,
    );
}

fn dump_page_table_recursive(
    table_address: usize,
    start_virtual_address: usize,
    end_virtual_address: usize,
    virtual_base_address: &mut usize,
    level: u8,
    space_count: u8,
    granule: usize,
    number_of_entries: usize,
) {
    let print_indent = |c: u8| {
        for _ in 0..c {
            print!(" ");
        }
    };
    let mut processing_descriptor_address = table_address;

    let should_print = |v_a: usize| -> bool {
        (start_virtual_address..=end_virtual_address).contains(&v_a)
            || (v_a..(v_a + granule)).contains(&start_virtual_address)
            || (v_a..(v_a + granule)).contains(&end_virtual_address)
    };

    if level == 1 {
        for _ in 0..number_of_entries {
            let level3_descriptor = unsafe { *(processing_descriptor_address as *const u64) };
            let should_print = should_print(*virtual_base_address);
            if should_print {
                print_indent(space_count);
                if (level3_descriptor & 0b1) == 0 {
                    println!(
                        "{:#X} ~ {:#X}: Invalid",
                        virtual_base_address,
                        *virtual_base_address + granule
                    );
                } else if (level3_descriptor & 0b10) == 0 {
                    println!(
                        "{:#X} ~ {:#X}: Reserved",
                        virtual_base_address,
                        *virtual_base_address + granule
                    );
                } else {
                    println!(
                        "{:#X} ~ {:#X}: {:#b}(OA: {:#X}, MemAttr: {})",
                        virtual_base_address,
                        *virtual_base_address + granule,
                        level3_descriptor,
                        extract_output_address(level3_descriptor, PAGE_SHIFT),
                        (level3_descriptor >> 2) & 0b111
                    );
                }
            }
            *virtual_base_address += granule;
            processing_descriptor_address += core::mem::size_of::<u64>();
        }
    } else {
        for _ in 0..number_of_entries {
            let descriptor = unsafe { *(processing_descriptor_address as *const u64) };
            let should_print = should_print(*virtual_base_address);
            if should_print {
                print_indent(space_count);
            }
            if (descriptor & 0b1) == 0 {
                if should_print {
                    println!(
                        "{:#X} ~ {:#X}: Invalid",
                        virtual_base_address,
                        *virtual_base_address + granule
                    );
                }
                *virtual_base_address += granule;
            } else if (descriptor & 0b10) == 0 {
                // Block Descriptor
                if should_print {
                    println!(
                        "{:#X} ~ {:#X}: Block: {:#b} (OA: {:#X}, MemAttr: {})",
                        virtual_base_address,
                        *virtual_base_address + granule,
                        descriptor,
                        extract_output_address(descriptor, PAGE_SHIFT),
                        (descriptor >> 2) & 0b111
                    );
                }
                *virtual_base_address += granule;
            } else {
                let next_level_table = extract_output_address(descriptor, PAGE_SHIFT);
                if should_print {
                    println!(
                        "{:#X} ~ {:#X}: Table: {:#b} (OA: {:#X})",
                        virtual_base_address,
                        *virtual_base_address + granule,
                        descriptor,
                        extract_output_address(descriptor, PAGE_SHIFT)
                    );
                }
                dump_page_table_recursive(
                    next_level_table,
                    start_virtual_address,
                    end_virtual_address,
                    virtual_base_address,
                    level - 1,
                    space_count + 2,
                    granule >> 9,
                    512,
                );
            }
            processing_descriptor_address += core::mem::size_of::<u64>();
        }
    }
}
