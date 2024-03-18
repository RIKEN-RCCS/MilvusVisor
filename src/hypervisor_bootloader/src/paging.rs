// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Paging
//!

use crate::{allocate_memory, free_memory};

use common::cpu::*;
use common::paging::*;
use common::{
    PAGE_MASK, PAGE_SHIFT, PAGE_SIZE, STAGE_2_PAGE_MASK, STAGE_2_PAGE_SHIFT, STAGE_2_PAGE_SIZE,
};

fn _clone_page_table(table_address: usize, current_level: i8) -> usize {
    let cloned_table_address = allocate_memory(1, None).expect("Failed to allocate page table");

    let cloned_table = unsafe {
        &mut *(cloned_table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };
    unsafe {
        *cloned_table =
            *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };
    if current_level == 3 {
        return cloned_table_address;
    }
    for e in cloned_table {
        if is_descriptor_table_or_level_3_descriptor(*e) {
            let next_level_table_address = extract_output_address(*e, PAGE_SHIFT);
            *e = ((*e) & !(next_level_table_address as u64))
                | (_clone_page_table(next_level_table_address, current_level + 1) as u64);
        }
    }
    return cloned_table_address;
}

/// Clone TTBR0_EL2
///
/// Clone the page table tree of TTBR0_EL2。
///
/// # Panics
/// If memory allocation is failed, this function panics
///
/// # Result
/// Returns Cloned Page Table Address
pub fn clone_page_table() -> usize {
    let page_table_address = TTBR::new(get_ttbr0_el2()).get_base_address();
    let tcr_el2 = get_tcr_el2();
    let first_table_level = get_initial_page_table_level_and_bits_to_shift(tcr_el2).0;
    return _clone_page_table(page_table_address, first_table_level);
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
    if (physical_address & !PAGE_MASK) != 0 {
        println!("Physical Address is not aligned.");
        return Err(());
    }
    let aligned_size = if (size & !PAGE_MASK) != 0 {
        (size & !PAGE_MASK) + PAGE_SIZE
    } else {
        size
    };
    let mut num_of_needed_pages = aligned_size >> PAGE_SHIFT;
    let tcr_el2 = get_tcr_el2();

    let mut tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as u32;

    #[allow(unused_variables)]
    let (table_level, shift_level) = get_initial_page_table_level_and_bits_to_shift(tcr_el2);
    pr_debug!("Initial Page Table Level: {table_level}, Initial Shift Bits: {shift_level}",);
    let min_t0sz = (virtual_address + size).leading_zeros();
    if min_t0sz < tcr_el2_t0sz {
        println!(
            "TCR_EL2::T0SZ will be changed to {} from {}, this may cause panic.",
            min_t0sz, tcr_el2_t0sz
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

/// Map address ~ (address + size) to dummy page
///
/// This function sets `address` ~ (`address` + `size) to un-accessible from EL1/EL0
///
/// # Arguments
/// * `address` - The address to hide from EL1/EL0
/// * `size` - The size to hide
/// * `dummy_page` - [`common::PAGE_SIZE`] memory area to convert the access from EL1/EL0
///
/// # Result
/// If mapping is succeeded, returns Ok(()), otherwise returns Err(())
pub fn map_dummy_page_into_vttbr_el2(
    mut address: usize,
    size: usize,
    mut dummy_page: usize, /*4 KiB Page Physical Address*/
) -> Result<(), ()> {
    if (size & !STAGE_2_PAGE_MASK) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
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

    let original_dummy_page = dummy_page;
    map_address_recursive_stage2(
        &mut dummy_page,
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
        true,
    )?;

    assert_eq!(num_of_needed_pages, 0);
    assert_eq!(original_dummy_page, dummy_page);
    return Ok(());
}

fn setup_stage_2_translation_recursive(
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
            setup_stage_2_translation_recursive(
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

pub fn setup_stage_2_translation() -> Result<(), ()> {
    let pa_range = get_id_aa64mmfr0_el1() & ID_AA64MMFR0_EL1_PARANGE;
    let ps = pa_range;
    let (t0sz, first_level) = match ps {
        0b000 => (32u8, 1i8),
        0b001 => (28u8, 1i8),
        0b010 => (24u8, 1i8),
        0b011 => (22u8, 0i8),
        0b100 => (20u8, 0i8),
        0b101 => (16u8, 0i8),
        0b110 => (12u8, -1i8),
        _ => {
            println!("unsupported PARange: {:#X}", pa_range);
            return Err(());
        }
    };
    let (sl0, sl2) = match first_level {
        1 => (0b01u8, 0b0u8),
        0 => (0b10u8, 0b0u8),
        -1 => (0b00u8, 0b1u8),
        _ => unreachable!(),
    };

    if sl2 != 0 {
        println!("VTCR_EL2::DS must be 1(TODO: support 52Bit OA)");
        return Err(());
    }

    let number_of_tables = calculate_number_of_concatenated_page_tables(t0sz, first_level) as usize;
    pr_debug!(
        "PARange: {:#b}, FirstLevel: {}, ConcatenatedTables: {}",
        pa_range,
        first_level,
        number_of_tables
    );

    let mut physical_address = 0;
    let table_address =
        allocate_page_table_for_stage_2(first_level, t0sz, true, number_of_tables as u8)?;

    setup_stage_2_translation_recursive(
        table_address,
        &mut physical_address,
        first_level,
        number_of_tables,
        t0sz,
    )?;

    /* Setup VTCR_EL2 */
    /* D13.2.148 VTCR_EL2, Virtualization Translation Control Register */
    let vtcr_el2: u64 = ((sl2 as u64)<< VTCR_EL2_SL2_BIT_OFFSET) |
        VTCR_EL2_RES1 |
        (0b1111 << VTCR_EL2_HWU_BITS_OFFSET)  |
        ((ps as u64) << VTCR_EL2_PS_BITS_OFFSET) |
        (0 << VTCR_EL2_TG0_BITS_OFFSET) /* 4KiB */ |
        (0b11 <<VTCR_EL2_SH0_BITS_OFFSET) /* Inner Sharable */ |
        (0b01 <<VTCR_EL2_ORG0_BITS_OFFSET) /* Outer Write-Back Read-Allocate Write-Allocate Cacheable */ |
        (0b01 << VTCR_EL2_IRG0_BITS_OFFSET) /* Inner Write-Back Read-Allocate Write-Allocate Cacheable */ |
        ((sl0 as u64) << VTCR_EL2_SL0_BITS_OFFSET) |
        ((t0sz as u64) << VTCR_EL2_T0SZ_BITS_OFFSET);

    set_vtcr_el2(vtcr_el2);
    set_vttbr_el2(table_address as u64);

    return Ok(());
}

pub fn dump_page_table_recursive(
    table_address: usize,
    virtual_base_address: &mut usize,
    level: u8,
    space_count: u8,
    granule: usize,
) {
    let print_indent = |c: u8| {
        for _ in 0..c {
            print!(" ");
        }
    };
    let mut processing_descriptor_address = table_address;

    if level == 1 {
        for _ in 0..512 {
            let level3_descriptor = unsafe { *(processing_descriptor_address as *const u64) };
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
            *virtual_base_address += granule;
            processing_descriptor_address += core::mem::size_of::<u64>();
        }
    } else {
        for _ in 0..512 {
            let descriptor = unsafe { *(processing_descriptor_address as *const u64) };
            print_indent(space_count);
            if (descriptor & 0b1) == 0 {
                println!(
                    "{:#X} ~ {:#X}: Invalid",
                    virtual_base_address,
                    *virtual_base_address + granule
                );
                *virtual_base_address += granule;
            } else if (descriptor & 0b10) == 0 {
                // Block Descriptor
                println!(
                    "{:#X} ~ {:#X}: Block: {:#b} (OA: {:#X}, MemAttr: {})",
                    virtual_base_address,
                    *virtual_base_address + granule,
                    descriptor,
                    extract_output_address(descriptor, PAGE_SHIFT),
                    (descriptor >> 2) & 0b111
                );
                *virtual_base_address += granule;
            } else {
                let next_level_table = extract_output_address(descriptor, PAGE_SHIFT);
                println!(
                    "{:#X} ~ {:#X}: Table: {:#b} (OA: {:#X})",
                    virtual_base_address,
                    *virtual_base_address + granule,
                    descriptor,
                    extract_output_address(descriptor, PAGE_SHIFT)
                );
                dump_page_table_recursive(
                    next_level_table,
                    virtual_base_address,
                    level - 1,
                    space_count + 2,
                    granule >> 9,
                );
            }
            processing_descriptor_address += core::mem::size_of::<u64>();
        }
    }
}

#[allow(dead_code)]
pub fn dump_page_table() {
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

    if page_shift == 16 {
        println!("64KiB Paging is not supported.");
        return;
    }

    /*
    let level_0_granule: usize = if page_shift == 12 {
        if tcr_el2_ds != 0 {
            512 << 30
        } else {
            1 << 30
        }
    } else if page_shift == 14 {
        if tcr_el2_ds != 0 {
            64 << 30
        } else {
            32 << 20
        }
    } else {
        unreachable!()
    };
    */

    let paging_level = 4 - get_initial_page_table_level_and_bits_to_shift(tcr_el2).0;
    println!("Lookup: {} Level", paging_level);
    let mut base_address: usize = 1 << page_shift;
    let mut current_level = 3i8;
    println!(
        "  {} KiB: Level {} Descriptor",
        base_address >> 10,
        current_level
    );
    for _ in 0..(paging_level - 1) {
        base_address <<= 9; /*512Entry*/
        current_level -= 1;
        if (base_address >> 10) < 1024 {
            print!("  {} KiB", base_address >> 10)
        } else if (base_address >> 20) < 1024 {
            print!("  {} MiB", base_address >> 20);
        } else {
            print!("  {} GiB", base_address >> 30);
        }
        println!(": Level {} Descriptor", current_level);
    }

    let mair_el2 = get_mair_el2();

    println!(
        "MAIR: {:#X}(Using MemAttr: {})",
        mair_el2,
        get_suitable_memory_attribute_index_from_mair_el2(false)
    );

    let page_table_address = TTBR::new(get_ttbr0_el2()).get_base_address();

    println!("PageTable: {:#X}", page_table_address);

    dump_page_table_recursive(
        page_table_address,
        &mut 0,
        paging_level as u8,
        0,
        base_address,
    );
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
