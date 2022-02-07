//!
//! Paging
//!

use super::allocate_memory;

use super::{
    TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H, TCR_EL2_DS_WITHOUT_E2H, TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H,
    TCR_EL2_TG0_WITHOUT_E2H,
};
use crate::{
    TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_PS_WITHOUT_E2H,
    TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_T0SZ_WITHOUT_E2H,
};
use common::{bitmask, PAGE_SHIFT, PAGE_SIZE, STAGE_2_PAGE_SHIFT, STAGE_2_PAGE_SIZE};
use uefi::boot_service::EfiBootServices;

const STAGE_2_PAGE_ENTRY_ATTRIBUTE: u64 =
    1 << 10 /* AF bit */|
    0b11 << 8 /* SH bits (Inner sharable) */|
    0b11 << 6 /* S2AP bit (Read/Write) */ |
    0b1111 << 2 /* MemAttr(Write-back) */;

const PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET: u64 = 50;
//const PAGE_DESCRIPTORS_CONTIGUOUS: u64 = 1 << 52;
const PAGE_DESCRIPTORS_NX_BIT_OFFSET: u64 = 54;

const PAGE_DESCRIPTORS_NT: u64 = 1 << 16;
const PAGE_DESCRIPTORS_AF_BIT_OFFSET: u64 = 10;
const PAGE_DESCRIPTORS_AF: u64 = 1 << PAGE_DESCRIPTORS_AF_BIT_OFFSET;
const PAGE_DESCRIPTORS_SH_BITS_OFFSET: u64 = 8;
const PAGE_DESCRIPTORS_SH_INNER_SHAREABLE: u64 = 0b11 << PAGE_DESCRIPTORS_SH_BITS_OFFSET;
const PAGE_DESCRIPTORS_AP_BITS_OFFSET: u64 = 6;

const MEMORY_PERMISSION_READABLE_BIT: u8 = 0;
const MEMORY_PERMISSION_WRITABLE_BIT: u8 = 1;
const MEMORY_PERMISSION_EXECUTABLE_BIT: u8 = 2;

const VTCR_EL2_RES1: u64 = 1 << 31;
const VTCR_EL2_HWU_BITS_OFFSET: u64 = 25;
const VTCR_EL2_PS_BITS_OFFSET: u64 = 16;
const VTCR_EL2_TG0_BITS_OFFSET: u64 = 14;
const VTCR_EL2_SH0_BITS_OFFSET: u64 = 12;
const VTCR_EL2_ORG0_BITS_OFFSET: u64 = 10;
const VTCR_EL2_IRG0_BITS_OFFSET: u64 = 8;
const VTCR_EL2_SL0_BITS_OFFSET: u64 = 6;
const VTCR_EL2_SL0: u64 = 0b11 << VTCR_EL2_SL0_BITS_OFFSET;
const VTCR_EL2_T0SZ_BITS_OFFSET: u64 = 0;
const VTCR_EL2_T0SZ: u64 = 0b111111 << VTCR_EL2_SL0_BITS_OFFSET;

#[derive(Copy, Clone)]
struct TTBR(u64); /* Translation Table Base Register */

impl TTBR {
    const ASID: u64 = (u16::MAX as u64) << 48;
    const CNP: u64 = 1 << 0;

    pub fn new(ttbr: u64) -> Self {
        Self(ttbr)
    }

    pub fn get_base_address(&self) -> usize {
        ((self.0) & !(Self::CNP | Self::ASID)) as usize
    }
}

const fn extract_output_address(descriptor: u64) -> usize {
    (descriptor
        & bitmask!(
            PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET - 1,
            PAGE_SHIFT as u64
        )) as usize
}

const fn is_descriptor_table_or_level_3_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b11
}
const fn is_block_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b01
}

pub fn set_ttbr0_el1(address: usize) {
    unsafe {
        asm!("
                msr ttbr0_el1, {:x}
        ", in(reg) address)
    };
}

pub fn set_ttbr0_el2(address: usize) -> usize {
    let mut old: usize;
    unsafe {
        asm!("
                mrs {:x}, ttbr0_el2
                msr ttbr0_el2, {:x}
                dsb ishst
                tlbi alle2
                dsb ish
                isb
        ", out(reg) old, in(reg) address)
    };
    return old;
}

fn _copy_page_table(b_s: *const EfiBootServices, table_address: usize, current_level: i8) -> usize {
    let cloned_table_address = allocate_memory(1).expect("Failed to allocate page table");
    unsafe { ((*b_s).copy_mem)(cloned_table_address, table_address, PAGE_SIZE) };
    let cloned_table = unsafe {
        &mut *(cloned_table_address as *mut [u64; PAGE_SIZE / core::mem::size_of::<u64>()])
    };
    if current_level == 3 {
        return cloned_table_address;
    }
    for e in cloned_table {
        if is_descriptor_table_or_level_3_descriptor(*e) {
            let next_level_table_address = extract_output_address(*e);
            *e = ((*e) & !(next_level_table_address as u64))
                | (_copy_page_table(b_s, next_level_table_address, current_level + 1) as u64);
        }
    }
    return cloned_table_address;
}

/// Copy TTBR0_EL2 for Hypervisor
///
/// ハイパーバイザー向けのページテーブルを複製する。
pub fn copy_page_table(b_s: *const EfiBootServices) -> usize /*cloned page table address */
{
    let mut page_table_address: usize;
    unsafe { asm!("mrs {:x}, ttbr0_el2",out(reg) page_table_address) };
    page_table_address = TTBR::new(page_table_address as u64).get_base_address();
    let tcr_el2: u64;
    unsafe { asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2) };
    let first_table_level = get_initial_page_table_level_and_bits_to_shift(tcr_el2).0;
    /* 4段階の場合は0番目のエントリーの次段階テーブルもコピーしておく */
    return _copy_page_table(b_s, page_table_address, first_table_level);
}

/// Map physical Address Recursively
///
/// permission: Bit0:Readable, Bit1: Writable, Bit2: Executable
fn map_address_recursive(
    b_s: *const EfiBootServices,
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    shift_level: usize,
    permission: u8,
    memory_attribute: u8, /* MemAttr */
    t0sz: u8,
) -> Result<(), ()> {
    if table_level == 3 {
        assert_eq!(shift_level, PAGE_SHIFT);
        let current_table =
            unsafe { &mut *(table_address as *mut [u64; PAGE_SIZE / core::mem::size_of::<u64>()]) };
        let table_index = (*virtual_address >> shift_level) & 0x1FF;
        let num_of_pages = if *num_of_remaining_pages + table_index > 512 {
            512 - table_index
        } else {
            *num_of_remaining_pages
        };
        let nx_bit: u64 = if (permission & (1 << MEMORY_PERMISSION_EXECUTABLE_BIT)) != 0 {
            0
        } else {
            1
        } << PAGE_DESCRIPTORS_NX_BIT_OFFSET;
        let access_permission: u64 = if (permission & (1 << MEMORY_PERMISSION_WRITABLE_BIT)) != 0 {
            0b00
        } else {
            0b10
        } << PAGE_DESCRIPTORS_AP_BITS_OFFSET;

        let attributes = nx_bit
            | PAGE_DESCRIPTORS_AF
            | PAGE_DESCRIPTORS_SH_INNER_SHAREABLE
            | nx_bit
            | access_permission
            | (memory_attribute << 2) as u64
            | 0b11;

        for index in table_index..(table_index + num_of_pages) {
            current_table[index] = *physical_address as u64 | attributes;
            *physical_address += PAGE_SIZE;
            *virtual_address += PAGE_SIZE;
        }
        *num_of_remaining_pages -= num_of_pages;
        return Ok(());
    }
    let current_table =
        unsafe { &mut *(table_address as *mut [u64; PAGE_SIZE / core::mem::size_of::<u64>()]) };
    let mut table_index = (*virtual_address >> shift_level) & 0x1FF;

    while *num_of_remaining_pages != 0 {
        println!(
            "{:#X}: Level{}'s Table Index: {:#X}",
            *virtual_address, table_level, table_index
        );
        if table_index >= 512 {
            break;
        }
        let target_descriptor = &mut current_table[table_index];
        if !is_descriptor_table_or_level_3_descriptor(*target_descriptor) {
            let allocated_table_address =
                allocate_page_table_for_stage_1(table_level, t0sz, false)?;

            if is_block_descriptor(*target_descriptor) {
                #[cfg(debug_assertions)]
                println!(
                    "Convert the block descriptor({:#b}) to table descriptor",
                    *target_descriptor
                );

                let mut block_physical_address = extract_output_address(*target_descriptor);
                let mut descriptor_attribute = *target_descriptor ^ (block_physical_address as u64);
                let next_level_page = unsafe {
                    &mut *(allocated_table_address
                        as *mut [u64; PAGE_SIZE / core::mem::size_of::<u64>()])
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
                unsafe { ((*b_s).set_mem)(allocated_table_address, PAGE_SIZE, 0) };
            }

            /* TODO: 52bit OA support */
            *target_descriptor = allocated_table_address as u64 | 0b11;
            println!("Allocated: {:#X}", allocated_table_address);
        }
        map_address_recursive(
            b_s,
            physical_address,
            virtual_address,
            num_of_remaining_pages,
            extract_output_address(*target_descriptor),
            table_level + 1,
            shift_level - 9,
            permission,
            memory_attribute,
            t0sz,
        )?;
        table_index += 1;
    }
    return Ok(());
}

pub fn map_address(
    b_s: *const EfiBootServices,
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
    let mut page_table: u64;
    let tcr_el2: u64;
    unsafe {
        asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2);
    }
    let mut tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as u32;

    let (table_level, shift_level) = get_initial_page_table_level_and_bits_to_shift(tcr_el2);
    println!(
        "Initial Page Table Level: {}, Initial Shift Bits: {}",
        table_level, shift_level
    );
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
            unsafe {
                asm!("msr tcr_el2, {:x}", in(reg) new_tcr_el2);
            }
            tcr_el2_t0sz = min_t0sz;
        }
    }

    unsafe {
        asm!("mrs {:x}, ttbr0_el2",out(reg) page_table);
    }

    map_address_recursive(
        b_s,
        &mut physical_address,
        &mut virtual_address,
        &mut num_of_needed_pages,
        TTBR(page_table).get_base_address(),
        table_level,
        shift_level,
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
    unsafe {
        asm!(
            "
                tlbi  alle2
                dsb   sy
                isb"
        )
    };
    println!(
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
    b_s: *const EfiBootServices,
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    shift_level: usize,
    is_unmap: bool,
    concatenated_tables: u8,
    t0sz: u8,
    is_dummy_page: bool,
) -> Result<(), ()> {
    if table_level == 3 {
        assert_eq!(shift_level, STAGE_2_PAGE_SHIFT);
        assert_eq!(concatenated_tables, 1);
        let current_table = unsafe {
            &mut *(table_address as *mut [u64; STAGE_2_PAGE_SIZE / core::mem::size_of::<u64>()])
        };
        let table_index = (*virtual_address >> shift_level) & 0x1FF;
        let num_of_pages = if *num_of_remaining_pages + table_index > 512 {
            512 - table_index
        } else {
            *num_of_remaining_pages
        };
        let attributes: u64 = PAGE_DESCRIPTORS_AF
            | if is_dummy_page {
                0
            } else {
                0 /*PAGE_DESCRIPTORS_CONTIGUOUS*/
            }
            | STAGE_2_PAGE_ENTRY_ATTRIBUTE
            | if is_unmap { 0b00 } else { 0b11 };
        for index in table_index..(table_index + num_of_pages) {
            current_table[index] = *physical_address as u64 | attributes;
            if !is_dummy_page {
                *physical_address += PAGE_SIZE;
            }
            *virtual_address += PAGE_SIZE;
        }
        *num_of_remaining_pages -= num_of_pages;
        return Ok(());
    }
    let current_table = unsafe {
        core::slice::from_raw_parts_mut(
            table_address as *mut u64,
            (STAGE_2_PAGE_SIZE * concatenated_tables as usize) / core::mem::size_of::<u64>(),
        )
    };
    let mut table_index =
        (*virtual_address >> shift_level) & ((0x200 * concatenated_tables as usize) - 1);

    while *num_of_remaining_pages != 0 {
        println!(
            "{:#X}: Level{}'s Table Index: {:#X}",
            *virtual_address, table_level, table_index
        );
        if table_index >= (512 * concatenated_tables as usize) {
            break;
        }
        let target_descriptor = &mut current_table[table_index];
        if *target_descriptor & 0b11 != 0b11 {
            let allocated_table_address =
                allocate_page_table_for_stage_2(table_level, t0sz, false, 1)?;

            if *target_descriptor & 0b11 == 0b01 {
                #[cfg(debug_assertions)]
                println!(
                    "Convert the block descriptor({:#b}) to table descriptor",
                    *target_descriptor
                );

                let mut block_physical_address = extract_output_address(*target_descriptor);
                let mut descriptor_attribute = *target_descriptor ^ (block_physical_address as u64);
                let next_level_page = unsafe {
                    &mut *(allocated_table_address
                        as *mut [u64; PAGE_SIZE / core::mem::size_of::<u64>()])
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
                unsafe { ((*b_s).set_mem)(allocated_table_address, PAGE_SIZE, 0) };
            }

            /* TODO: 52bit OA support */
            *target_descriptor = allocated_table_address as u64 | 0b11;
            println!("Allocated: {:#X}", allocated_table_address);
        }
        map_address_recursive_stage2(
            b_s,
            physical_address,
            virtual_address,
            num_of_remaining_pages,
            extract_output_address(*target_descriptor),
            table_level + 1,
            shift_level - 9,
            is_unmap,
            1,
            t0sz,
            is_dummy_page,
        )?;
        table_index += 1;
    }
    unsafe { asm!("TLBI VMALLS12E1") };
    return Ok(());
}

pub fn map_dummy_page_into_vttbr_el2(
    b_s: *const EfiBootServices,
    mut virtual_address: usize,
    size: usize,
    mut dummy_page: usize, /*4 KiB Page Physical Address*/
) -> Result<(), ()> {
    if (size & ((1usize << STAGE_2_PAGE_SHIFT) - 1)) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
    let vtcr_el2: u64;
    unsafe { asm!("mrs {:x}, vtcr_el2",out(reg) vtcr_el2) };
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };
    let shift_level = STAGE_2_PAGE_SHIFT + 9 * ((3 - initial_look_up_level) as usize);
    let vttbr_el2: u64;

    unsafe {
        asm!("mrs {:x}, vttbr_el2",out(reg) vttbr_el2);
    }

    let original_dummy_page = dummy_page;
    map_address_recursive_stage2(
        b_s,
        &mut dummy_page,
        &mut virtual_address,
        &mut num_of_needed_pages,
        TTBR::new(vttbr_el2).get_base_address(),
        initial_look_up_level,
        shift_level,
        false,
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level),
        vtcr_el2_t0sz,
        true,
    )?;

    assert_eq!(num_of_needed_pages, 0);
    assert_eq!(original_dummy_page, dummy_page);
    return Ok(());
}

/// VTTBR_EL2の該当アドレス範囲を全てInvalid Entryにする。
/// 現在はInitial Table Levelは0までのみの対応
#[allow(dead_code)]
pub fn unmap_address_from_vttbr_el2(
    b_s: *const EfiBootServices,
    mut address: usize,
    size: usize,
) -> Result<(), ()> {
    if (size & ((1usize << STAGE_2_PAGE_SHIFT) - 1)) != 0 {
        println!("Size({:#X}) is not aligned.", size);
        return Err(());
    }
    let mut num_of_needed_pages = size >> STAGE_2_PAGE_SHIFT;
    let vtcr_el2: u64;
    unsafe { asm!("mrs {:x}, vtcr_el2",out(reg) vtcr_el2) };
    let vtcr_el2_sl0 = ((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u8;
    let vtcr_el2_t0sz = ((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u8;
    let initial_look_up_level: i8 = match vtcr_el2_sl0 {
        0b00 => 2,
        0b01 => 1,
        0b10 => 0,
        0b11 => 3,
        _ => unreachable!(),
    };
    let shift_level = STAGE_2_PAGE_SHIFT + 9 * ((3 - initial_look_up_level) as usize);
    let vttbr_el2: u64;

    assert!(address < (1 << (64 - vtcr_el2_t0sz)));

    unsafe {
        asm!("mrs {:x}, vttbr_el2",out(reg) vttbr_el2);
    }

    map_address_recursive_stage2(
        b_s,
        &mut 0,
        &mut address,
        &mut num_of_needed_pages,
        TTBR::new(vttbr_el2).get_base_address(),
        initial_look_up_level,
        shift_level,
        true,
        calculate_number_of_concatenated_page_tables(vtcr_el2_t0sz, initial_look_up_level),
        vtcr_el2_t0sz,
        false,
    )?;
    assert_eq!(num_of_needed_pages, 0);
    println!("Unmapped {:#X} Bytes({} Pages)", size, size >> PAGE_SHIFT);
    return Ok(());
}

pub fn setup_stage_2_translation() -> Result<(), ()> {
    const FIRST_LEVEL: i8 = 1;
    let top_shift_level: u8 = 12 + 9 * (3 - FIRST_LEVEL) as u8;
    let ps: u8 = 0b010; /* 40bit 1TiB */
    let sl0: u8 = 0b01; /* Starting Level 1 */
    let t0sz: u8 = 24; /* 2^(64 - 24) = 1TiB */
    let number_of_tables = calculate_number_of_concatenated_page_tables(t0sz, FIRST_LEVEL) as usize;

    let id_aa64mmfr0_el1: u64;
    unsafe { asm!("mrs {:x}, id_aa64mmfr0_el1",out(reg) id_aa64mmfr0_el1) };
    assert!((id_aa64mmfr0_el1 & 0b1111) as u8 >= ps);

    let mut physical_address = 0;
    let table_address =
        allocate_page_table_for_stage_2(FIRST_LEVEL, t0sz, true, number_of_tables as u8)?;
    let top_level_page_table = unsafe {
        core::slice::from_raw_parts_mut(
            table_address as *mut u64,
            (STAGE_2_PAGE_SIZE * number_of_tables) / core::mem::size_of::<u64>(),
        )
    };

    for e in top_level_page_table {
        let second_table_address =
            allocate_page_table_for_stage_2(FIRST_LEVEL + 1, t0sz, false, 1)?;
        let second_level_page_table = unsafe {
            &mut *(second_table_address
                as *mut [u64; STAGE_2_PAGE_SIZE / core::mem::size_of::<u64>()])
        };
        for e2 in second_level_page_table {
            *e2 = physical_address /* | PAGE_DESCRIPTORS_CONTIGUOUS */ | STAGE_2_PAGE_ENTRY_ATTRIBUTE | 0b01;
            physical_address += 1 << (top_shift_level - 9);
        }
        *e = (second_table_address as u64) | 0b11;
    }

    /* Setup VTCR_EL2 */
    /* D13.2.148 VTCR_EL2, Virtualization Translation Control Register */
    let vtcr_el2: u64 = VTCR_EL2_RES1 |
        (0b1111 << VTCR_EL2_HWU_BITS_OFFSET)  |
        ((ps as u64) << VTCR_EL2_PS_BITS_OFFSET) |
        (0 << VTCR_EL2_TG0_BITS_OFFSET) /* 4KiB */ |
        (0b11 <<VTCR_EL2_SH0_BITS_OFFSET) /* Inner Sharable */ |
        (0b01 <<VTCR_EL2_ORG0_BITS_OFFSET) /* Outer Write-Back Read-Allocate Write-Allocate Cacheable */ |
        (0b01 << VTCR_EL2_IRG0_BITS_OFFSET) /* Inner Write-Back Read-Allocate Write-Allocate Cacheable */ |
        ((sl0 as u64) << VTCR_EL2_SL0_BITS_OFFSET) |
        ((t0sz as u64) << VTCR_EL2_T0SZ_BITS_OFFSET);

    unsafe { asm!("msr vtcr_el2, {:x}",in(reg) vtcr_el2) };
    unsafe { asm!("msr vttbr_el2, {:x}",in(reg) table_address) };
    unsafe {
        asm!(
            "
            dsb ishst
            tlbi alle2
            dsb ish
            isb"
        )
    };
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
                    extract_output_address(level3_descriptor),
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
                    extract_output_address(descriptor),
                    (descriptor >> 2) & 0b111
                );
                *virtual_base_address += granule;
            } else {
                let next_level_table = extract_output_address(descriptor);
                println!(
                    "{:#X} ~ {:#X}: Table: {:#b} (OA: {:#X})",
                    virtual_base_address,
                    *virtual_base_address + granule,
                    descriptor,
                    extract_output_address(descriptor)
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
    let tcr_el2: u64;
    unsafe {
        asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2);
    };
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
    drop(current_level);

    let mair_el2: u64;
    unsafe { asm!("mrs {:x}, mair_el2",out(reg) mair_el2) };

    println!(
        "MAIR: {:#X}(Using MemAttr: {})",
        mair_el2,
        get_suitable_memory_attribute_index_from_mair_el2(false)
    );

    let mut page_table_address: usize;
    unsafe {
        asm!("mrs {:x}, ttbr0_el2",out(reg) page_table_address);
    }
    page_table_address = TTBR::new(page_table_address as u64).get_base_address();

    println!("PageTable: {:#X}", page_table_address);

    dump_page_table_recursive(
        page_table_address,
        &mut 0,
        paging_level as u8,
        0,
        base_address,
    );
}

/// 現時点ではTTBR0_EL2のみ対応
pub fn get_initial_page_table_level_and_bits_to_shift(tcr_el2: u64) -> (i8, usize) {
    let tcr_el2_ds =
        ((tcr_el2 & TCR_EL2_DS_WITHOUT_E2H) >> TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H) as u8;
    let tcr_el2_tg0 = (tcr_el2 & TCR_EL2_TG0_WITHOUT_E2H) >> TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H;
    let tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as usize;
    let page_shift = 12 + (tcr_el2_tg0 << 1) as usize;

    /* aarch64/translation/walk/AArch64.TranslationTableWalk (J1-7982) */
    let first_level = 4
        - (1 + ((64 - tcr_el2_t0sz /* TTBR1_EL2ではここが t1sz(TCR_EL2[21:16] */ - page_shift - 1)
            / (page_shift - 3))) as i8;

    if tcr_el2_ds == 0 && first_level == -1 {
        println!("5-Level Paging with DS == 0 is invalid.");
    }
    (first_level, page_shift + 9 * (3 - first_level) as usize)
}

fn get_suitable_memory_attribute_index_from_mair_el2(is_device: bool) -> u8 {
    let mut mair_el2: u64;
    let suitable_attribute: u64 = if is_device { 0x00 } else { 0xff };
    unsafe { asm!("mrs {:x},mair_el2",out(reg) mair_el2) };
    for index in 0..7 {
        let attribute = mair_el2 & 0xff;
        if attribute == suitable_attribute {
            return index;
        }
        mair_el2 >>= 8;
    }
    panic!("Attr=={:#X} is not found...", suitable_attribute);
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
                    println!(
                        "The table address is not alignment with {}, {:#X} will be wasted.",
                        table_address_alignment, address
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
                    println!(
                        "The table address is not alignment with {}, {:#X} will be wasted.",
                        table_address_alignment, address
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

#[inline(always)]
const fn calculate_number_of_concatenated_page_tables(t0sz: u8, initial_lookup_level: i8) -> u8 {
    if t0sz > (43 - ((3 - initial_lookup_level) as u8) * 9) {
        1
    } else {
        2u8.pow(((43 - ((3 - initial_lookup_level) as u8) * 9) - t0sz) as u32)
    }
}
