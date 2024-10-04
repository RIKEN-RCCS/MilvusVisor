// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Paging
//!

use crate::cpu::{
    TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H, TCR_EL2_DS_WITHOUT_E2H,
    TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_T0SZ_WITHOUT_E2H,
    TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_TG0_WITHOUT_E2H, get_mair_el2,
};
use crate::{PAGE_MASK, PAGE_SIZE, STAGE_2_PAGE_MASK, STAGE_2_PAGE_SIZE, bitmask};

pub const PAGE_TABLE_SIZE: usize = 0x1000;

pub const PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET: u64 = 50;
pub const PAGE_DESCRIPTORS_CONTIGUOUS: u64 = 1 << 52;
pub const PAGE_DESCRIPTORS_NX_BIT_OFFSET: u64 = 54;

pub const PAGE_DESCRIPTORS_NT: u64 = 1 << 16;
pub const PAGE_DESCRIPTORS_AF_BIT_OFFSET: u64 = 10;
pub const PAGE_DESCRIPTORS_AF: u64 = 1 << PAGE_DESCRIPTORS_AF_BIT_OFFSET;
pub const PAGE_DESCRIPTORS_SH_BITS_OFFSET: u64 = 8;
pub const PAGE_DESCRIPTORS_SH_INNER_SHAREABLE: u64 = 0b11 << PAGE_DESCRIPTORS_SH_BITS_OFFSET;
pub const PAGE_DESCRIPTORS_AP_BITS_OFFSET: u64 = 6;

pub const MEMORY_PERMISSION_READABLE_BIT: u8 = 0;
pub const MEMORY_PERMISSION_WRITABLE_BIT: u8 = 1;
pub const MEMORY_PERMISSION_EXECUTABLE_BIT: u8 = 2;

const STAGE_2_PAGE_ENTRY_ATTRIBUTE: u64 =
    1 << 10 /* AF bit */ |
        0b11 << 8 /* SH bits (Inner sharable) */ |
        0b1111 << 2 /* MemAttr(Write-back) */;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Shareability {
    NonShareable,
    OuterShareable,
    InterShareable,
}

#[derive(Copy, Clone)]
pub struct TTBR(u64); /* Translation Table Base Register */

impl TTBR {
    const ASID: u64 = (u16::MAX as u64) << 48;
    const CNP: u64 = 1 << 0;

    pub const fn new(ttbr: u64) -> Self {
        Self(ttbr)
    }

    pub const fn get_base_address(&self) -> usize {
        ((self.0) & !(Self::CNP | Self::ASID)) as usize
    }
}

pub const fn extract_output_address(descriptor: u64, page_shift: usize) -> usize {
    (descriptor
        & bitmask!(
            PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET - 1,
            page_shift as u64
        )) as usize
}

pub const fn is_descriptor_table_or_level_3_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b11
}

pub const fn is_block_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b01
}

pub const fn create_attributes_for_stage_1(
    permission: u8,
    memory_attribute: u8,
    is_block_entry: bool,
) -> u64 {
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

    nx_bit
        | PAGE_DESCRIPTORS_AF
        | PAGE_DESCRIPTORS_SH_INNER_SHAREABLE
        | nx_bit
        | access_permission
        | (memory_attribute << 2) as u64
        | if is_block_entry { 0b01 } else { 0b11 }
}

pub const fn create_attributes_for_stage_2(
    permission: u8,
    _is_dummy_page: bool,
    is_unmap: bool,
    is_block_entry: bool,
) -> u64 {
    PAGE_DESCRIPTORS_AF
        | (((permission as u64) & (!(1 << MEMORY_PERMISSION_EXECUTABLE_BIT))) << 6)
        | STAGE_2_PAGE_ENTRY_ATTRIBUTE
        | if is_unmap {
            0b00
        } else if is_block_entry {
            0b01
        } else {
            0b11
        }
}

pub const fn table_level_to_table_shift(
    translation_granule_shift: usize,
    table_level: i8,
) -> usize {
    translation_granule_shift + 9 * (3 - table_level) as usize
}

/// Get first level of page table of TTBR_EL2
///
/// # Arguments
/// * `tcr_el2` - the value to calculate first level
///
/// # Result
/// Returns (first level of page table, the left-shift value of first level table's granule)
pub const fn get_initial_page_table_level_and_bits_to_shift(tcr_el2: u64) -> (i8, usize) {
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
        panic!("5-Level Paging with DS == 0 is invalid.");
    }
    (
        first_level,
        table_level_to_table_shift(page_shift, first_level),
    )
}

pub fn get_suitable_memory_attribute_index_from_mair_el2(is_device: bool) -> u8 {
    let mut mair_el2 = get_mair_el2();
    let suitable_attribute: u64 = if is_device { 0x00 } else { 0xff };
    for index in 0..7 {
        let attribute = mair_el2 & 0xff;
        if attribute == suitable_attribute {
            return index;
        }
        mair_el2 >>= 8;
    }
    panic!("Attr=={:#X} is not found...", suitable_attribute);
}

pub const fn calculate_number_of_concatenated_page_tables(
    t0sz: u8,
    initial_lookup_level: i8,
) -> u8 {
    if t0sz > (43 - ((3 - initial_lookup_level) as u8) * 9) {
        1
    } else {
        2u8.pow(((43 - ((3 - initial_lookup_level) as u8) * 9) - t0sz) as u32)
    }
}

pub fn page_align_up(size: usize) -> usize {
    assert_ne!(size, 0);
    ((size - 1) & PAGE_MASK) + PAGE_SIZE
}

pub fn stage2_page_align_up(size: usize) -> usize {
    assert_ne!(size, 0);
    ((size - 1) & STAGE_2_PAGE_MASK) + STAGE_2_PAGE_SIZE
}
