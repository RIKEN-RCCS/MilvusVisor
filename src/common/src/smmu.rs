// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! System Memory Management Unit
//!
//! Supported Version: 3.3

use crate::bitmask;
use crate::paging::Shareability;

pub const SMMU_MEMORY_MAP_SIZE: usize = 64 * 0x1000;
pub const SMMU_IDR0: usize = 0x00;
pub const SMMU_IDR1: usize = 0x04;
pub const SMMU_IDR2: usize = 0x08;
pub const SMMU_IDR3: usize = 0x0C;
pub const SMMU_IDR4: usize = 0x10;
pub const SMMU_IDR5: usize = 0x14;

pub const SMMU_CR0: usize = 0x20;
pub const SMMU_CR0ACK: usize = 0x24;
pub const SMMU_CR1: usize = 0x28;
pub const SMMU_GBPA: usize = 0x44;
pub const SMMU_STRTAB_BASE: usize = 0x80;
pub const SMMU_STRTAB_BASE_CFG: usize = 0x88;

pub const SMMU_IDR0_HYP: u32 = 1 << 9;
pub const SMMU_IDR0_S1P: u32 = 1 << 1;
pub const SMMU_IDR0_S2P: u32 = 1 << 0;
pub const SMMU_IDR0_TTENDIAN_BITS_OFFSET: u32 = 21;
pub const SMMU_IDR0_TTENDIAN: u32 = 0b11 << SMMU_IDR0_TTENDIAN_BITS_OFFSET;
pub const SMMU_IDR0_ST_LEVEL_BITS_OFFSET: u32 = 27;
pub const SMMU_IDR0_ST_LEVEL: u32 = 0b11 << SMMU_IDR0_ST_LEVEL_BITS_OFFSET;

pub const SMMU_IDR5_GRAN4K: u32 = 1 << 4;

pub const SMMU_CR0_SMMUEN: u32 = 1 << 0;

pub const SMMU_CR1_TABLE_SH_BITS_OFFSET: u32 = 10;

pub const SMMU_GBPA_SHCFG_BITS_OFFSET: u32 = 12;

type SteArrayBaseType = u64;
const STE_ARRAY_BASE_TYPE_BITS: SteArrayBaseType =
    (core::mem::size_of::<SteArrayBaseType>() * 8) as SteArrayBaseType;

const STE_V: SteArrayBaseType = 1 << 0;

const STE_CONFIG_OFFSET: SteArrayBaseType = 1;
const STE_CONFIG_INDEX: usize = (1 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_CONFIG: SteArrayBaseType = 0b111 << STE_CONFIG_OFFSET;

const STE_S2T0SZ_OFFSET: SteArrayBaseType = 160 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2T0SZ_INDEX: usize = (160 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2T0SZ: SteArrayBaseType = 0b111111 << STE_S2T0SZ_OFFSET;

const STE_S2SL0_OFFSET: SteArrayBaseType = 166 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2SL0_INDEX: usize = (166 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2SL0: SteArrayBaseType = 0b11 << STE_S2SL0_OFFSET;

const STE_S2IR0_OFFSET: SteArrayBaseType = 168 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2IR0_INDEX: usize = (168 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2IR0: SteArrayBaseType = 0b11 << STE_S2IR0_OFFSET;

const STE_S2OR0_OFFSET: SteArrayBaseType = 170 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2OR0_INDEX: usize = (170 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2OR0: SteArrayBaseType = 0b11 << STE_S2OR0_OFFSET;

const STE_S2SH0_OFFSET: SteArrayBaseType = 172 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2SH0_INDEX: usize = (172 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2SH0: SteArrayBaseType = 0b11 << STE_S2SH0_OFFSET;

const STE_S2TG_OFFSET: SteArrayBaseType = 174 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2TG_INDEX: usize = (174 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2TG: SteArrayBaseType = 0b11 << STE_S2TG_OFFSET;

const STE_S2PS_OFFSET: SteArrayBaseType = 176 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2PS_INDEX: usize = (176 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2PS: SteArrayBaseType = 0b111 << STE_S2PS_OFFSET;

const STE_S2AA64_OFFSET: SteArrayBaseType = 179 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2AA64_INDEX: usize = (179 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2AA64: SteArrayBaseType = 0b1 << STE_S2AA64_OFFSET;

const STE_S2TTB_OFFSET: SteArrayBaseType = 196 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2TTB_INDEX: usize = (196 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2TTB: SteArrayBaseType = (bitmask!(51, 4) >> 4) << STE_S2TTB_OFFSET;
// MEMO: Set S2HWU** to 0 because the page table is shared with CPUs.

#[derive(Clone)]
pub struct StreamTableEntry([SteArrayBaseType; 8]);

impl StreamTableEntry {
    pub const fn new() -> Self {
        Self([0; 8])
    }

    pub fn validate(&mut self) {
        self.0[0] |= STE_V;
    }

    pub fn set_config(&mut self, is_stage1_bypassed: bool, is_stage2_bypassed: bool) {
        self.0[STE_CONFIG_INDEX] = (self.0[STE_CONFIG_INDEX] & (!STE_CONFIG))
            | ((0b100
                | (!is_stage1_bypassed as SteArrayBaseType)
                | ((!is_stage2_bypassed as SteArrayBaseType) << 1))
                << STE_CONFIG_OFFSET);
    }

    pub fn set_s2t0sz(&mut self, s2t0sz: u32) {
        self.0[STE_S2T0SZ_INDEX] = (self.0[STE_S2T0SZ_INDEX] & (!STE_S2T0SZ))
            | ((s2t0sz as SteArrayBaseType) << STE_S2T0SZ_OFFSET);
    }

    pub fn set_s2sl0(&mut self, s2sl0: u32) {
        self.0[STE_S2SL0_INDEX] = (self.0[STE_S2SL0_INDEX] & (!STE_S2SL0))
            | ((s2sl0 as SteArrayBaseType) << STE_S2SL0_OFFSET);
    }

    pub fn set_s2ir0(&mut self, is_write_back: bool, is_write_allocate: bool) {
        self.0[STE_S2IR0_INDEX] = (self.0[STE_S2IR0_INDEX] & (!STE_S2IR0))
            | (((is_write_back as SteArrayBaseType)
                | ((!is_write_allocate as SteArrayBaseType) << 1))
                << STE_S2IR0_OFFSET);
    }

    pub fn set_s2or0(&mut self, is_write_back: bool, is_write_allocate: bool) {
        self.0[STE_S2OR0_INDEX] = (self.0[STE_S2OR0_INDEX] & (!STE_S2OR0))
            | (((is_write_back as SteArrayBaseType)
                | ((!is_write_allocate as SteArrayBaseType) << 1))
                << STE_S2OR0_OFFSET);
    }

    pub fn set_s2sh0(&mut self, sharaebility: Shareability) {
        let s = match sharaebility {
            Shareability::NonShareable => 0b00,
            Shareability::OuterShareable => 0b10,
            Shareability::InterShareable => 0b11,
        };
        self.0[STE_S2SH0_INDEX] =
            (self.0[STE_S2SH0_INDEX] & (!STE_S2SH0)) | (s << STE_S2OR0_OFFSET);
    }

    pub fn set_s2tg(&mut self, granule_size: usize) {
        let g = match granule_size {
            0x1000 => 0b00,
            0x4000 => 0b10,
            0x10000 => 0b01,
            _ => unimplemented!(),
        };
        self.0[STE_S2TG_INDEX] = (self.0[STE_S2TG_INDEX] & (!STE_S2TG)) | (g << STE_S2TG_OFFSET);
    }

    pub fn set_s2ps(&mut self, s2ps: u8) {
        self.0[STE_S2PS_INDEX] = (self.0[STE_S2PS_INDEX] & (!STE_S2PS))
            | ((s2ps as SteArrayBaseType) << STE_S2PS_OFFSET);
    }

    pub fn set_s2aa64(&mut self, is_aa64: bool) {
        self.0[STE_S2AA64_INDEX] = (self.0[STE_S2AA64_INDEX] & (!STE_S2AA64))
            | ((is_aa64 as SteArrayBaseType) << STE_S2AA64_OFFSET);
    }

    pub fn set_stage2_translation_table(&mut self, table_address: usize) {
        assert_eq!(table_address & !(bitmask!(51, 4)), 0);
        self.0[STE_S2TTB_INDEX] =
            (self.0[STE_S2TTB_INDEX] & (!STE_S2TTB)) | (table_address as SteArrayBaseType);
        self.set_s2aa64(true);
    }
}
