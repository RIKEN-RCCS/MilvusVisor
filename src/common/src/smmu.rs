// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
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
pub const SMMU_CR2: usize = 0x2C;
pub const SMMU_GBPA: usize = 0x44;
pub const SMMU_AGBPA: usize = 0x48;
pub const SMMU_IRQ_CTRL: usize = 0x50;
pub const SMMU_IRQ_CTRLACK: usize = 0x54;
pub const SMMU_GERRORN: usize = 0x64;
pub const SMMU_GERROR_IRQ_CFG0: usize = 0x68;
pub const SMMU_GERROR_IRQ_CFG1: usize = 0x70;
pub const SMMU_GERROR_IRQ_CFG2: usize = 0x74;
pub const SMMU_STRTAB_BASE: usize = 0x80;
pub const SMMU_STRTAB_BASE_HIGH: usize = 0x84;
pub const SMMU_STRTAB_BASE_CFG: usize = 0x88;
pub const SMMU_CMDQ_BASE: usize = 0x90;
pub const SMMU_CMDQ_PROD: usize = 0x98;
pub const SMMU_CMDQ_CONS: usize = 0x9C;
pub const SMMU_EVENTQ_BASE: usize = 0xA0;
pub const SMMU_EVENTQ_PROD_ALIAS: usize = 0xA8;
pub const SMMU_EVENTQ_COS_ALIAS: usize = 0xAC;
pub const SMMU_EVENTQ_IRQ_CFG0: usize = 0xB0;
pub const SMMU_EVENTQ_IRQ_CFG1: usize = 0xB8;
pub const SMMU_EVENTQ_IRQ_CFG2: usize = 0xBC;
pub const SMMU_PRIQ_BASE: usize = 0xC0;
pub const SMMU_PRIQ_IRQ_CFG0: usize = 0xD0;
pub const SMMU_PRIQ_IRQ_CFG1: usize = 0xD8;
pub const SMMU_PRIQ_IRQ_CFG2: usize = 0xDC;
pub const SMMU_GATOS_CTRL: usize = 0x100;
pub const SMMU_GATOS_SID: usize = 0x0108;
pub const SMMU_GATOS_ADDR: usize = 0x0110;
pub const SMMU_GATOS_PAR: usize = 0x0118;
pub const SMMU_GMPAM: usize = 0x0138;
pub const SMMU_GBPMPAM: usize = 0x013C;
pub const SMMU_VATOS_SEL: usize = 0x0180;

/*
pub const SMMU_VATOS_SEL: usize = 0x0180;
pub const SMMU_VATOS_SID: usize = 0x0A08;
pub const SMMU_VATOS_ADDR: usize = 0x0A10;
pub const SMMU_VATOS_PAR: usize = 0x0A18;
*/

pub const SMMU_CMDQ_CONTROL_PAGE_BASE: usize = 0x4000;
pub const SMMU_CMDQ_CONTROL_PAGE_BASE_END: usize = 0x4000 + 32 * 255;

pub const SMMU_IDR0_VATOS: u32 = 1 << 20;
pub const SMMU_IDR0_CD2L: u32 = 1 << 19;
pub const SMMU_IDR0_VMID16: u32 = 1 << 18;
pub const SMMU_IDR0_HYP: u32 = 1 << 9;
pub const SMMU_IDR0_S1P: u32 = 1 << 1;
pub const SMMU_IDR0_S2P: u32 = 1 << 0;
pub const SMMU_IDR0_TTENDIAN_BITS_OFFSET: u32 = 21;
pub const SMMU_IDR0_TTENDIAN: u32 = 0b11 << SMMU_IDR0_TTENDIAN_BITS_OFFSET;
pub const SMMU_IDR0_ST_LEVEL_BITS_OFFSET: u32 = 27;
pub const SMMU_IDR0_ST_LEVEL: u32 = 0b11 << SMMU_IDR0_ST_LEVEL_BITS_OFFSET;

pub const SMMU_IDR5_GRAN4K: u32 = 1 << 4;

pub const SMMU_CR0_SMMUEN_BIT_OFFSET: u32 = 0;
pub const SMMU_CR0_SMMUEN: u32 = 1 << SMMU_CR0_SMMUEN_BIT_OFFSET;
pub const SMMU_CR0_EVENTQEN: u32 = 1 << 2;
pub const SMMU_CR0_VMW: u32 = 0b111 << 6;

pub const SMMU_CR1_TABLE_SH_BITS_OFFSET: u32 = 10;
pub const SMMU_CR1_QUEUE_SH: u32 = 0b11 << 4;
pub const SMMU_CR1_QUEUE_OC: u32 = 0b11 << 2;
pub const SMMU_CR1_QUEUE_IC: u32 = 0b11;

pub const SMMU_CR2_E2H: u32 = 1;

pub const SMMU_STRTAB_BASE_ADDRESS: u64 = bitmask!(51, 6);

pub const SMMU_STRTAB_BASE_CFG_FMT_BITS_OFFSET: u32 = 16;
pub const SMMU_STRTAB_BASE_CFG_FMT: u32 = 0b11 << SMMU_STRTAB_BASE_CFG_FMT_BITS_OFFSET;
pub const SMMU_STRTAB_BASE_CFG_FMT_2LEVEL: u32 = 0b01 << SMMU_STRTAB_BASE_CFG_FMT_BITS_OFFSET;
pub const SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET: u32 = 6;
pub const SMMU_STRTAB_BASE_CFG_SPLIT: u32 = 0b11111 << SMMU_STRTAB_BASE_CFG_SPLIT_BITS_OFFSET;
pub const SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET: u32 = 0;
pub const SMMU_STRTAB_BASE_CFG_LOG2SIZE: u32 =
    0b111111 << SMMU_STRTAB_BASE_CFG_LOG2SIZE_BITS_OFFSET;

pub const SMMU_GBPA_UPDATE: u32 = 1 << 31;
pub const SMMU_GBPA_ABORT: u32 = 1 << 20;
pub const SMMU_GBPA_SHCFG_INCOMING: u32 = 0b01 << 12;

pub const SMMU_VATOS_SID_SUBSTREAM_ID: u64 = bitmask!(51, 32);

pub type SteArrayBaseType = u64;

const STE_ARRAY_BASE_TYPE_BITS: SteArrayBaseType = SteArrayBaseType::BITS as SteArrayBaseType;

pub const STE_V_INDEX: usize = 0;
pub const STE_V: SteArrayBaseType = 1 << 0;

const STE_CONFIG_OFFSET: SteArrayBaseType = 1;
pub const STE_CONFIG_INDEX: usize = (1 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_CONFIG: SteArrayBaseType = 0b111 << STE_CONFIG_OFFSET;

const STE_S2HWU_OFFSET: SteArrayBaseType = 72 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2HWU_INDEX: usize = (72 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2HWU: SteArrayBaseType = 0b1111 << STE_S2HWU_OFFSET;

const STE_S2FWB_OFFSET: SteArrayBaseType = 89 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2FWB_INDEX: usize = (89 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2FWB: SteArrayBaseType = 0b1 << STE_S2FWB_OFFSET;

const STE_S2VMID_OFFSET: SteArrayBaseType = 128 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2VMID_INDEX: usize = (128 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2VMID: SteArrayBaseType = bitmask!(143 - 128, 0) << STE_S2VMID_OFFSET;

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

const STE_S2ENDI_OFFSET: SteArrayBaseType = 180 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2ENDI_INDEX: usize = (180 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2ENDI: SteArrayBaseType = 0b1 << STE_S2ENDI_OFFSET;

const STE_S2AFFD_OFFSET: SteArrayBaseType = 181 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2AFFD_INDEX: usize = (181 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2AFFD: SteArrayBaseType = 0b1 << STE_S2AFFD_OFFSET;

const STE_S2PTW_OFFSET: SteArrayBaseType = 182 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2PTW_INDEX: usize = (182 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2PTW: SteArrayBaseType = 0b1 << STE_S2PTW_OFFSET;

const STE_S2HD_OFFSET: SteArrayBaseType = 183 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2HD_INDEX: usize = (183 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2HD: SteArrayBaseType = 0b1 << STE_S2HD_OFFSET;

const STE_S2HA_OFFSET: SteArrayBaseType = 184 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2HA_INDEX: usize = (184 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2HA: SteArrayBaseType = 0b1 << STE_S2HA_OFFSET;

const STE_S2S_OFFSET: SteArrayBaseType = 185 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2S_INDEX: usize = (185 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2S: SteArrayBaseType = 0b1 << STE_S2S_OFFSET;

const STE_S2R_OFFSET: SteArrayBaseType = 186 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2R_INDEX: usize = (186 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2R: SteArrayBaseType = 0b1 << STE_S2R_OFFSET;

const STE_S2NSW_OFFSET: SteArrayBaseType = 192 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2NSW_INDEX: usize = (192 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2NSW: SteArrayBaseType = 0b1 << STE_S2NSW_OFFSET;

const STE_S2NSA_OFFSET: SteArrayBaseType = 193 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2NSA_INDEX: usize = (193 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2NSA: SteArrayBaseType = 0b1 << STE_S2NSA_OFFSET;

const STE_S2TTB_OFFSET: SteArrayBaseType = 196 % STE_ARRAY_BASE_TYPE_BITS;
const STE_S2TTB_INDEX: usize = (196 / STE_ARRAY_BASE_TYPE_BITS) as usize;
const STE_S2TTB: SteArrayBaseType = (bitmask!(51, 4) >> 4) << STE_S2TTB_OFFSET;
// MEMO: Set S2HWU** to 0 because the page table is shared with CPUs.

#[derive(Clone, Copy)]
pub struct StreamTableEntry([SteArrayBaseType; 8]);

impl Default for StreamTableEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamTableEntry {
    pub const fn new() -> Self {
        Self([0; 8])
    }

    pub fn is_validated(&self) -> bool {
        (self.0[STE_V_INDEX] & STE_V) != 0
    }

    pub fn validate(&mut self) {
        self.0[STE_V_INDEX] |= STE_V;
    }

    pub fn get_config(&self) -> SteArrayBaseType {
        (self.0[STE_CONFIG_INDEX] & STE_CONFIG) >> STE_CONFIG_OFFSET
    }

    pub fn is_stage1_bypassed(&self) -> bool {
        (((self.0[STE_CONFIG_INDEX] & STE_CONFIG) >> STE_CONFIG_OFFSET) & 1) == 0
    }

    pub fn is_traffic_can_pass(&self) -> bool {
        ((self.0[STE_CONFIG_INDEX] >> STE_CONFIG_OFFSET) & 0b100) != 0
    }

    pub fn set_config(
        &mut self,
        is_traffic_can_pass: bool,
        is_stage1_bypassed: bool,
        is_stage2_bypassed: bool,
    ) {
        self.0[STE_CONFIG_INDEX] = (self.0[STE_CONFIG_INDEX] & (!STE_CONFIG))
            | ((((is_traffic_can_pass as SteArrayBaseType) << 2)
                | ((!is_stage2_bypassed as SteArrayBaseType) << 1)
                | (!is_stage1_bypassed as SteArrayBaseType))
                << STE_CONFIG_OFFSET);
    }

    pub fn set_s2hwu(&mut self, hwu: u8) {
        assert!(hwu <= 0b1111);
        self.0[STE_S2HWU_INDEX] = (self.0[STE_S2HWU_INDEX] & (!STE_S2HWU))
            | ((hwu as SteArrayBaseType) << STE_S2HWU_OFFSET);
    }

    pub fn set_s2fwb(&mut self, fwb: u8) {
        assert!(fwb < 2);
        self.0[STE_S2FWB_INDEX] = (self.0[STE_S2FWB_INDEX] & (!STE_S2FWB))
            | ((fwb as SteArrayBaseType) << STE_S2FWB_OFFSET);
    }

    pub fn set_s2vmid(&mut self, vmid: u16) {
        self.0[STE_S2VMID_INDEX] = (self.0[STE_S2VMID_INDEX] & (!STE_S2VMID))
            | ((vmid as SteArrayBaseType) << STE_S2VMID_OFFSET);
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

    pub fn set_s2endi(&mut self, is_big_endian: bool) {
        self.0[STE_S2ENDI_INDEX] = (self.0[STE_S2ENDI_INDEX] & (!STE_S2ENDI))
            | ((is_big_endian as SteArrayBaseType) << STE_S2ENDI_OFFSET);
    }

    pub fn set_s2affd(&mut self, access_flag_fault_never_occuers: bool) {
        self.0[STE_S2AFFD_INDEX] = (self.0[STE_S2AFFD_INDEX] & (!STE_S2AFFD))
            | ((access_flag_fault_never_occuers as SteArrayBaseType) << STE_S2AFFD_OFFSET);
    }

    pub fn set_s2ptw(&mut self, ptw: u8) {
        assert!(ptw < 2);
        self.0[STE_S2PTW_INDEX] = (self.0[STE_S2PTW_INDEX] & (!STE_S2PTW))
            | ((ptw as SteArrayBaseType) << STE_S2PTW_OFFSET);
    }

    pub fn set_s2hd(&mut self, hd: u8) {
        assert!(hd < 2);
        self.0[STE_S2HD_INDEX] =
            (self.0[STE_S2HD_INDEX] & (!STE_S2HD)) | ((hd as SteArrayBaseType) << STE_S2HD_OFFSET);
    }

    pub fn set_s2ha(&mut self, ha: u8) {
        assert!(ha <= 0b11);
        self.0[STE_S2HA_INDEX] =
            (self.0[STE_S2HA_INDEX] & (!STE_S2HA)) | ((ha as SteArrayBaseType) << STE_S2HA_OFFSET);
    }

    pub fn set_s2s(&mut self, should_stall: bool) {
        self.0[STE_S2S_INDEX] = (self.0[STE_S2S_INDEX] & (!STE_S2S))
            | ((should_stall as SteArrayBaseType) << STE_S2S_OFFSET);
    }

    pub fn set_s2r(&mut self, should_record: bool) {
        self.0[STE_S2R_INDEX] = (self.0[STE_S2R_INDEX] & (!STE_S2R))
            | ((should_record as SteArrayBaseType) << STE_S2R_OFFSET);
    }

    pub fn set_s2nsa(&mut self, nsa: u8) {
        assert!(nsa < 2);
        self.0[STE_S2NSA_INDEX] = (self.0[STE_S2NSA_INDEX] & (!STE_S2NSA))
            | ((nsa as SteArrayBaseType) << STE_S2NSA_OFFSET);
    }

    pub fn set_stage2_translation_table(&mut self, table_address: usize) {
        assert_eq!(table_address & !bitmask!(51, 4), 0);
        self.0[STE_S2TTB_INDEX] =
            (self.0[STE_S2TTB_INDEX] & (!STE_S2TTB)) | (table_address as SteArrayBaseType);
        self.set_s2aa64(true);
    }

    /// This function is not validate STE
    pub fn set_stage2_settings(
        &mut self,
        vtcr_el2: u64,
        vttbr_el2: u64,
        is_traffic_can_pass: bool,
        is_stage1_bypassed: bool,
    ) {
        use crate::STAGE_2_PAGE_SIZE;
        use crate::cpu::{
            VTCR_EL2_PS, VTCR_EL2_PS_BITS_OFFSET, VTCR_EL2_SL0, VTCR_EL2_SL0_BITS_OFFSET,
            VTCR_EL2_T0SZ, VTCR_EL2_T0SZ_BITS_OFFSET,
        };

        self.set_s2hwu(0b0000);
        self.set_s2fwb(0);
        self.set_s2vmid(0);
        self.set_s2t0sz(((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u32);
        self.set_s2sl0(((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u32);
        self.set_s2ir0(false, true);
        self.set_s2or0(false, true);
        self.set_s2tg(STAGE_2_PAGE_SIZE);
        self.set_s2sh0(Shareability::NonShareable);
        self.set_s2ps(((vtcr_el2 & VTCR_EL2_PS) >> VTCR_EL2_PS_BITS_OFFSET) as u8);
        self.set_s2aa64(true);
        self.set_s2endi(false);
        self.set_s2affd(true);
        self.set_s2ptw(0);
        self.set_s2hd(0);
        self.set_s2ha(0);
        self.set_s2s(false); // TODO:
        self.set_s2r(false); // TODO:
        self.set_s2nsa(0);
        self.set_stage2_translation_table(vttbr_el2 as usize);
        self.set_config(is_traffic_can_pass, is_stage1_bypassed, false);
    }
}

/// This function will return false when the data is STE::config
pub fn is_offset_configuration_about_stage2(offset: usize, data: SteArrayBaseType) -> bool {
    assert_eq!(size_of::<SteArrayBaseType>(), 8);
    match offset {
        1 => {
            let mask: SteArrayBaseType = (0b1111 << (72 - 64)) | (1 << (89 - 64));
            (data & mask) != 0
        }
        2 | 3 => true,
        _ => false,
    }
}

pub const fn get_level1_table_size(log2_size: u32, split: u32) -> usize {
    8usize * (log2_size - split) as usize
}

pub const fn get_level2_table_size(span: u64, _split: u32) -> usize {
    (1usize << (span - 1)) * size_of::<StreamTableEntry>()
}

pub fn create_bitmask_of_stage2_configurations(ste_offset: usize) -> u64 {
    let start_offset = ste_offset / size_of::<SteArrayBaseType>();
    let end_offset = (ste_offset + size_of::<u64>()) / size_of::<SteArrayBaseType>();
    let mut mask: u64 = 0;

    for i in start_offset..end_offset {
        let m = _create_bitmask_of_stage2_configurations(i) as u64;
        let i_byte_offset = i * size_of::<u64>();
        if i_byte_offset >= ste_offset {
            mask |= m << (i_byte_offset - ste_offset);
        } else {
            mask |= m >> (ste_offset - i_byte_offset);
        }
    }
    mask
}

const fn _create_bitmask_of_stage2_configurations(
    ste_offset_by_array_base_type: usize,
) -> SteArrayBaseType {
    let mut mask: SteArrayBaseType = 0;
    if ste_offset_by_array_base_type == STE_CONFIG_INDEX {
        mask |= 0b010 << STE_CONFIG_OFFSET;
    }
    if ste_offset_by_array_base_type == STE_S2HWU_INDEX {
        mask |= STE_S2HWU;
    }
    if ste_offset_by_array_base_type == STE_S2FWB_INDEX {
        mask |= STE_S2FWB;
    }
    if ste_offset_by_array_base_type == STE_S2VMID_INDEX {
        mask |= STE_S2VMID;
    }
    if ste_offset_by_array_base_type == STE_S2T0SZ_INDEX {
        mask |= STE_S2T0SZ;
    };
    if ste_offset_by_array_base_type == STE_S2SL0_INDEX {
        mask |= STE_S2SL0;
    }
    if ste_offset_by_array_base_type == STE_S2IR0_INDEX {
        mask |= STE_S2IR0;
    }
    if ste_offset_by_array_base_type == STE_S2OR0_INDEX {
        mask |= STE_S2OR0;
    }
    if ste_offset_by_array_base_type == STE_S2SH0_INDEX {
        mask |= STE_S2SH0;
    }
    if ste_offset_by_array_base_type == STE_S2TG_INDEX {
        mask |= STE_S2TG;
    }
    if ste_offset_by_array_base_type == STE_S2PS_INDEX {
        mask |= STE_S2PS;
    };
    if ste_offset_by_array_base_type == STE_S2AA64_INDEX {
        mask |= STE_S2AA64;
    }
    if ste_offset_by_array_base_type == STE_S2ENDI_INDEX {
        mask |= STE_S2ENDI;
    }
    if ste_offset_by_array_base_type == STE_S2AFFD_INDEX {
        mask |= STE_S2AFFD;
    }
    if ste_offset_by_array_base_type == STE_S2PTW_INDEX {
        mask |= STE_S2PTW;
    }
    if ste_offset_by_array_base_type == STE_S2HD_INDEX {
        mask |= STE_S2HD;
    }
    if ste_offset_by_array_base_type == STE_S2HA_INDEX {
        mask |= STE_S2HA;
    };
    if ste_offset_by_array_base_type == STE_S2S_INDEX {
        mask |= STE_S2S;
    }
    if ste_offset_by_array_base_type == STE_S2R_INDEX {
        mask |= STE_S2R;
    }
    if ste_offset_by_array_base_type == STE_S2NSW_INDEX {
        mask |= STE_S2NSW;
    }
    if ste_offset_by_array_base_type == STE_S2NSA_INDEX {
        mask |= STE_S2NSA;
    }
    if ste_offset_by_array_base_type == STE_S2TTB_INDEX {
        mask |= STE_S2TTB;
    }

    mask
}
