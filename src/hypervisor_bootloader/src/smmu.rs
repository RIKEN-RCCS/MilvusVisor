// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! System Memory Management Unit
//!

use crate::allocate_memory;
use crate::paging::map_address;

use common::acpi::{get_acpi_table, iort::IORT, AcpiError};
use common::cpu::{
    get_vtcr_el2, get_vttbr_el2, VTCR_EL2_PS, VTCR_EL2_PS_BITS_OFFSET, VTCR_EL2_SL0,
    VTCR_EL2_SL0_BITS_OFFSET, VTCR_EL2_T0SZ, VTCR_EL2_T0SZ_BITS_OFFSET,
};
use common::paging::Shareability;
use common::smmu::{
    StreamTableEntry, SMMU_CR0, SMMU_CR0ACK, SMMU_CR0_SMMUEN, SMMU_CR1,
    SMMU_CR1_TABLE_SH_BITS_OFFSET, SMMU_GBPA, SMMU_GBPA_SHCFG_BITS_OFFSET, SMMU_IDR0,
    SMMU_IDR0_S2P, SMMU_IDR0_ST_LEVEL, SMMU_IDR0_TTENDIAN, SMMU_IDR0_TTENDIAN_BITS_OFFSET,
    SMMU_IDR1, SMMU_IDR5, SMMU_IDR5_GRAN4K, SMMU_MEMORY_MAP_SIZE, SMMU_STRTAB_BASE,
    SMMU_STRTAB_BASE_CFG,
};
use common::{bitmask, PAGE_SIZE, STAGE_2_PAGE_SIZE};

/// SMMUの初期化および設定を行います
///
/// 渡されたACPIテーブルの中からIORTを捜索し、その中からSMMUv3のベースアドレスを発見した場合に
/// 以下の初期化を行います。
///
/// 1. SMMU領域をマップ(マップするサイズ: [`SMMU_MEMORY_MAP_SIZE`])
/// 2. SMMUがStage2ページングと２段階Stream Tableをサポートし利用可能か確認
/// 3. CPUのStage2ページングの設定をコピーしSTEを作成する
/// 4. 作成したSTEを複製した2段目のStream Tableを一つ作成
/// 5. 1段目のStream Tableの各Descriptorに作成した2段目のStream Tableのアドレスを設定
/// 6. IORTに存在するStream IDの全てをマップできているか確認
/// 7. SMMUの有効化
///
/// # Arguments
/// acpi_address: ACPI 2.0以降のRSDPのアドレス
///
/// # Return Value
/// 上記すべての初期化に成功した場合にSome(smmuのベースアドレス)、そうでなければNone
pub fn detect_smmu(acpi_address: usize) -> Option<usize> {
    match get_acpi_table(acpi_address, &IORT::SIGNATURE) {
        Ok(address) => {
            let iort = unsafe { &*(address as *const IORT) };
            if let Some(smmu_v3) = iort.get_smmu_v3_information() {
                let base_address = smmu_v3.base_address as usize;
                println!("SMMU Base Address: {:#X}", base_address);

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
                let smmu_idr0 = unsafe { *((base_address + SMMU_IDR0) as *const u32) };
                let s2p = (smmu_idr0 & SMMU_IDR0_S2P) != 0;
                let is_supported_2level_stream_table = (smmu_idr0 & SMMU_IDR0_ST_LEVEL) != 0;
                println!(
                    "SMMU_IDR0: {:#X}(2Level: {}, S2P: {})",
                    smmu_idr0, is_supported_2level_stream_table, s2p
                );
                if ((smmu_idr0 & SMMU_IDR0_TTENDIAN) >> SMMU_IDR0_TTENDIAN_BITS_OFFSET) == 0b11 {
                    println!("Big Endian is not supported.");
                    return None;
                } else if !s2p {
                    println!("Stage 2 paging is not supported.");
                    return None;
                } else if !is_supported_2level_stream_table {
                    println!("2Level stream table is not supported.");
                    return None;
                }
                let smmu_idr5 = unsafe { *((base_address + SMMU_IDR5) as *const u32) };
                if (smmu_idr5 & SMMU_IDR5_GRAN4K) == 0 {
                    println!("4K Paging is not supported.");
                    return None;
                }
                let smmu_cr0 = unsafe { *((base_address + SMMU_CR0) as *const u32) };
                if (smmu_cr0 & SMMU_CR0_SMMUEN) != 0 {
                    println!("SMMU is already enabled.");
                    return None;
                }
                let mut smmu_cr1 = unsafe { *((base_address + SMMU_CR1) as *const u32) };
                smmu_cr1 |= (0b11) << SMMU_CR1_TABLE_SH_BITS_OFFSET;
                unsafe { *((base_address + SMMU_CR1) as *mut u32) = smmu_cr1 };

                let smmu_gbpa = 0b01 << SMMU_GBPA_SHCFG_BITS_OFFSET;
                unsafe { *((base_address + SMMU_GBPA) as *mut u32) = smmu_gbpa };

                /* Create STE */
                let mut ste = StreamTableEntry::new();
                ste.set_config(true, false);
                ste.set_s2ir0(false, true);
                ste.set_s2or0(false, true);
                ste.set_s2sh0(Shareability::OuterShareable);
                ste.set_s2tg(STAGE_2_PAGE_SIZE);
                let vtcr_el2 = get_vtcr_el2();
                ste.set_s2t0sz(((vtcr_el2 & VTCR_EL2_T0SZ) >> VTCR_EL2_T0SZ_BITS_OFFSET) as u32);
                ste.set_s2sl0(((vtcr_el2 & VTCR_EL2_SL0) >> VTCR_EL2_SL0_BITS_OFFSET) as u32);
                ste.set_s2ps(((vtcr_el2 & VTCR_EL2_PS) >> VTCR_EL2_PS_BITS_OFFSET) as u8);
                let vttbr_el2 = get_vttbr_el2();
                ste.set_stage2_translation_table(vttbr_el2 as usize);
                ste.validate();

                let level2_table_address =
                    allocate_memory(1).expect("Failed to allocate a table for SMMU");
                let level1_table_address =
                    allocate_memory(1).expect("Failed to allocate a table for SMMU");
                assert_eq!(core::mem::size_of::<StreamTableEntry>(), 64);
                let level2_table = unsafe {
                    &mut *(level2_table_address
                        as *mut [StreamTableEntry;
                            PAGE_SIZE / core::mem::size_of::<StreamTableEntry>()])
                };
                for e in level2_table {
                    *e = ste.clone();
                }
                for e in unsafe { &mut *(level1_table_address as *mut [u64; PAGE_SIZE / 8]) } {
                    *e = level2_table_address as u64 | 7; /* Level2 Table contains 2^(7- 1) (= 64) STEs */
                }
                const MAX_STREAM_ID: u32 = (64 * (PAGE_SIZE / 8) - 1) as u32;
                const TABLE_LOG2_SIZE: u32 = (MAX_STREAM_ID + 1).trailing_zeros();

                for e in smmu_v3.get_array_of_id_mappings() {
                    if e.is_single_map() {
                        println!("Single Map StreamID: {:#X}", e.output_base);
                        if e.output_base > MAX_STREAM_ID {
                            panic!("Unsupported StreamID: {:X}", e.output_base);
                        }
                    } else {
                        let max_stream_id = e.output_base + e.number_of_ids - 1;
                        println!("StreamID: {:#X}~{:#X}", e.output_base, max_stream_id);
                        if max_stream_id > MAX_STREAM_ID {
                            panic!("Unsupported StreamID: {:X}", max_stream_id);
                        }
                    }
                }
                let smmu_idr1 = unsafe { *((base_address + SMMU_IDR1) as *const u32) };
                let stream_id_size = smmu_idr1 & bitmask!(5, 0);
                let number_of_stream_ids = if (1 << stream_id_size) - 1 < MAX_STREAM_ID {
                    stream_id_size
                } else {
                    TABLE_LOG2_SIZE
                };
                println!(
                    "Number of Stream Ids: 2^{:#X} - 1({:#X})",
                    number_of_stream_ids,
                    2u32.pow(number_of_stream_ids) - 1
                );
                let strtab_base_cfg = (1 << 16) | (6 << 6) | number_of_stream_ids;
                unsafe { *((base_address + SMMU_STRTAB_BASE_CFG) as *mut u32) = strtab_base_cfg };
                unsafe {
                    *((base_address + SMMU_STRTAB_BASE) as *mut u64) =
                        (level1_table_address as u64) & bitmask!(51, 6)
                };
                /* Enable SMMU */
                let smmu_cr0 = SMMU_CR0_SMMUEN;
                unsafe { *((base_address + SMMU_CR0) as *mut u32) = smmu_cr0 };

                let smmu_cr0ack = unsafe { *((base_address + SMMU_CR0ACK) as *const u32) };
                if (smmu_cr0ack & SMMU_CR0_SMMUEN) == 0 {
                    panic!("Failed to enable SMMU(SMMU_CR0ACK: {:#X})", smmu_cr0ack);
                }
                Some(base_address)
            } else {
                println!("SMMUv3 is not found");
                None
            }
        }
        Err(AcpiError::TableNotFound) => {
            println!("IORT is not found.");
            None
        }
        Err(e) => {
            println!("Failed to get IORT table: {:?}", e);
            None
        }
    }
}
