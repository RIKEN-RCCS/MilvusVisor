// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]

pub mod acpi;
pub mod cpu;
pub mod paging;
pub mod serial_port;
pub mod smmu;

use crate::serial_port::SerialPortInfo;

use core::mem::MaybeUninit;

/// 読み込むハイパーバイザー本体の位置
pub const HYPERVISOR_PATH: &'static str = "\\EFI\\BOOT\\hypervisor_kernel";
/// ハイパーバイザーをマップするアドレス
pub const HYPERVISOR_VIRTUAL_BASE_ADDRESS: usize = 0x7FC0000000;
/// シリアルポートのI/Oアドレスをマップするアドレス
pub const HYPERVISOR_SERIAL_BASE_ADDRESS: usize = 0x7FD0000000;
/// 起動時に確保するメモリ量
pub const ALLOC_SIZE: usize = 128 * 1024 * 1024; /* 128 MB */
pub const MAX_PHYSICAL_ADDRESS: usize = (1 << (52 + 1)) - 1; /* Armv8.2-A */
//pub const MAX_PHYSICAL_ADDRESS: usize = (1 << (48 + 1)) - 1;/* Armv8.0 */
pub const PAGE_MASK: usize = !0xFFF;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SHIFT: usize = 12;
pub const STAGE_2_PAGE_SIZE: usize = 0x1000;
pub const STAGE_2_PAGE_SHIFT: usize = 12;
pub const STAGE_2_PAGE_MASK: usize = !0xFFF;
/// 各CPUに割り当てるスタックのページ数
/// STACK_SIZE = STACK_PAGES << PAGE_SHIFT = STACK_PAGES * PAGE_SIZE
pub const STACK_PAGES: usize = 16;

pub type HypervisorKernelMainType = fn(&mut SystemInformation);

#[macro_export]
macro_rules! bitmask {
    ($high:expr,$low:expr) => {
        ((1 << (($high - $low) + 1)) - 1) << $low
    };
}

pub struct EcamInfo {
    pub address: usize,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// For communicating about system registers between hypervisor_bootloader and hypervisor_kernel
pub struct SystemInformation {
    pub vbar_el2: u64,
    pub acpi_rsdp_address: Option<usize>,
    pub memory_pool: &'static ([MaybeUninit<usize>; ALLOC_SIZE / PAGE_SIZE], usize),
    pub serial_port: Option<SerialPortInfo>,
    pub ecam_info: Option<EcamInfo>,
    pub smmu_v3_base_address: Option<usize>,
}
