// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![feature(let_chains)]

pub mod acpi;
pub mod cpu;
#[cfg(feature = "advanced_memory_manager")]
pub mod memory_allocator;
pub mod paging;
pub mod serial_port;
pub mod smmu;
pub mod spin_flag;
#[cfg(not(feature = "advanced_memory_manager"))]
pub mod stack_memory_allocator;

#[cfg(feature = "advanced_memory_manager")]
pub use memory_allocator::MemoryAllocator;

#[cfg(not(feature = "advanced_memory_manager"))]
pub use stack_memory_allocator::MemoryAllocator;

use crate::serial_port::SerialPortInfo;

/// The name of this hypervisor
pub const HYPERVISOR_NAME: &'static str = "MilvusVisor";
/// The hash value of VCS from the environment variable
pub const HYPERVISOR_HASH_INFO: Option<&'static str> = if let Some(s) = option_env!("PROJECT_HASH") && s.len() != 0 {Some(s)}else{None};
/// The compiler information from the environment variables
pub const COMPILER_INFO: Option<&'static str> =if let Some(s) = option_env!("RUSTC_VERSION") && s.len() != 0 {Some(s)}else{None};
/// The path of hypervisor_kernel
pub const HYPERVISOR_PATH: &'static str = "\\EFI\\BOOT\\hypervisor_kernel";
/// The path of DTB written
pub const DTB_WRITTEN_PATH: &'static str = "\\EFI\\BOOT\\dtb";
/// The path of hypervisor_kernel of tftp
pub const HYPERVISOR_TFTP_PATH: &'static str = "/uefi/hypervisor_kernel";
/// The path of payload uefi application
pub const UEFI_PAYLOAD_PATH: &'static str = "/uefi/grubaa64.efi";
/// The virtual address to map hypervisor_kernel (same as hypervisor_kernel/config/linkerscript.ld)
pub const HYPERVISOR_VIRTUAL_BASE_ADDRESS: usize = 0x7FC0000000;
/// The virtual address of serial port MMIO
pub const HYPERVISOR_SERIAL_BASE_ADDRESS: usize = 0x7FD0000000;
/// The memory size to allocate
pub const ALLOC_SIZE: usize = 256 * 1024 * 1024; /* 256 MB */
pub const MAX_PHYSICAL_ADDRESS: usize = (1 << (52 + 1)) - 1; /* Armv8.2-A */
//pub const MAX_PHYSICAL_ADDRESS: usize = (1 << (48 + 1)) - 1;/* Armv8.0 */
pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);
pub const STAGE_2_PAGE_SHIFT: usize = 12;
pub const STAGE_2_PAGE_SIZE: usize = 1 << STAGE_2_PAGE_SHIFT;
pub const STAGE_2_PAGE_MASK: usize = !(STAGE_2_PAGE_SIZE - 1);
/// The stack pages to assing each cpu.
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

#[derive(Debug)]
pub struct MemorySaveListEntry {
    pub memory_start: usize,
    pub saved_address: usize,
    pub num_of_pages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAllocationError {
    AddressNotAvailable,
    InvalidSize,
    InvalidAddress,
    EntryPoolRunOut,
}

/// if [`MemorySaveListEntry::saved_address`] was this value, it indicates the entry is ondemand save area.
pub const MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG: usize = usize::MAX;

/// For communicating about system registers between hypervisor_bootloader and hypervisor_kernel
pub struct SystemInformation {
    pub vbar_el2: u64,
    pub acpi_rsdp_address: Option<usize>,
    pub available_memory_info: (
        usize, /* base_address */
        usize, /* number of pages */
    ),
    pub memory_save_list: *mut [MemorySaveListEntry],
    pub serial_port: Option<SerialPortInfo>,
    pub ecam_info: Option<EcamInfo>,
    pub smmu_v3_base_address: Option<usize>,
    pub exit_boot_service_address: usize,
}
