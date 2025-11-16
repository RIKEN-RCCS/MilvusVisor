// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Temporary Memory Mapping
//!
//! This module provides functionality to temporarily map physical addresses
//! to virtual addresses for reading physical memory contents.
//!

use crate::paging::map_address;
use common::cpu::flush_tlb_el2;
use common::{HYPERVISOR_VIRTUAL_BASE_ADDRESS, PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};

/// Base virtual address for temporary mappings
/// This is located above the hypervisor base address to avoid conflicts
const TEMPORARY_MAPPING_BASE: usize = 0x7FE0000000;

/// Maximum size allowed for temporary mapping (16MB)
const MAX_TEMPORARY_MAPPING_SIZE: usize = 16 * 1024 * 1024;

/// Create a temporary mapping for reading and writing physical memory
///
/// This function maps the specified physical address range to a temporary
/// virtual address range that can be used for reading/writing the physical memory contents.
///
/// # Arguments
/// * `physical_addr` - The physical address to map (must be page-aligned)
/// * `size` - The size of the memory region to map
///
/// # Returns
/// * `Ok(virtual_addr)` - The virtual address where the physical memory is mapped
/// * `Err(())` - If the mapping failed
///
/// # Safety
/// The caller must ensure that:
/// - The physical address range is valid and accessible
/// - The returned virtual address is only used for reading
/// - `remove_temporary_mapping` is called when done to clean up
pub fn create_temporary_mapping_with_attrs(
    physical_addr: usize,
    size: usize,
    is_device: bool,
) -> Result<usize, ()> {
    // Validate input parameters
    if (physical_addr & !PAGE_MASK) != 0 {
        pr_debug!("Physical address {:#X} is not page-aligned", physical_addr);
        return Err(());
    }

    if size == 0 || size > MAX_TEMPORARY_MAPPING_SIZE {
        pr_debug!(
            "Invalid size: {} (max: {})",
            size,
            MAX_TEMPORARY_MAPPING_SIZE
        );
        return Err(());
    }

    // Calculate aligned size
    let aligned_size = if (size & ((1usize << PAGE_SHIFT) - 1)) != 0 {
        (size & PAGE_MASK) + PAGE_SIZE
    } else {
        size
    };

    // Use a fixed virtual address for temporary mapping
    let virtual_addr = TEMPORARY_MAPPING_BASE;

    // Create the mapping with read-only permissions
    // readable=true, writable=false, executable=false, is_device=false
    match map_address(
        physical_addr,
        virtual_addr,
        aligned_size,
        true,  // readable
        true,  // writable
        false, // not executable
        is_device,
    ) {
        Ok(()) => {
            // Flush TLB to ensure the old mapping is removed
            flush_tlb_el2();
            pr_debug!(
                "Temporary mapping created: physical {:#X} -> virtual {:#X}, size {:#X}",
                physical_addr,
                virtual_addr,
                aligned_size
            );
            Ok(virtual_addr)
        }
        Err(()) => {
            pr_debug!(
                "Failed to create temporary mapping for physical {:#X}, size {:#X}",
                physical_addr,
                aligned_size
            );
            Err(())
        }
    }
}

pub fn create_temporary_mapping(physical_addr: usize, size: usize) -> Result<usize, ()> {
    create_temporary_mapping_with_attrs(physical_addr, size, false)
}

pub fn create_device_temporary_mapping(physical_addr: usize, size: usize) -> Result<usize, ()> {
    create_temporary_mapping_with_attrs(physical_addr, size, true)
}

/// Remove a temporary mapping
///
/// This function removes the temporary mapping created by `create_temporary_mapping`.
/// It clears the page table entries and flushes the TLB to ensure the mapping is
/// completely removed.
///
/// # Arguments
/// * `virtual_addr` - The virtual address returned by `create_temporary_mapping`
/// * `size` - The size of the mapped region
///
/// # Returns
/// * `Ok(())` - If the mapping was successfully removed
/// * `Err(())` - If the removal failed
pub fn remove_temporary_mapping(virtual_addr: usize, size: usize) -> Result<(), ()> {
    // Validate input parameters
    if virtual_addr != TEMPORARY_MAPPING_BASE {
        pr_debug!(
            "Invalid virtual address for temporary mapping: {:#X}",
            virtual_addr
        );
        return Err(());
    }

    if size == 0 || size > MAX_TEMPORARY_MAPPING_SIZE {
        pr_debug!("Invalid size for temporary mapping removal: {}", size);
        return Err(());
    }

    // Calculate aligned size
    let aligned_size = if (size & ((1usize << PAGE_SHIFT) - 1)) != 0 {
        (size & PAGE_MASK) + PAGE_SIZE
    } else {
        size
    };

    // For now, we implement a simple approach by mapping to zero
    // This effectively removes the mapping by making it invalid
    // TODO: Implement proper page table entry clearing
    match map_address(
        0, // Map to physical address 0 (invalid/inaccessible)
        virtual_addr,
        aligned_size,
        false, // not readable
        false, // not writable
        false, // not executable
        false, // not device memory
    ) {
        Ok(()) => {
            // Flush TLB to ensure the old mapping is removed
            flush_tlb_el2();
            pr_debug!(
                "Temporary mapping removed: virtual {:#X}, size {:#X}",
                virtual_addr,
                aligned_size
            );
            Ok(())
        }
        Err(()) => {
            pr_debug!(
                "Failed to remove temporary mapping at virtual {:#X}, size {:#X}",
                virtual_addr,
                aligned_size
            );
            Err(())
        }
    }
}
