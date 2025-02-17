// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Stack Style Memory Allocator
//!

use crate::{MemoryAllocationError, PAGE_SHIFT, paging::page_align_up};

/// Stack Style Memory Allocator
///
/// The memory allocator which can allocate memory with alignment.
///
/// If you modified the member, please adjust [`Self::init`]
pub struct MemoryAllocator {
    base_address: usize,
    available_pages: usize,
}

impl MemoryAllocator {
    /// Setup myself with allocated address
    ///
    /// All members of Self are uninitialized.
    /// Please be careful when you assign some value into the member which has a drop trait.
    /// (Use `core::mem::forget(core::mem::replace(&mut self.member, new_value))`)
    /// This function is used to reduce the stack usage.
    /// (`aarch64-unknown-uefi` does not have __chkstk)
    ///
    /// # Arguments
    /// * `self` - mutable reference of Self, it may be uninitialized
    /// * `allocated_address` - the base address allocated
    /// * `allocated_size` - the allocated size
    pub fn init(&mut self, allocated_address: usize, allocated_size: usize) {
        /* Initialize members */
        self.available_pages = allocated_size >> PAGE_SHIFT;
        self.base_address = allocated_address;
    }

    /*
    /// Setup MemoryAllocator with allocated address, and return Self
    pub fn create(mut allocated_address: usize, allocated_size: usize) -> Self {
        use core::mem::MaybeUninit;

        let mut available_pages: usize = 0;
        let mut pool: [MaybeUninit<usize>; ALLOC_SIZE >> PAGE_SHIFT] = MaybeUninit::uninit_array();
        let mut allocated_pages = allocated_size >> PAGE_SHIFT;
        assert!(allocated_pages <= (ALLOC_SIZE >> PAGE_SHIFT));

        while allocated_pages > 0 {
            pool[available_pages].write(allocated_address);
            available_pages += 1;
            allocated_address += PAGE_SIZE;
            allocated_pages -= 1;
        }

        Self {
            pool: unsafe { MaybeUninit::array_assume_init(pool) },
            available_pages,
        }
    }
    */

    fn _allocate_memory(&mut self, pages: usize) -> Result<usize, MemoryAllocationError> {
        if self.available_pages < pages {
            return Err(MemoryAllocationError::AddressNotAvailable);
        }
        self.available_pages -= pages;
        Ok(self.base_address + (self.available_pages << PAGE_SHIFT))
    }

    pub fn allocate(&mut self, size: usize, align: usize) -> Result<usize, MemoryAllocationError> {
        if size == 0 {
            return Err(MemoryAllocationError::InvalidSize);
        }
        let pages = page_align_up(size) >> PAGE_SHIFT;
        if align <= PAGE_SHIFT {
            return self._allocate_memory(pages);
        }
        let mut base = self._allocate_memory(pages)?;
        while (base & ((1 << align) - 1)) != 0 {
            base = self._allocate_memory(1)?;
        }
        Ok(base)
    }

    pub fn free(&mut self, _address: usize, _size: usize) -> Result<(), MemoryAllocationError> {
        Ok(())
    }

    pub fn get_all_memory(&mut self) -> (usize /*base_address*/, usize /* number of pages*/) {
        let number_of_pages = self.available_pages;
        self.available_pages = 0;
        (self.base_address, number_of_pages)
    }
}
