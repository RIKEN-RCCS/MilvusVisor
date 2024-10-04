// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Memory Allocator
//!

use crate::{MemoryAllocationError, PAGE_SHIFT};

/// Advanced Memory Allocator
///
/// The memory allocator which can allocate/free memory with alignment.
///
/// If you modified the member, please adjust [`Self::init`]
pub struct MemoryAllocator {
    free_memory_size: usize,
    first_entry: *mut MemoryEntry,
    free_list: [Option<*mut MemoryEntry>; Self::NUM_OF_FREE_LIST],
    memory_entry_pool: [MemoryEntry; Self::NUM_OF_POOL_ENTRIES],
}

struct MemoryEntry {
    /* Contains free memory area */
    previous: Option<*mut Self>,
    next: Option<*mut Self>,
    list_prev: Option<*mut Self>,
    list_next: Option<*mut Self>,
    start: usize,
    end: usize,
    enabled: bool,
}

/// ATTENTION: free_list's Iter(not normal next)
struct FreeListIterMut {
    entry: Option<*mut MemoryEntry>,
}

impl MemoryAllocator {
    const NUM_OF_POOL_ENTRIES: usize = 64;
    const NUM_OF_FREE_LIST: usize = 12;

    /// Setup myself with allocated address
    ///
    /// All members of Self are uninitialized.
    /// Please be careful when you assign some value into the member which has a drop trait.
    /// (Use `core::mem::forget(core::mem::replace(&mut self.member, new_value))`)
    /// This function is used to reduce the stack usage.
    /// (`aarch64-unknown-uefi` does not have __chkstk)
    ///
    /// # Panics
    /// If [`Self::free`] is failed, this function panics.
    ///
    /// # Arguments
    /// * `self` - mutable reference of Self, it may be uninitialized
    /// * `allocated_address` - the base address allocated
    /// * `allocated_size` - the allocated size
    pub fn init(&mut self, allocated_address: usize, allocated_size: usize) {
        use core::mem::replace;

        /* Initialize members */
        self.free_memory_size = 0;
        self.first_entry = core::ptr::null_mut();
        let _ = replace(&mut self.free_list, [None; Self::NUM_OF_FREE_LIST]);

        for e in &mut self.memory_entry_pool {
            *e = MemoryEntry {
                previous: None,
                next: None,
                list_prev: None,
                list_next: None,
                start: 0,
                end: 0,
                enabled: false,
            };
        }

        self.free(allocated_address, allocated_size)
            .expect("Failed to init memory");
    }

    pub fn get_all_memory(&mut self) -> (usize /*base_address*/, usize /* number of pages*/) {
        unreachable!()
    }

    fn create_memory_entry(&mut self) -> Result<&'static mut MemoryEntry, MemoryAllocationError> {
        for e in &mut self.memory_entry_pool {
            if !e.is_enabled() {
                e.set_enabled();
                e.init();
                return Ok(unsafe { &mut *(e as *mut _ as usize as *mut MemoryEntry) });
            }
        }
        Err(MemoryAllocationError::EntryPoolRunOut)
    }

    fn search_entry_containing_address_mut(
        &mut self,
        address: usize,
    ) -> Option<&'static mut MemoryEntry> {
        let mut entry = unsafe { &mut *self.first_entry };
        while entry.get_start_address() < address && entry.get_end_address() < address {
            if let Some(t) = entry.get_next_entry() {
                entry = t;
            } else {
                return None;
            }
        }
        if address >= entry.get_start_address() && address <= entry.get_end_address() {
            return Some(entry);
        }
        None
    }

    fn search_entry_previous_address_mut(
        &mut self,
        address: usize,
    ) -> Option<&'static mut MemoryEntry> {
        let mut entry = unsafe { &mut *self.first_entry };
        while entry.get_start_address() < address {
            if let Some(t) = entry.get_next_entry() {
                entry = t;
            } else {
                return if entry.get_end_address() <= address {
                    Some(entry)
                } else {
                    entry.get_prev_entry()
                };
            }
        }
        entry.get_prev_entry()
    }

    fn define_used_memory(
        &mut self,
        start_address: usize,
        size: usize,
        align_order: usize,
        target_entry: &mut Option<&mut MemoryEntry>,
    ) -> Result<(), MemoryAllocationError> {
        if size == 0 || self.free_memory_size < size {
            return Err(MemoryAllocationError::InvalidSize);
        }
        if align_order != 0 {
            let (aligned_start_address, aligned_size) =
                Self::align_address_and_size(start_address, size, align_order);
            return self.define_used_memory(aligned_start_address, aligned_size, 0, target_entry);
        }
        let entry = if let Some(t) = target_entry {
            assert!(t.get_start_address() <= start_address);
            assert!(t.get_end_address() >= Self::size_to_end_address(size, start_address));
            t
        } else if let Some(t) = self.search_entry_containing_address_mut(start_address) {
            t
        } else {
            return Err(MemoryAllocationError::InvalidAddress);
        };

        if entry.get_start_address() == start_address {
            if entry.get_end_address() == Self::size_to_end_address(size, start_address) {
                /* Delete the entry */
                if entry.is_first_entry() {
                    if let Some(next) = entry.get_next_entry() {
                        self.first_entry = next as *mut _;
                    } else {
                        return Err(MemoryAllocationError::AddressNotAvailable);
                    }
                }
                self.unchain_entry_from_free_list(entry);
                entry.delete();
                if target_entry.is_some() {
                    *target_entry = None;
                }
            } else {
                let old_size = entry.get_size();
                entry.set_range(start_address + size, entry.get_end_address());
                self.chain_entry_to_free_list(entry, Some(old_size));
            }
        } else if entry.get_end_address() == start_address {
            if size != 1 {
                return Err(MemoryAllocationError::InvalidAddress);
            }
            /* Allocate 1 byte of end_address */
            entry.set_range(entry.get_start_address(), start_address - 1);
            self.chain_entry_to_free_list(entry, Some(entry.get_size() + size));
        } else if entry.get_end_address() == Self::size_to_end_address(size, start_address) {
            let old_size = entry.get_size();
            entry.set_range(entry.get_start_address(), start_address - 1);
            self.chain_entry_to_free_list(entry, Some(old_size));
        } else {
            let new_entry = self.create_memory_entry()?;
            let old_size = entry.get_size();
            new_entry.set_range(start_address + size, entry.get_end_address());
            entry.set_range(entry.get_start_address(), start_address - 1);
            if let Some(next) = entry.get_next_entry() {
                new_entry.chain_after_me(next);
            }
            entry.chain_after_me(new_entry);
            self.chain_entry_to_free_list(entry, Some(old_size));
            self.chain_entry_to_free_list(new_entry, None);
        }
        self.free_memory_size -= size;
        Ok(())
    }

    fn define_free_memory(
        &mut self,
        start_address: usize,
        size: usize,
    ) -> Result<(), MemoryAllocationError> {
        if size == 0 {
            return Err(MemoryAllocationError::InvalidSize);
        }
        let entry = self
            .search_entry_previous_address_mut(start_address)
            .unwrap_or(unsafe { &mut *self.first_entry });
        let end_address = Self::size_to_end_address(size, start_address);

        if entry.get_start_address() <= start_address && entry.get_end_address() >= end_address {
            /* already freed */
            return Err(MemoryAllocationError::InvalidAddress);
        } else if entry.get_end_address() >= start_address && !entry.is_first_entry() {
            /* Free duplicated area */
            return self.define_free_memory(
                entry.get_end_address() + 1,
                Self::size_from_address(entry.get_end_address() + 1, end_address),
            );
        } else if entry.get_end_address() == end_address {
            /* Free duplicated area */
            /* entry may be first entry */
            return self.define_free_memory(start_address, size - entry.get_size());
        }

        let mut processed = false;
        let old_size = entry.get_size();
        let address_after_entry = entry.get_end_address() + 1;

        if address_after_entry == start_address {
            entry.set_range(entry.get_start_address(), end_address);
            processed = true;
        }

        if entry.is_first_entry() && entry.get_start_address() == end_address + 1 {
            entry.set_range(start_address, entry.get_end_address());
            processed = true;
        }

        if let Some(next) = entry.get_next_entry() {
            if next.get_start_address() <= start_address {
                assert!(!processed);
                return if next.get_end_address() >= end_address {
                    Err(MemoryAllocationError::InvalidAddress) /* already freed */
                } else {
                    self.define_free_memory(
                        next.get_end_address() + 1,
                        end_address - next.get_end_address(),
                    )
                };
            }
            if next.get_start_address() == end_address + 1 {
                let next_old_size = next.get_size();
                next.set_range(start_address, next.get_end_address());
                self.chain_entry_to_free_list(next, Some(next_old_size));
                processed = true;
            }

            if (next.get_start_address() == entry.get_end_address() + 1)
                || (processed && address_after_entry >= next.get_start_address())
            {
                entry.set_range(
                    entry.get_start_address(),
                    entry.get_end_address().max(next.get_end_address()),
                );

                self.unchain_entry_from_free_list(next);
                next.delete();
            }
            if processed {
                self.free_memory_size += size;
                self.chain_entry_to_free_list(entry, Some(old_size));
                return Ok(());
            }
            let new_entry = self.create_memory_entry()?;
            new_entry.set_range(start_address, end_address);
            if new_entry.get_end_address() < entry.get_start_address() {
                if let Some(prev_entry) = entry.get_prev_entry() {
                    assert!(prev_entry.get_end_address() < new_entry.get_start_address());
                    prev_entry.chain_after_me(new_entry);
                    new_entry.chain_after_me(entry);
                } else {
                    self.first_entry = new_entry as *mut _;
                    new_entry.chain_after_me(entry);
                }
            } else {
                next.set_prev_entry(new_entry);
                new_entry.set_next_entry(next);
                entry.chain_after_me(new_entry);
            }
            self.free_memory_size += size;
            self.chain_entry_to_free_list(entry, Some(old_size));
            self.chain_entry_to_free_list(new_entry, None);
            Ok(())
        } else {
            if processed {
                self.free_memory_size += size;
                self.chain_entry_to_free_list(entry, Some(old_size));
                return Ok(());
            }
            let new_entry = self.create_memory_entry()?;
            new_entry.set_range(start_address, end_address);
            if entry.get_end_address() < new_entry.get_start_address() {
                entry.chain_after_me(new_entry);
            } else {
                if let Some(prev_entry) = entry.get_prev_entry() {
                    assert!(prev_entry.get_end_address() < entry.get_start_address());
                    prev_entry.chain_after_me(new_entry);
                } else {
                    self.first_entry = new_entry as *mut _;
                }
                new_entry.chain_after_me(entry);
            }
            self.free_memory_size += size;
            self.chain_entry_to_free_list(entry, Some(old_size));
            self.chain_entry_to_free_list(new_entry, None);
            Ok(())
        }
    }

    pub fn allocate(
        &mut self,
        size: usize,
        align_order: usize,
    ) -> Result<usize, MemoryAllocationError> {
        if size == 0 || self.free_memory_size <= size {
            return Err(MemoryAllocationError::InvalidSize);
        }
        let page_order = Self::size_to_page_order(size);
        for i in page_order..Self::NUM_OF_FREE_LIST {
            let first_entry = if let Some(t) = self.free_list[i] {
                unsafe { &mut *t }
            } else {
                continue;
            };

            for entry in first_entry.list_iter_mut() {
                if entry.get_size() >= size {
                    let address_to_allocate = if align_order != 0 {
                        let (aligned_address, aligned_available_size) =
                            Self::align_address_and_available_size(
                                entry.get_start_address(),
                                entry.get_size(),
                                align_order,
                            );
                        if aligned_available_size < size {
                            continue;
                        }
                        aligned_address
                    } else {
                        entry.get_start_address()
                    };
                    self.define_used_memory(address_to_allocate, size, 0, &mut Some(entry))?;
                    return Ok(address_to_allocate);
                }
            }
        }
        Err(MemoryAllocationError::AddressNotAvailable)
    }

    pub fn free(&mut self, start_address: usize, size: usize) -> Result<(), MemoryAllocationError> {
        if self.free_memory_size == 0 {
            let first_entry = self.create_memory_entry()?;

            first_entry.init();
            first_entry.set_range(
                start_address,
                Self::size_to_end_address(size, start_address),
            );
            first_entry.set_enabled();
            self.chain_entry_to_free_list(first_entry, None);
            self.first_entry = first_entry;
            self.free_memory_size = size;
        } else {
            self.define_free_memory(start_address, size)?;
        }
        Ok(())
    }

    fn unchain_entry_from_free_list(&mut self, entry: &mut MemoryEntry) {
        let order = Self::size_to_page_order(entry.get_size());
        if self.free_list[order] == Some(entry as *mut _) {
            self.free_list[order] = entry.list_next;
        }
        entry.unchain_from_freelist();
    }

    fn chain_entry_to_free_list(&mut self, entry: &mut MemoryEntry, old_size: Option<usize>) {
        let new_order = Self::size_to_page_order(entry.get_size());
        if let Some(old_size) = old_size {
            if old_size == entry.get_size() {
                return;
            }
            let old_order = Self::size_to_page_order(old_size);
            if self.free_list[old_order] == Some(entry as *mut _) {
                self.free_list[old_order] = entry.list_next;
            }
            entry.unchain_from_freelist();
        }
        assert_eq!(entry.list_next, None);
        assert_eq!(entry.list_prev, None);

        if self.free_list[new_order].is_none() {
            self.free_list[new_order] = Some(entry as *mut _);
        } else {
            let mut list_entry: &mut MemoryEntry =
                unsafe { &mut *self.free_list[new_order].unwrap() };
            if list_entry.get_size() >= entry.get_size() {
                list_entry.list_prev = Some(entry as *mut _);
                entry.list_next = Some(list_entry as *mut _);
                self.free_list[new_order] = Some(entry as *mut _);
            } else {
                loop {
                    if let Some(next_entry) = list_entry.list_next.map(|n| unsafe { &mut *n }) {
                        if next_entry.get_size() >= entry.get_size() {
                            list_entry.list_next = Some(entry as *mut _);
                            entry.list_prev = Some(list_entry as *mut _);
                            entry.list_next = Some(next_entry as *mut _);
                            next_entry.list_prev = Some(entry as *mut _);
                            break;
                        }
                        list_entry = next_entry;
                    } else {
                        list_entry.list_next = Some(entry as *mut _);
                        entry.list_prev = Some(list_entry as *mut _);
                        break;
                    }
                }
            }
        }
    }

    #[inline]
    const fn size_to_page_order(size: usize) -> usize {
        let mut order = 0;
        while size > (1 << (order + PAGE_SHIFT)) {
            order += 1;
            if order == Self::NUM_OF_FREE_LIST - 1 {
                return order;
            }
        }
        order
    }

    #[inline]
    const fn align_address_and_size(
        address: usize,
        size: usize,
        align_order: usize,
    ) -> (usize /* address */, usize /* size */) {
        let align_size = 1 << align_order;
        let mask = !(align_size - 1);
        let aligned_address = address & mask;
        let aligned_size = ((size + (address - aligned_address) - 1) & mask) + align_size;
        (aligned_address, aligned_size)
    }

    #[inline]
    const fn align_address_and_available_size(
        start_address: usize,
        size: usize,
        align_order: usize,
    ) -> (usize /* address */, usize /* size */) {
        if start_address == 0 {
            return (0, size);
        }
        let align_size = 1 << align_order;
        let mask = !(align_size - 1);
        let aligned_address = ((start_address - 1) & mask) + align_size;
        assert!(aligned_address >= start_address);
        if size > (aligned_address - start_address) {
            (aligned_address, size - (aligned_address - start_address))
        } else {
            (aligned_address, 0)
        }
    }

    const fn size_to_end_address(size: usize, start_address: usize) -> usize {
        start_address + size - 1
    }

    const fn size_from_address(start_address: usize, end_address: usize) -> usize {
        assert!(start_address <= end_address);
        end_address - start_address + 1
    }
}

impl MemoryEntry {
    pub fn init(&mut self) {
        self.previous = None;
        self.next = None;
        self.list_prev = None;
        self.list_next = None;
    }

    pub fn delete(&mut self) {
        if let Some(previous) = self.get_prev_entry() {
            if let Some(next) = self.get_next_entry() {
                previous.chain_after_me(next);
            } else {
                previous.unset_next_entry();
            }
        } else if let Some(next) = self.get_next_entry() {
            next.unset_prev_entry();
        }
        self.previous = None;
        self.next = None;
        self.set_disabled();
    }

    pub fn set_enabled(&mut self) {
        self.enabled = true;
    }

    pub fn set_disabled(&mut self) {
        self.enabled = false;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_range(&mut self, start: usize, end: usize) {
        assert!(start < end);
        self.start = start;
        self.end = end;
    }

    pub fn get_start_address(&self) -> usize {
        self.start
    }

    pub fn get_end_address(&self) -> usize {
        self.end
    }

    pub fn get_prev_entry(&self) -> Option<&'static mut Self> {
        if let Some(previous) = self.previous {
            unsafe { Some(&mut *previous) }
        } else {
            None
        }
    }

    pub fn set_prev_entry(&mut self, prev: &mut Self) {
        self.previous = Some(prev as *mut _);
    }

    pub fn unset_prev_entry(&mut self) {
        self.previous = None;
    }

    pub fn get_next_entry(&self) -> Option<&'static mut Self> {
        if let Some(next) = self.next {
            unsafe { Some(&mut *next) }
        } else {
            None
        }
    }

    pub fn set_next_entry(&mut self, next: &mut Self) {
        self.next = Some(next as *mut _);
    }

    pub fn unset_next_entry(&mut self) {
        self.next = None;
    }

    pub fn get_size(&self) -> usize {
        MemoryAllocator::size_from_address(self.start, self.end)
    }

    pub fn chain_after_me(&mut self, entry: &mut Self) {
        self.next = Some(entry as *mut _);
        entry.previous = Some(self as *mut _);
    }

    pub fn is_first_entry(&self) -> bool {
        self.previous.is_none()
    }

    pub fn unchain_from_freelist(&mut self) {
        if let Some(prev_address) = self.list_prev {
            let prev_entry = unsafe { &mut *prev_address };
            prev_entry.list_next = self.list_next;
        }
        if let Some(next_address) = self.list_next {
            let next_entry = unsafe { &mut *next_address };
            next_entry.list_prev = self.list_prev;
        }
        self.list_next = None;
        self.list_prev = None;
    }

    pub fn list_iter_mut(&mut self) -> FreeListIterMut {
        FreeListIterMut {
            entry: Some(self as *mut _),
        }
    }
}

impl Iterator for FreeListIterMut {
    type Item = &'static mut MemoryEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(address) = self.entry {
            let entry = unsafe { &mut *(address) };
            self.entry = entry.list_next; /* ATTENTION: get **free_list's** next */
            Some(entry)
        } else {
            None
        }
    }
}
