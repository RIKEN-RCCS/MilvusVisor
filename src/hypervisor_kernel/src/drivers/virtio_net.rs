// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php
//!
//! Virtio Device Interface for Light Weight Isolation Environment
//!
//! This module provides virtio network device interface to communicate with BSP environment

use common::GeneralPurposeRegisters;
use common::cpu;
use common::spin_flag::SpinLockFlag;

use crate::memory_hook::*;
use crate::paging;

use super::virtio::*;

const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;

/// Virtio Network Entry Descriptor
#[repr(C)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

pub struct VirtioNetwork {
    lock: SpinLockFlag,
    affinity: u64,
    int_id: u32,
    page_size: usize,
    queue_selector: u8,
    queue: [VirtQueue; 2],
    interrupt_status: u8,
    status: u8,
    mac_address: [u8; 6],
    features_select: u8,
    base_address: usize,
}

static mut VIRTIO_NET_LIST: [VirtioNetwork; 10] =
    unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
static mut BSP_VIRTIO_NET_LIST: [VirtioNetwork; 10] =
    unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

impl VirtioNetwork {
    /// The size of MMIO handled by this implementation
    pub const MMIO_SIZE: usize = 0x100;

    fn init(&mut self, affinity: u64, int_id: u32, base_address: usize) {
        assert!(self.lock.is_locked());
        self.affinity = affinity;
        self.int_id = int_id;
        self.page_size = Self::MMIO_SIZE;
        self.base_address = base_address;
        for e in &mut self.queue {
            *e = VirtQueue::new();
        }
    }

    fn process_receive_frame(queue: &mut VirtQueue, frame: &[u8]) -> Result<(), ()> {
        let Some(id) = queue.get_next_avail_id() else {
            println!("Failed to get avail id.");
            return Err(());
        };
        let Some(descriptor_id) = queue.get_descriptor_id(id) else {
            println!("Failed to get descriptor id");
            return Err(());
        };
        let Some(mut descriptor) = queue.get_descriptor(descriptor_id) else {
            println!("Failed to get descriptor");
            return Err(());
        };
        if (descriptor.length as usize) < size_of::<VirtioNetHdr>() {
            println!("Descriptor is too small");
            return Err(());
        }
        let hdr = unsafe { &mut *(descriptor.address as *mut VirtioNetHdr) };
        let mut descriptor_offset = size_of::<VirtioNetHdr>();
        let mut pointer = 0;
        *hdr = VirtioNetHdr {
            flags: 0,
            gso_type: 0,
            hdr_len: descriptor_offset as _,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        };

        loop {
            let writing_length =
                ((descriptor.length as usize) - descriptor_offset).min(frame.len() - pointer);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &frame[pointer],
                    ((descriptor.address as usize) + descriptor_offset) as *mut u8,
                    writing_length,
                )
            };
            descriptor_offset = 0;
            pointer += writing_length;
            hdr.num_buffers += 1;
            if pointer == frame.len() {
                break;
            }

            if (descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) == 0 {
                println!("Failed to get next descriptor");
                return Err(());
            }
            descriptor = if let Some(d) = queue.get_descriptor(descriptor.next) {
                d
            } else {
                println!("Failed to get next descriptor");
                return Err(());
            }
        }
        if pointer != frame.len() {
            println!(
                "Expected {:#X} bytes to write, but only {:#X} bytes are written.",
                frame.len(),
                pointer
            );
            return Err(());
        }

        queue.write_used(
            descriptor_id,
            (frame.len() + size_of::<VirtioNetHdr>()) as u32,
        );
        Ok(())
    }

    fn process_transmit_frames<F>(queue: &mut VirtQueue, mut callback: F) -> Result<u32, ()>
    where
        F: FnMut(&[u8]),
    {
        let mut number_of_frames = 0;
        while let Some(id) = queue.get_next_avail_id() {
            let Some(request_descriptor_id) = queue.get_descriptor_id(id) else {
                println!("Failed to get next descriptor id");
                return Err(());
            };
            let Some(request_descriptor) = queue.get_descriptor(request_descriptor_id) else {
                println!("Failed to get next descriptor");
                return Err(());
            };
            if (request_descriptor.length as usize) < size_of::<VirtioNetHdr>() {
                println!("Invalid Request: Descriptor is too small");
                return Err(());
            }
            let request = unsafe { &*(request_descriptor.address as usize as *const VirtioNetHdr) };
            if request.flags != 0 || request.gso_type != 0 {
                println!(
                    "Unsupported flag({:#X}) nor gso_type({:#X})",
                    request.flags, request.gso_type
                );
                return Err(());
            }

            let mut descriptor_id = request_descriptor.next;
            let mut total_size = 0;
            let size = request_descriptor.length as usize - size_of::<VirtioNetHdr>();

            if size > 0 {
                let frame = request_descriptor.address as usize + size_of::<VirtioNetHdr>();
                number_of_frames += 1;
                total_size += size;

                callback(unsafe { core::slice::from_raw_parts(frame as *const u8, size) });
                if (request_descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) == 0 {
                    queue.write_used(request_descriptor_id, total_size as u32);
                    continue;
                }
            }
            if (request_descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) == 0 {
                println!("Invalid Request: Broken Descriptor");
                return Err(());
            }

            loop {
                let Some(descriptor) = queue.get_descriptor(descriptor_id) else {
                    println!("Failed to get next descriptor");
                    return Err(());
                };
                let frame = descriptor.address as usize;
                let size = descriptor.length as usize;
                total_size += size;
                number_of_frames += 1;

                callback(unsafe { core::slice::from_raw_parts(frame as *const u8, size) });
                if (descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) != 0 {
                    descriptor_id = descriptor.next;
                } else {
                    break;
                }
            }
            queue.write_used(request_descriptor_id, total_size as u32);
        }
        Ok(number_of_frames)
    }

    fn transmit(&mut self, queue_id: u8) {
        assert!(self.lock.is_locked());
        let Some(linked_virtio) =
            Self::get_linked_struct(cpu::mpidr_to_affinity(cpu::get_mpidr_el1()))
                .or_else(|| Self::get_linked_struct_bsp(self.affinity))
        else {
            println!("Failed to get the linked VirtIO");
            return;
        };
        let mut should_interrupt: bool = false;

        let number_of_frames =
            Self::process_transmit_frames(&mut self.queue[queue_id as usize], |frame| {
                if linked_virtio.lock.try_lock_weak().is_err() {
                    self.lock.unlock();
                    loop {
                        while linked_virtio.lock.try_lock_weak().is_err() {
                            core::hint::spin_loop();
                        }
                        if self.lock.try_lock_weak().is_ok() {
                            break;
                        }
                        linked_virtio.lock.unlock();
                    }
                }
                if linked_virtio.is_ready() {
                    if linked_virtio.queue[0].is_avail_ring_empty() {
                        println!("VirtQueue is full");
                    } else {
                        Self::process_receive_frame(&mut linked_virtio.queue[0], frame)
                            .expect("Failed to transmit frame");
                        should_interrupt = true;
                    }
                } else {
                    println!("Linked device is not ready.");
                }
                linked_virtio.lock.unlock();
            })
            .expect("Failed to process frame");
        if number_of_frames > 0 {
            self.trigger_interrupt(1);
            if should_interrupt {
                if linked_virtio.lock.try_lock_weak().is_err() {
                    self.lock.unlock();
                    loop {
                        while linked_virtio.lock.try_lock_weak().is_err() {
                            core::hint::spin_loop();
                        }
                        if self.lock.try_lock_weak().is_ok() {
                            break;
                        }
                        linked_virtio.lock.unlock();
                    }
                }
                linked_virtio.trigger_interrupt(0);
                linked_virtio.lock.unlock();
            }
        }
    }

    fn get_target_struct(affinity: u64, base_address: usize) -> Option<&'static mut Self> {
        unsafe { (&raw mut VIRTIO_NET_LIST).as_mut().unwrap() }
            .iter_mut()
            .find(|e| e.affinity == affinity && e.base_address == base_address)
    }

    fn get_target_struct_bsp(base_address: usize) -> Option<&'static mut Self> {
        unsafe { (&raw mut BSP_VIRTIO_NET_LIST).as_mut().unwrap() }
            .iter_mut()
            .find(|e| e.base_address == base_address)
    }

    fn get_linked_struct(affinity: u64) -> Option<&'static mut Self> {
        unsafe { (&raw mut BSP_VIRTIO_NET_LIST).as_mut().unwrap() }
            .iter_mut()
            .find(|e| e.affinity == affinity && e.base_address != 0)
    }

    fn get_linked_struct_bsp(affinity: u64) -> Option<&'static mut Self> {
        unsafe { (&raw mut VIRTIO_NET_LIST).as_mut().unwrap() }
            .iter_mut()
            .find(|e| e.affinity == affinity && e.base_address != 0)
    }

    pub fn setup_new_device(int_id: u32, mmio_base_address: usize) {
        let mut should_add_handler = true;
        for e in unsafe { (&raw mut VIRTIO_NET_LIST).as_mut().unwrap() }.iter_mut() {
            e.lock.lock();
            if e.affinity == 0 && e.int_id == 0 {
                /* Empty Entry */
                e.init(
                    cpu::mpidr_to_affinity(cpu::get_mpidr_el1()),
                    int_id,
                    mmio_base_address,
                );
                e.lock.unlock();
                break;
            }
            if e.base_address == mmio_base_address {
                should_add_handler = false;
            }
            e.lock.unlock();
        }

        paging::add_memory_access_trap(
            mmio_base_address & common::STAGE_2_PAGE_MASK,
            common::STAGE_2_PAGE_SIZE,
            false,
            false,
        )
        .expect("Failed to setup memory trap.");

        if should_add_handler {
            add_memory_load_access_handler(LoadAccessHandlerEntry::new(
                mmio_base_address,
                Self::MMIO_SIZE,
                0,
                Self::load_handler,
            ))
            .expect("Failed to add the handler");
            add_memory_store_access_handler(StoreAccessHandlerEntry::new(
                mmio_base_address,
                Self::MMIO_SIZE,
                0,
                Self::store_handler,
            ))
            .expect("Failed to add the handler");
        }
    }

    pub fn setup_new_device_bsp(int_id: u32, mmio_base_address: usize, linked_mpidr: u64) {
        for e in unsafe { (&raw mut BSP_VIRTIO_NET_LIST).as_mut().unwrap() }.iter_mut() {
            e.lock.lock();
            if e.affinity == 0 && e.int_id == 0 {
                /* Empty Entry */
                e.init(
                    cpu::mpidr_to_affinity(linked_mpidr),
                    int_id,
                    mmio_base_address,
                );
                e.lock.unlock();
                break;
            }
            e.lock.unlock();
        }

        paging::add_memory_access_trap(
            mmio_base_address & common::STAGE_2_PAGE_MASK,
            common::STAGE_2_PAGE_SIZE,
            false,
            false,
        )
        .expect("Failed to setup memory trap.");

        add_memory_load_access_handler(LoadAccessHandlerEntry::new(
            mmio_base_address,
            Self::MMIO_SIZE,
            0,
            Self::load_handler,
        ))
        .expect("Failed to add the handler");
        add_memory_store_access_handler(StoreAccessHandlerEntry::new(
            mmio_base_address,
            Self::MMIO_SIZE,
            0,
            Self::store_handler,
        ))
        .expect("Failed to add the handler");
    }

    const fn is_ready(&self) -> bool {
        (self.status & 4) != 0
    }

    fn trigger_interrupt(&mut self, _queue: usize) {
        assert!(self.lock.is_locked());
        self.interrupt_status |= 1;
        crate::gic::set_interrupt_pending(self.int_id);
    }

    fn load_handler(
        accessing_memory_address: usize,
        _: &mut GeneralPurposeRegisters,
        _: u8,
        _: bool,
        _: bool,
        entry: &LoadAccessHandlerEntry,
    ) -> LoadHookResult {
        let offset = accessing_memory_address - entry.get_target_address();
        let mut value = 0u64;
        let net = Self::get_target_struct(
            cpu::mpidr_to_affinity(cpu::get_mpidr_el1()),
            entry.get_target_address(),
        )
        .unwrap_or_else(|| {
            Self::get_target_struct_bsp(entry.get_target_address())
                .expect("Failed to find the descriptor")
        });

        if offset < 0x100 {
            match offset {
                VIRTIO_MMIO_MAGIC => {
                    value = VIRTIO_MMIO_MAGIC_VALUE as u64;
                }
                VIRTIO_MMIO_VERSION => {
                    value = 0x01;
                }
                VIRTIO_MMIO_DEVICE_ID => {
                    value = 0x01;
                }
                VIRTIO_MMIO_VENDOR_ID => {
                    value = 0x1AF4103F;
                }
                VIRTIO_MMIO_DEVICE_FEATURES => {
                    net.lock.lock();
                    if net.features_select == 1 {
                        value = 0;
                    } else {
                        value = VIRTIO_NET_F_MRG_RXBUF as u64;
                    }
                    net.lock.unlock();
                }
                VIRTIO_MMIO_QUEUE_NUM_MAX => {
                    value = 1024;
                }
                VIRTIO_MMIO_GUEST_PAGE_SIZE => {
                    net.lock.lock();
                    value = net.page_size as u64;
                    net.lock.unlock();
                }
                VIRTIO_MMIO_INTERRUPT_STATUS => {
                    net.lock.lock();
                    value = net.interrupt_status as u64;
                    net.lock.unlock();
                }
                VIRTIO_MMIO_STATUS => {
                    net.lock.lock();
                    value = net.status as u64;
                    net.lock.unlock();
                }
                VIRTIO_MMIO_QUEUE_PFN => {
                    net.lock.lock();
                    value = (net.queue[net.queue_selector as usize].get_descriptor_base_address()
                        / net.page_size) as u64;
                    net.lock.unlock();
                }
                _ => { /* Ignore */ }
            }
        } else if (0x100..=0x106).contains(&offset) {
            net.lock.lock();
            value = net.mac_address[offset - 0x100] as u64;
            net.lock.unlock();
        }
        LoadHookResult::Data(value)
    }

    fn store_handler(
        accessing_memory_address: usize,
        _: &mut GeneralPurposeRegisters,
        _: u8,
        data: u64,
        entry: &StoreAccessHandlerEntry,
    ) -> StoreHookResult {
        let offset = accessing_memory_address - entry.get_target_address();
        let net = Self::get_target_struct(
            cpu::mpidr_to_affinity(cpu::get_mpidr_el1()),
            entry.get_target_address(),
        )
        .unwrap_or_else(|| {
            Self::get_target_struct_bsp(entry.get_target_address())
                .expect("Failed to find the descriptor")
        });

        match offset {
            VIRTIO_MMIO_DEVICE_FEATURES_SEL => {
                net.lock.lock();
                net.features_select = data as u8;
                net.lock.unlock();
            }
            VIRTIO_MMIO_GUEST_PAGE_SIZE => {
                net.lock.lock();
                net.page_size = data as usize;
                net.lock.unlock();
            }
            VIRTIO_MMIO_QUEUE_SEL => {
                net.lock.lock();
                net.queue_selector = data as u8;
                net.lock.unlock();
            }
            VIRTIO_MMIO_QUEUE_NUM => {
                net.lock.lock();
                net.queue[net.queue_selector as usize].set_queue_size(
                    data as usize,
                    true,
                    net.page_size,
                );
                net.lock.unlock();
            }

            VIRTIO_MMIO_QUEUE_PFN => {
                net.lock.lock();
                net.queue[net.queue_selector as usize]
                    .set_packed_descriptor(data as usize, net.page_size);
                net.lock.unlock();
            }
            VIRTIO_MMIO_QUEUE_NOTIFY => {
                net.lock.lock();
                if net.queue_selector == 1 {
                    net.transmit(net.queue_selector);
                }
                net.lock.unlock();
            }
            VIRTIO_MMIO_INTERRUPT_ACK => {
                net.lock.lock();
                net.interrupt_status &= !(data as u8);
                net.lock.unlock();
            }
            VIRTIO_MMIO_STATUS => {
                net.lock.lock();
                net.status = data as u8;
                net.lock.unlock();
            }
            _ => { /* Ignore */ }
        }
        if (0x100..=0x106).contains(&offset) {
            net.lock.lock();
            net.mac_address[offset - 0x100] = data as u8;
            net.lock.unlock();
        }
        StoreHookResult::Cancel
    }
}
