// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php
//!
//! Virtio Device Interface
//!
//! This module provides virtio network device interface.
//!
//! This is an experimental implementation.
//! It may be not able to create virtio device on some devices.
//!

use core::mem::size_of;
use core::num::NonZeroUsize;

use common::spin_flag::SpinLockFlag;
use common::GeneralPurposeRegisters;

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

///
/// Providing interface to communicate with OS
///
/// This device provides low layer interface of virtio network.
/// [`VirtioNetwork::create_new_device`] creates a virtio network device over MMIO.
/// It handles send/receive ethernet frames, but it does not contain TCP/IP protocol stacks(must be implemented by yourself).
///
/// By registering `callback` you can receive ethernet frames when you OS writes.
/// If you want to reply while processing, you can use `send_frame` closure passed as the second argument.
/// **In the `callback`, do not use [`VirtioNetwork::send_frame`] directly due to avoid deadlocking.**
///
/// When you will send the frames out of `callback`, use [`VirtioNetwork::send_frame`].
///
/// # Example
///
/// ```rust
/// /// The function will be called when OS sends ethernet frames.
/// /// `frame` contains a ethernet frame, `send_frame` is a function pointer to replay
/// fn receive(frame: &[u8], send_frame: &mut dyn FnMut(&[u8]) -> Result<(), ()>) {
///   println!("Received: {:#X?}", frame);
///   // Echo back same ethernet frame to OS, it does not mean anything usually.
///   let _ = (send_frame)(frame);
/// }
///
/// VirtioNetwork::create_new_device(
///   0x45000000, // Base Address of MMIO, the size of MMIO is VirtioNetwork::MMIO_SIZE
///   40, // INT_ID assigned for this device, select the number which is not used by physical devices
///   receive, // The function pointer to receive handler
///   acpi_rsdp_address, // The RSDP address, it is used to notify the MMIO area to OS
///   1, // The number to generate device name, it must be unique in virtio devices
///  ).expect("Failed to create virtio network");
/// ```
pub struct VirtioNetwork {
    lock: SpinLockFlag,
    int_id: u32,
    page_size: usize,
    queue_selector: u8,
    queue: [VirtQueue; 2],
    interrupt_status: u8,
    status: u8,
    mac_address: [u8; 6],
    features_select: u8,
    //base_address: usize,
    callback: fn(frame: &[u8], send_frame: &mut dyn FnMut(&[u8]) -> Result<(), ()>),
}

impl VirtioNetwork {
    /// The size of MMIO handled by this implementation
    pub const MMIO_SIZE: usize = 0x100;

    /// Create a virtio network device and register
    ///
    /// This function allocate memory for [`VirtioNetwork`] and add memory trap at `base_address`.
    /// If `rsdp_address` is available, this will append AML(ACPI Machine Language) to notify the device information to OS.
    ///
    /// # Arguments
    /// * `base_address`: The address this device can occupy.
    ///                   `base_address` ~ (`base_address` + [`Self::MMIO_SIZE`] - 1) will be trapped and handled.
    ///                   The area must be usable and reserved.
    /// * `int_id`: INT_ID used by this device when it wants to interrupt. `int_id` must not be used by physical devices.
    /// * `callback`: The function pointer to handle received frames. This function is called with two arguments.
    ///               First argument(`frame`) is the array of the received frame, second(`send_frame`) is a closure
    ///               which should be used to send a frame, its arguments and results is same as [`VirtioNetwork::send_frame`].
    /// * `rsdp_address`: The ACPI's RSD pointer. If it is available, this will generate AML and append to SSDT.
    /// * `device_suffix`: A number which is unique between virtio network devices. Ignored if `rsdp_address` is None.
    ///
    /// # Result
    /// If it is failed to create virtio device, this will return `Err(())`,
    /// otherwise this returns a mutable reference of the created device.
    ///
    /// **Note: if failed to append AML to SSDT,  this will not return Err**
    pub fn create_new_device(
        base_address: usize,
        int_id: u32,
        receive_callback: fn(frame: &[u8], send_frame: &mut dyn FnMut(&[u8]) -> Result<(), ()>),
        rsdp_address: Option<NonZeroUsize>,
        device_suffix: u8,
    ) -> Result<&'static mut Self, ()> {
        if device_suffix > 0xF {
            println!("Device Suffix({:#X}) is invalid", device_suffix);
            return Err(());
        }

        let device = crate::allocate_memory(1, None);
        if let Err(e) = device {
            println!("Failed to allocate memory: {:?}", e);
            return Err(());
        }
        let device = unsafe { &mut *(device.unwrap() as *mut Self) };
        *device = Self {
            lock: SpinLockFlag::new(),
            int_id,
            page_size: 0x1000,
            queue_selector: 0,
            queue: [VirtQueue::new(), VirtQueue::new()],
            interrupt_status: 0,
            status: 0,
            mac_address: [0; 6],
            features_select: 0,
            //base_address,
            callback: receive_callback,
        };

        if paging::add_memory_access_trap(
            base_address & common::STAGE_2_PAGE_MASK,
            common::STAGE_2_PAGE_SIZE,
            false,
            false,
        )
        .is_err()
        {
            println!("Failed to setup memory trap.");
            let _ = crate::free_memory(device as *mut _ as usize, 1);
            return Err(());
        };
        if add_memory_load_access_handler(LoadAccessHandlerEntry::new(
            base_address,
            Self::MMIO_SIZE,
            device as *mut _ as usize,
            Self::load_handler,
        ))
        .is_err()
        {
            println!("Failed to add the handler");
            let _ = crate::free_memory(device as *mut _ as usize, 1);
            return Err(());
        };
        if add_memory_store_access_handler(StoreAccessHandlerEntry::new(
            base_address,
            Self::MMIO_SIZE,
            device as *mut _ as usize,
            Self::store_handler,
        ))
        .is_err()
        {
            println!("Failed to add the handler");
            let _ = crate::free_memory(device as *mut _ as usize, 1);
            return Err(());
        }

        if let Some(rsdp) = rsdp_address {
            let suffix = if device_suffix <= 9 {
                b'0' + device_suffix
            } else {
                b'A' + (device_suffix - 0xA)
            };
            append_virtio_ssdt(rsdp.get(), [b'V', b'N', b'T', suffix], base_address, int_id);
        }
        Ok(device)
    }

    /// The handler to receive ethernet frames from the OS
    fn receive_frames(&mut self, queue_id: u8) -> Result<u32, ()> {
        assert!(self.lock.is_locked());
        let mut number_of_frames = 0;
        let mut is_sent_frames = false;
        if queue_id as usize >= self.queue.len() {
            println!("Queue id({:#X}) is invalid", queue_id);
            return Err(());
        }

        while let Some(id) = self.queue[queue_id as usize].get_next_avail_id() {
            let Some(request_descriptor_id) = self.queue[queue_id as usize].get_descriptor_id(id)
            else {
                println!("Failed to get next descriptor id");
                return Err(());
            };
            let Some(request_descriptor) =
                self.queue[queue_id as usize].get_descriptor(request_descriptor_id)
            else {
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

                (self.callback)(
                    unsafe { core::slice::from_raw_parts(frame as *const u8, size) },
                    &mut |frame: &[u8]| -> Result<(), ()> {
                        is_sent_frames = true;
                        Self::_send_frame(&mut self.queue[0], frame)
                    },
                );
                if (request_descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) == 0 {
                    self.queue[queue_id as usize]
                        .write_used(request_descriptor_id, total_size as u32);
                    continue;
                }
            }
            if (request_descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) == 0 {
                println!("Invalid Request: Broken Descriptor");
                return Err(());
            }

            loop {
                let Some(descriptor) = self.queue[queue_id as usize].get_descriptor(descriptor_id)
                else {
                    println!("Failed to get next descriptor");
                    return Err(());
                };
                let frame = descriptor.address as usize;
                let size = descriptor.length as usize;
                total_size += size;
                number_of_frames += 1;

                (self.callback)(
                    unsafe { core::slice::from_raw_parts(frame as *const u8, size) },
                    &mut |frame: &[u8]| -> Result<(), ()> {
                        is_sent_frames = true;
                        Self::_send_frame(&mut self.queue[0], frame)
                    },
                );
                if (descriptor.flags & VIRT_QUEUE_DESC_FLAGS_NEXT) != 0 {
                    descriptor_id = descriptor.next;
                } else {
                    break;
                }
            }
            self.queue[queue_id as usize].write_used(request_descriptor_id, total_size as u32);
        }
        if number_of_frames > 0 {
            self.trigger_interrupt(1);
        }
        if is_sent_frames {
            self.trigger_interrupt(0);
        }

        Ok(number_of_frames)
    }

    /// Send ethernet frames to guest
    ///
    /// # Arguments
    /// * frame: the array to send
    ///
    /// # Result
    /// If failed to send the frame, this will return Err(())
    #[allow(dead_code)]
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), ()> {
        self.lock.lock();
        if !self.is_ready() {
            println!("Device is not ready.");
            self.lock.unlock();
            return Err(());
        }
        let result = Self::_send_frame(&mut self.queue[0], frame);
        if result.is_ok() {
            self.trigger_interrupt(0);
        }
        self.lock.unlock();
        result
    }

    fn _send_frame(queue: &mut VirtQueue, frame: &[u8]) -> Result<(), ()> {
        /*
         */
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
                //self.lock.unlock();
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
        let device_address = entry.get_data();
        if device_address == 0 {
            println!("There is not device to handle");
            return LoadHookResult::Data(0);
        }
        let net = unsafe { &*(device_address as *const VirtioNetwork) };

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
        } else {
            if 0x100 <= offset && offset <= 0x106 {
                net.lock.lock();
                value = net.mac_address[offset - 0x100] as u64;
                net.lock.unlock();
            }
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
        let device_address = entry.get_data();
        if device_address == 0 {
            println!("There is not device to handle");
            return StoreHookResult::Cancel;
        }
        let net = unsafe { &mut *(device_address as *mut VirtioNetwork) };

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
                    let _ = net.receive_frames(net.queue_selector);
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
        if 0x100 <= offset && offset <= 0x106 {
            net.lock.lock();
            net.mac_address[offset - 0x100] = data as u8;
            net.lock.unlock();
        }
        StoreHookResult::Cancel
    }
}
