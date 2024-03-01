// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php
//!
//! Virtio Interface
//!
//! This module provides virtio common interface and virtio queue
//!

use core::mem::size_of;

pub(super) const VIRTIO_MMIO_MAGIC: usize = 0x000;
pub(super) const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x74726976;
pub(super) const VIRTIO_MMIO_VERSION: usize = 0x04;
pub(super) const VIRTIO_MMIO_DEVICE_ID: usize = 0x008;
pub(super) const VIRTIO_MMIO_VENDOR_ID: usize = 0x00c;
pub(super) const VIRTIO_MMIO_DEVICE_FEATURES: usize = 0x010;
pub(super) const VIRTIO_MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
pub(super) const VIRTIO_MMIO_GUEST_PAGE_SIZE: usize = 0x028;
pub(super) const VIRTIO_MMIO_QUEUE_SEL: usize = 0x030;
pub(super) const VIRTIO_MMIO_QUEUE_NUM_MAX: usize = 0x034;
pub(super) const VIRTIO_MMIO_QUEUE_NUM: usize = 0x038;
pub(super) const VIRTIO_MMIO_QUEUE_PFN: usize = 0x040;
pub(super) const VIRTIO_MMIO_QUEUE_NOTIFY: usize = 0x050;
pub(super) const VIRTIO_MMIO_INTERRUPT_STATUS: usize = 0x060;
pub(super) const VIRTIO_MMIO_INTERRUPT_ACK: usize = 0x064;
pub(super) const VIRTIO_MMIO_STATUS: usize = 0x070;

#[repr(C)]
pub(super) struct VirtQueueDesc {
    pub address: u64,
    pub length: u32,
    pub flags: u16,
    pub next: u16,
}

pub(super) const VIRT_QUEUE_DESC_FLAGS_NEXT: u16 = 1;
#[allow(dead_code)]
pub(super) const VIRT_QUEUE_DESC_FLAGS_WRITE: u16 = 1 << 1;

#[repr(C)]
pub(super) struct VirtQueueAvail {
    pub flags: u16,
    pub idx: u16,
}

#[repr(C)]
pub(super) struct VirtQueueUsedElement {
    pub id: u32,
    pub length: u32,
}

#[repr(C)]
pub(super) struct VirtQueueUsed {
    pub flags: u16,
    pub idx: u16,
}

pub(super) struct VirtQueue {
    descriptor: *mut VirtQueueDesc,
    avail_ring: *mut VirtQueueAvail,
    used_ring: *mut VirtQueueUsed,
    queue_size: usize,
    last_avail_id: u16,
    used_id: u16,
}

impl VirtQueue {
    pub(super) const fn new() -> Self {
        Self {
            descriptor: core::ptr::null_mut(),
            avail_ring: core::ptr::null_mut(),
            used_ring: core::ptr::null_mut(),
            queue_size: 0,
            last_avail_id: 0,
            used_id: 0,
        }
    }
    pub(super) fn get_descriptor(&self, id: u16) -> Option<VirtQueueDesc> {
        if !self.descriptor.is_null() {
            Some(unsafe {
                core::ptr::read_volatile(
                    (self.descriptor as usize + size_of::<VirtQueueDesc>() * (id as usize))
                        as *const VirtQueueDesc,
                )
            })
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub(super) const fn is_avail_ring_empty(&self) -> bool {
        self.last_avail_id == unsafe { &*self.avail_ring }.idx
    }

    pub(super) fn get_descriptor_base_address(&self) -> usize {
        self.descriptor as usize
    }

    pub(super) fn set_queue_size(
        &mut self,
        queue_size: usize,
        should_adjust_descriptors: bool,
        page_size: usize,
    ) {
        self.queue_size = queue_size;
        if should_adjust_descriptors {
            self.set_packed_descriptor(self.descriptor as usize, page_size);
        }
    }

    pub(super) fn set_packed_descriptor(&mut self, pfn: usize, page_size: usize) {
        let descriptor = pfn * page_size;
        self.descriptor = descriptor as *mut _;
        self.avail_ring = (descriptor + size_of::<VirtQueueDesc>() * self.queue_size) as *mut _;
        self.used_ring = ((((self.avail_ring as usize + size_of::<u16>() * (3 + self.queue_size))
            - 1)
            & !(page_size - 1))
            + page_size) as *mut _;
    }

    pub(super) fn get_descriptor_id(&self, id: u16) -> Option<u16> {
        if !self.avail_ring.is_null() {
            Some(unsafe {
                core::ptr::read_volatile(
                    (self.avail_ring as usize
                        + size_of::<VirtQueueAvail>()
                        + size_of::<u16>() * (id as usize)) as *const u16,
                )
            })
        } else {
            None
        }
    }

    pub(super) fn get_next_avail_id(&mut self) -> Option<u16> {
        if self.last_avail_id == unsafe { &*self.avail_ring }.idx {
            return None;
        }
        let next = self.last_avail_id % (self.queue_size as u16);
        self.last_avail_id += 1;
        Some(next)
    }

    pub(super) fn write_used(&mut self, id: u16, length: u32) {
        let used_id = self.used_id % (self.queue_size as u16);
        self.used_id += 1;
        unsafe {
            core::ptr::write_volatile(
                (self.used_ring as usize
                    + size_of::<VirtQueueUsed>()
                    + size_of::<VirtQueueUsedElement>() * (used_id as usize))
                    as *mut VirtQueueUsedElement,
                VirtQueueUsedElement {
                    id: (id as u32),
                    length,
                },
            )
        };
        unsafe { &mut *self.used_ring }.idx = self.used_id;
    }
}

pub(super) fn append_virtio_ssdt(
    rsdp_address: usize,
    device_name: [u8; 4],
    mmio_address: usize,
    int_id: u32,
) {
    const SSDT_TEMPLATE_SIZE: usize = 0x4B;
    let mut ssdt_template: [u8; SSDT_TEMPLATE_SIZE] = [
        0x10, 0x4a, 0x04, 0x5c, 0x5f, 0x53, 0x42, 0x5f, 0x5b, 0x82, 0x41, 0x04, 0x56, 0x4e, 0x54,
        0x30, 0x08, 0x5f, 0x48, 0x49, 0x44, 0x0d, 0x4c, 0x4e, 0x52, 0x4f, 0x30, 0x30, 0x30, 0x35,
        0x00, 0x08, 0x5f, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5f, 0x43, 0x43, 0x41, 0x01, 0x08, 0x5f,
        0x43, 0x52, 0x53, 0x11, 0x1a, 0x0a, 0x17, 0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0,
        0x00, 0x02, 0x00, 0x00, 0x89, 0x06, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x00, 0x79, 0x00,
    ];
    /// The offset of DEVICE NAME
    const DEVICE_NAME_OFFSET: usize = 12;
    /// The offset of MMIO Base Address
    const ADDRESS_OFFSET: usize = 56;
    /// The offset of Interrupt Number
    const INTID_OFFSET: usize = 69;

    /* Modify AML */
    for i in 0..4 {
        ssdt_template[DEVICE_NAME_OFFSET + i] = device_name[i];
    }
    if mmio_address > u32::MAX as usize {
        println!(
            "MMIO Base Address({:#X}) is not 32bit address",
            mmio_address
        );
        return;
    }
    for (e, i) in ssdt_template[ADDRESS_OFFSET..(ADDRESS_OFFSET + 4)]
        .iter_mut()
        .zip(mmio_address.to_le_bytes())
    {
        *e = i;
    }
    for (e, i) in ssdt_template[INTID_OFFSET..(INTID_OFFSET + 4)]
        .iter_mut()
        .zip(int_id.to_le_bytes())
    {
        *e = i;
    }

    /* Append */
    let Ok(ssdt) = common::acpi::get_acpi_table(rsdp_address, b"SSDT") else {
        println!("Failed to find SSDT");
        return;
    };
    let length = unsafe { &mut *((ssdt + 4) as *mut u32) };
    unsafe {
        core::ptr::copy_nonoverlapping(
            &ssdt_template as *const u8,
            (ssdt + (*length as usize)) as *mut u8,
            SSDT_TEMPLATE_SIZE,
        )
    };
    *length += SSDT_TEMPLATE_SIZE as u32;

    /* Calculate Checksum */
    let checksum = unsafe { &mut *((ssdt + 9) as *mut u8) };
    *checksum = 0;
    let mut s = 0i32;
    for i in 0..(*length as usize) {
        s = s.wrapping_add(unsafe { *((ssdt + i) as *const u8) } as i32);
    }
    *checksum = ((-s) & 0xff) as u8;
}
