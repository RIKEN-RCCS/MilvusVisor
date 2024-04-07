// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//!  Multiple APIC Description Table
//!
//! Supported MADT Revision: ~ 5

const STRUCT_TYPE_GICC: u8 = 0x0B;
const STRUCT_TYPE_GICD: u8 = 0x0C;
const STRUCT_TYPE_ITS: u8 = 0x0F;

const GICC_FLAGS_ENABLED: u32 = 1;

#[repr(C, packed)]
pub struct MADT {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: [u8; 4],
    creator_revision: u32,
    flags: u32,
    local_interrupt_controller_address: u32,
    /* interrupt_controller_structure: [struct; n] */
}

#[repr(C, packed)]
pub struct GicCpuInterfaceStructure {
    struct_type: u8,
    length: u8,
    reserved_1: [u8; 2],
    cpu_interface_number: u32,
    acpi_processor_uid: u32,
    flags: u32,
    parking_protocol_version: u32,
    performance_interrupt_gsiv: u32,
    parked_address: u64,
    physical_base_address: u64,
    gicv: u64,
    gich: u64,
    vgic_maintenance_interrupt: u32,
    gicr_base_address: u64,
    mpidr: u64,
    processor_power_efficiency_class: u8,
    reserved_2: u8,
    spe_overflow_interrupt: u16,
}

/// The iterator to get MPIDR which is enabled(`GICC_FLAGS_ENABLED` is enabled)
pub struct GicCpuInterfaceStructureList {
    pointer: usize,
    limit: usize,
}

pub struct GicInterruptTranslationServiceStructureList {
    pointer: usize,
    limit: usize,
}

impl MADT {
    pub const SIGNATURE: [u8; 4] = *b"APIC";
    const STRUCT_SIZE: usize = core::mem::size_of::<MADT>();

    pub fn get_gic_list(&self) -> GicCpuInterfaceStructureList {
        let length = self.length as usize - Self::STRUCT_SIZE;
        let pointer = self as *const _ as usize + Self::STRUCT_SIZE;

        GicCpuInterfaceStructureList {
            pointer,
            limit: pointer + length,
        }
    }

    pub fn get_gic_distributor_address(&self) -> Option<(u8, usize)> {
        let mut base_address = self as *const _ as usize + Self::STRUCT_SIZE;
        let limit = base_address + (self.length as usize - Self::STRUCT_SIZE);
        while base_address < limit {
            let record_type = unsafe { *(base_address as *const u8) };
            let record_length = unsafe { *((base_address + 1) as *const u8) };
            if record_type == STRUCT_TYPE_GICD {
                return unsafe {
                    Some((
                        *((base_address + 20) as *const u8),
                        *((base_address + 8) as *const u64) as usize,
                    ))
                };
            }
            base_address += record_length as usize;
        }
        return None;
    }

    pub fn get_gic_its_list(&self) -> GicInterruptTranslationServiceStructureList {
        let length = self.length as usize - Self::STRUCT_SIZE;
        let pointer = self as *const _ as usize + Self::STRUCT_SIZE;

        GicInterruptTranslationServiceStructureList {
            pointer,
            limit: pointer + length,
        }
    }
}

impl Iterator for GicCpuInterfaceStructureList {
    type Item = &'static GicCpuInterfaceStructure;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pointer >= self.limit {
            return None;
        }
        let record_base = self.pointer;
        let record_type = unsafe { *(record_base as *const u8) };
        let record_length = unsafe { *((record_base + 1) as *const u8) };

        self.pointer += record_length as usize;
        match record_type {
            STRUCT_TYPE_GICC => {
                let gicc_struct = unsafe { &*(record_base as *const GicCpuInterfaceStructure) };
                if (gicc_struct.flags & GICC_FLAGS_ENABLED) != 0 {
                    /* Enabled */
                    Some(gicc_struct)
                } else {
                    self.next()
                }
            }
            _ => self.next(),
        }
    }
}

impl GicCpuInterfaceStructure {
    pub const fn get_gic_redistributor_base_address(&self) -> usize {
        self.gicr_base_address as usize
    }
}

impl Iterator for GicInterruptTranslationServiceStructureList {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pointer >= self.limit {
            return None;
        }
        let record_base = self.pointer;
        let record_type = unsafe { *(record_base as *const u8) };
        let record_length = unsafe { *((record_base + 1) as *const u8) };

        self.pointer += record_length as usize;
        match record_type {
            STRUCT_TYPE_ITS => Some(unsafe { *((record_base + 8) as *const u64) } as usize),
            _ => self.next(),
        }
    }
}
