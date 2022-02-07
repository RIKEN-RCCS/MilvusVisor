//!
//!  Multiple APIC Description Table
//!
//! Supported MADT Revision: ~ 5

pub const MADT_SIGNATURE: [u8; 4] = *b"APIC";

const MADT_STRUCT_SIZE: usize = core::mem::size_of::<MADT>();

const STRUCT_TYPE_GICC: u8 = 0xB;

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
struct GicCpuInterfaceStructure {
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

/// MADTのリストから順次GicCpuInterfaceStructureを検出し、MPIDRを返却するIterです
///
/// このIteratorはMADTのInterrupt Controller Structure配列からGicCpuInterfaceStructureを先頭から順に
/// 取得し、その中にあるMPIDRの値を返します。なお該当MPIDRが有効でない([`GICC_FLAGS_ENABLED`]が立ってない)
/// 場合はスキップします。
pub struct ProcessorIdIter {
    base_address: usize,
    pointer: usize,
    length: usize,
}

impl MADT {
    pub fn get_processor_id_list(&self) -> ProcessorIdIter {
        let length = self.length as usize - MADT_STRUCT_SIZE;
        let base_address = self as *const _ as usize + MADT_STRUCT_SIZE;

        ProcessorIdIter {
            base_address,
            pointer: 0,
            length,
        }
    }
}

impl Iterator for ProcessorIdIter {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pointer >= self.length {
            return None;
        }
        let record_base = self.base_address + self.pointer;
        let record_type = unsafe { *(record_base as *const u8) };
        let record_length = unsafe { *((record_base + 1) as *const u8) };

        self.pointer += record_length as usize;
        match record_type {
            STRUCT_TYPE_GICC => {
                let gicc_struct = unsafe { &*(record_base as *const GicCpuInterfaceStructure) };
                if (gicc_struct.flags & GICC_FLAGS_ENABLED) != 0 {
                    /* Enabled */
                    Some(gicc_struct.mpidr)
                } else {
                    self.next()
                }
            }
            _ => self.next(),
        }
    }
}
