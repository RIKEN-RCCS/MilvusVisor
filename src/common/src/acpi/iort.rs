// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! I/O Remapping Table
//!

#[repr(C, packed)]
pub struct IORT {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: [u8; 4],
    creator_revision: u32,
    number_of_iort_nodes: u32,
    offset_to_array_of_iort_nodes: u32,
    reserved: u32,
}

#[repr(C, packed)]
pub struct SmmuV3Node {
    s_type: u8,
    length: u16,
    revision: u8,
    id: u32,
    number_of_id_mappings: u32,
    reference_to_id_array: u32,
    base_address: u64,
    flag: u32,
    reserved: u32,
    vatos_address: u64,
    model: u32,
    event: u32,
    pri: u32,
    gerr: u32,
    sync: u32,
    proximity_domain: u32,
    device_id_mapping_index: u32,
}

pub struct IdMappingIter {
    p: usize,
    n: u32,
}

#[derive(Clone)]
#[repr(C)]
pub struct IdMapping {
    input_base: u32,
    number_of_ids: u32,
    output_base: u32,
    output_reference: u32,
    flags: u32,
}

impl IORT {
    pub const SIGNATURE: [u8; 4] = *b"IORT";

    pub fn get_smmu_v3_information(&self) -> Option<&SmmuV3Node> {
        let mut node_address =
            self as *const Self as usize + self.offset_to_array_of_iort_nodes as usize;
        for _ in 0..self.number_of_iort_nodes {
            if unsafe { *(node_address as *const u8) } == SmmuV3Node::NODE_TYPE {
                return Some(unsafe { &*(node_address as *const SmmuV3Node) });
            }
            node_address += unsafe { *((node_address + 1) as *const u16) } as usize;
        }
        None
    }
}

impl SmmuV3Node {
    const NODE_TYPE: u8 = 0x04;
    pub const fn get_base_address(&self) -> usize {
        self.base_address as usize
    }

    pub const fn get_number_of_mappings(&self) -> usize {
        self.number_of_id_mappings as usize
    }

    pub fn get_array_of_id_mappings(&self) -> IdMappingIter {
        IdMappingIter {
            p: self as *const _ as usize + self.reference_to_id_array as usize,
            n: self.number_of_id_mappings,
        }
    }
}

impl Iterator for IdMappingIter {
    type Item = IdMapping;

    fn next(&mut self) -> Option<Self::Item> {
        if self.n == 0 {
            None
        } else {
            let a = self.p;
            self.n -= 1;
            self.p += core::mem::size_of::<Self::Item>();
            Some(unsafe { &*(a as *const Self::Item) }.clone())
        }
    }
}

impl IdMapping {
    pub const fn get_output_base(&self) -> usize {
        self.output_base as usize
    }

    pub const fn get_output_reference(&self) -> usize {
        self.output_reference as usize
    }

    pub const fn get_number_of_ids(&self) -> usize {
        self.number_of_ids as usize
    }

    pub const fn is_single_map(&self) -> bool {
        (self.flags & 1) != 0
    }
}
