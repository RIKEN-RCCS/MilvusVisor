// Copyright (c) 2022 RIKEN
// Copyright (c) 2023 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

const FDT_BEGIN_NODE: u32 = 0x00000001u32.to_be();
const FDT_END_NODE: u32 = 0x00000002u32.to_be();
const FDT_PROP: u32 = 0x00000003u32.to_be();
const FDT_NOP: u32 = 0x00000004u32.to_be();
const FDT_END: u32 = 0x00000009u32.to_be();
const TOKEN_SIZE: usize = 4;

const PROP_STATUS: &[u8] = "status".as_bytes();
const PROP_STATUS_OKAY: &[u8] = "okay".as_bytes();
const PROP_COMPATIBLE: &[u8] = "compatible".as_bytes();
const PROP_ADDRESS_CELLS: &[u8] = "#address-cells".as_bytes();
const PROP_SIZE_CELLS: &[u8] = "#size-cells".as_bytes();
const PROP_REG: &[u8] = "reg".as_bytes();

const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

#[repr(C)]
struct DtbHeader {
    magic: u32,
    total_size: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsv_map: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl DtbHeader {
    const DTB_MAGIC: u32 = 0xd00dfeedu32.to_be();
    pub fn check_magic(&self) -> bool {
        self.magic == Self::DTB_MAGIC
    }
}

#[derive(Clone)]
pub struct DtbNode {
    address_offset: usize,
    address_cells: u32,
    size_cells: u32,
    base_pointer: usize,
}

#[derive(Clone)]
pub struct DtbNodeNameSearchHolder {
    node: DtbNode,
    pointer: usize,
}

#[allow(dead_code)]
pub struct DtbAnalyser {
    struct_block_address: usize,
    struct_block_size: usize,
    strings_block_address: usize,
    strings_block_size: usize,
}

impl DtbNode {
    fn skip_nop(pointer: &mut usize) {
        while unsafe { *(*pointer as *const u32) } == FDT_NOP {
            *pointer += TOKEN_SIZE;
        }
        return;
    }

    fn skip_padding(pointer: &mut usize) -> Result<(), ()> {
        while (*pointer & (TOKEN_SIZE - 1)) != 0 {
            *pointer += 1;
        }
        return Ok(());
    }

    #[allow(dead_code)]
    fn match_name(mut pointer: usize, s: &[u8]) -> bool {
        for c in s {
            if unsafe { &*(pointer as *const u8) } != c {
                return false;
            }
            pointer += 1;
        }
        let last = unsafe { *(pointer as *const u8) };
        last == 0 || last == b'@'
    }

    fn match_string(mut pointer: usize, s: &[u8]) -> bool {
        for c in s {
            if unsafe { &*(pointer as *const u8) } != c {
                return false;
            }
            pointer += 1;
        }
        unsafe { *(pointer as *const u8) == 0 }
    }

    fn skip_to_end_of_node(pointer: &mut usize) -> Result<(), ()> {
        Self::skip_nop(pointer);
        if unsafe { *(*pointer as *const u32) } != FDT_BEGIN_NODE {
            println!(
                "Expected FDT_BEGIN_NODE, but found {:#X}",
                u32::from_be(unsafe { *(*pointer as *const u32) })
            );
            return Err(());
        }
        *pointer += TOKEN_SIZE;
        while unsafe { *(*pointer as *const u8) } != 0 {
            *pointer += 1;
        }
        *pointer += 1;
        Self::skip_padding(pointer)?;

        while unsafe { *(*pointer as *const u32) } != FDT_END_NODE {
            assert_eq!(*pointer & (TOKEN_SIZE - 1), 0);
            match unsafe { *(*pointer as *const u32) } {
                FDT_PROP => {
                    *pointer += TOKEN_SIZE;
                    let property_len = u32::from_be(unsafe { *(*pointer as *const u32) });
                    *pointer += core::mem::size_of::<u32>() * 2;
                    *pointer += property_len as usize;
                    Self::skip_padding(pointer)?;
                }
                FDT_BEGIN_NODE => {
                    Self::skip_to_end_of_node(pointer)?;
                }
                FDT_NOP => {}
                _ => {
                    println!(
                        "Expected TOKEN, but found {:#X}(Address: {:#X})",
                        u32::from_be(unsafe { *(*pointer as *const u32) }),
                        *pointer
                    );
                    return Err(());
                }
            }
            Self::skip_nop(pointer);
        }
        *pointer += TOKEN_SIZE;
        return Ok(());
    }

    fn add_offset(&mut self, mut regs: usize, regs_len: u32) {
        if regs_len == (self.address_cells + self.size_cells) * TOKEN_SIZE as u32 {
            let mut address_cells = 0usize;
            for _ in 0..self.address_cells {
                address_cells <<= u32::BITS;
                address_cells |= u32::from_be(unsafe { *(regs as *const u32) }) as usize;
                regs += TOKEN_SIZE;
            }
            self.address_offset += address_cells as usize;
        }
    }

    fn search_pointer_to_property(
        &mut self,
        target_prop_name: &[u8],
        dtb: &DtbAnalyser,
    ) -> Result<Option<(usize, u32)>, ()> {
        let mut pointer = self.base_pointer;
        Self::skip_nop(&mut pointer);
        if unsafe { *(pointer as *const u32) } != FDT_BEGIN_NODE {
            println!(
                "Expected FDT_BEGIN_NODE, but found {:#X}",
                u32::from_be(unsafe { *(pointer as *const u32) })
            );
            return Err(());
        }
        pointer += TOKEN_SIZE;
        while unsafe { *(pointer as *const u8) } != 0 {
            pointer += 1;
        }
        pointer += 1;
        Self::skip_padding(&mut pointer)?;

        while unsafe { *(pointer as *const u32) } != FDT_END_NODE {
            assert_eq!(pointer & (TOKEN_SIZE - 1), 0);
            match unsafe { *(pointer as *const u32) } {
                FDT_PROP => {
                    pointer += TOKEN_SIZE;
                    let property_len = u32::from_be(unsafe { *(pointer as *const u32) });
                    pointer += core::mem::size_of::<u32>();
                    let name_segment_offset = u32::from_be(unsafe { *((pointer) as *const u32) });
                    pointer += core::mem::size_of::<u32>();

                    let prop_name = dtb.get_name(name_segment_offset)?;
                    if Self::match_string(prop_name, PROP_ADDRESS_CELLS) {
                        self.address_cells = u32::from_be(unsafe { *(pointer as *const u32) });
                    } else if Self::match_string(prop_name, PROP_SIZE_CELLS) {
                        self.size_cells = u32::from_be(unsafe { *(pointer as *const u32) });
                    } else if Self::match_string(prop_name, target_prop_name) {
                        return Ok(Some((pointer, property_len)));
                    }

                    pointer += property_len as usize;
                    Self::skip_padding(&mut pointer)?;
                }
                FDT_BEGIN_NODE => {
                    Self::skip_to_end_of_node(&mut pointer)?;
                }
                FDT_NOP => {}
                _ => {
                    println!(
                        "Expected TOKEN, but found {:#X}(Offset from current node: {:#X})",
                        u32::from_be(unsafe { *(pointer as *const u32) }),
                        pointer - self.base_pointer
                    );
                    return Err(());
                }
            }
            Self::skip_nop(&mut pointer);
        }
        return Ok(None);
    }

    fn _search_device_by_node_name(
        &mut self,
        node_name: &[u8],
        dtb: &DtbAnalyser,
        pointer: &mut usize,
    ) -> Result<Option<Self>, ()> {
        Self::skip_nop(pointer);
        if unsafe { *(*pointer as *const u32) } != FDT_BEGIN_NODE {
            println!(
                "Expected FDT_BEGIN_NODE, but found {:#X}",
                u32::from_be(unsafe { *(*pointer as *const u32) })
            );
            return Err(());
        }
        *pointer += TOKEN_SIZE;

        let is_name_matched = Self::match_name(*pointer, node_name);

        while unsafe { *(*pointer as *const u8) } != 0 {
            *pointer += 1;
        }
        *pointer += 1;

        Self::skip_padding(pointer)?;

        self.__search_device_by_node_name(node_name, dtb, pointer, is_name_matched)
    }

    fn __search_device_by_node_name(
        &mut self,
        node_name: &[u8],
        dtb: &DtbAnalyser,
        pointer: &mut usize,
        is_name_matched: bool,
    ) -> Result<Option<Self>, ()> {
        let mut regs: usize = 0;
        let mut regs_len: u32 = 0;
        while unsafe { *(*pointer as *const u32) } != FDT_END_NODE {
            assert_eq!(*pointer & (TOKEN_SIZE - 1), 0);
            match unsafe { *(*pointer as *const u32) } {
                FDT_PROP => {
                    *pointer += TOKEN_SIZE;
                    let property_len = u32::from_be(unsafe { *(*pointer as *const u32) });
                    *pointer += core::mem::size_of::<u32>();
                    let name_segment_offset = u32::from_be(unsafe { *((*pointer) as *const u32) });
                    *pointer += core::mem::size_of::<u32>();

                    let prop_name = dtb.get_name(name_segment_offset)?;
                    if Self::match_string(prop_name, PROP_ADDRESS_CELLS) {
                        self.address_cells = u32::from_be(unsafe { *(*pointer as *const u32) });
                    } else if Self::match_string(prop_name, PROP_SIZE_CELLS) {
                        self.size_cells = u32::from_be(unsafe { *(*pointer as *const u32) });
                    } else if Self::match_string(prop_name, PROP_REG) {
                        regs = *pointer;
                        regs_len = property_len;
                    }

                    *pointer += property_len as usize;
                    Self::skip_padding(pointer)?;
                }
                FDT_BEGIN_NODE => {
                    if regs != 0 {
                        self.add_offset(regs, regs_len);
                        regs = 0;
                    }
                    if is_name_matched {
                        return Ok(Some(self.clone()));
                    }
                    let mut child = self.clone();
                    child.base_pointer = *pointer;
                    let result = child._search_device_by_node_name(node_name, dtb, pointer)?;
                    if result.is_some() {
                        return Ok(result);
                    }
                }
                FDT_NOP => {}
                _ => {
                    println!(
                        "Expected TOKEN, but found {:#X}(Offset from current node: {:#X})",
                        u32::from_be(unsafe { *(*pointer as *const u32) }),
                        *pointer - self.base_pointer
                    );
                    return Err(());
                }
            }
            Self::skip_nop(pointer);
        }
        if regs != 0 {
            self.add_offset(regs, regs_len);
        }
        if is_name_matched {
            return Ok(Some(self.clone()));
        }
        *pointer += TOKEN_SIZE;
        return Ok(None);
    }

    fn _search_device_by_compatible(
        &mut self,
        compatible_devices: &[&[u8]],
        dtb: &DtbAnalyser,
        pointer: &mut usize,
    ) -> Result<Option<(Self, usize)>, ()> {
        Self::skip_nop(pointer);

        if unsafe { *(*pointer as *const u32) } != FDT_BEGIN_NODE {
            println!(
                "Expected FDT_BEGIN_NODE, but found {:#X}",
                u32::from_be(unsafe { *(*pointer as *const u32) })
            );
            return Err(());
        }
        *pointer += TOKEN_SIZE;

        while unsafe { *(*pointer as *const u8) } != 0 {
            *pointer += 1;
        }
        *pointer += 1;

        Self::skip_padding(pointer)?;

        self.__search_device_by_compatible(compatible_devices, dtb, pointer)
    }

    fn __search_device_by_compatible(
        &mut self,
        compatible_devices: &[&[u8]],
        dtb: &DtbAnalyser,
        pointer: &mut usize,
    ) -> Result<Option<(Self, usize)>, ()> {
        let mut compatible_index: Option<usize> = None;
        let mut regs: usize = 0;
        let mut regs_len: u32 = 0;

        while unsafe { *(*pointer as *const u32) } != FDT_END_NODE {
            assert_eq!(*pointer & (TOKEN_SIZE - 1), 0);
            match unsafe { *(*pointer as *const u32) } {
                FDT_PROP => {
                    *pointer += TOKEN_SIZE;
                    let property_len = u32::from_be(unsafe { *(*pointer as *const u32) });
                    *pointer += core::mem::size_of::<u32>();
                    let name_segment_offset = u32::from_be(unsafe { *((*pointer) as *const u32) });
                    *pointer += core::mem::size_of::<u32>();

                    let prop_name = dtb.get_name(name_segment_offset)?;
                    if Self::match_string(prop_name, PROP_COMPATIBLE) {
                        let mut list_pointer = 0usize;
                        'list_loop: while list_pointer < property_len as usize {
                            for (index, c_d) in compatible_devices.iter().enumerate() {
                                if Self::match_string(*pointer + list_pointer, c_d) {
                                    compatible_index = Some(index);
                                    break 'list_loop;
                                }
                            }
                            while unsafe { *((*pointer + list_pointer) as *const u8) } != 0 {
                                list_pointer += 1;
                            }
                            list_pointer += 1;
                        }
                    } else if Self::match_string(prop_name, PROP_ADDRESS_CELLS) {
                        self.address_cells = u32::from_be(unsafe { *(*pointer as *const u32) });
                    } else if Self::match_string(prop_name, PROP_SIZE_CELLS) {
                        self.size_cells = u32::from_be(unsafe { *(*pointer as *const u32) });
                    } else if Self::match_string(prop_name, PROP_REG) {
                        regs = *pointer;
                        regs_len = property_len;
                    }
                    *pointer += property_len as usize;
                    Self::skip_padding(pointer)?;
                }
                FDT_BEGIN_NODE => {
                    if regs != 0 {
                        self.add_offset(regs, regs_len);
                        regs = 0;
                    }
                    if let Some(index) = compatible_index {
                        return Ok(Some((self.clone(), index)));
                    }
                    let mut child = self.clone();
                    child.base_pointer = *pointer;
                    let result =
                        child._search_device_by_compatible(compatible_devices, dtb, pointer)?;
                    if result.is_some() {
                        return Ok(result);
                    }
                }
                FDT_NOP => {}
                _ => {
                    println!(
                        "Expected TOKEN, but found {:#X}(Offset from current node: {:#X})",
                        u32::from_be(unsafe { *(*pointer as *const u32) }),
                        *pointer - self.base_pointer
                    );
                    return Err(());
                }
            }
            Self::skip_nop(pointer);
        }
        if regs != 0 {
            self.add_offset(regs, regs_len);
        }
        if let Some(index) = compatible_index {
            return Ok(Some((self.clone(), index)));
        }
        *pointer += TOKEN_SIZE;
        return Ok(None);
    }

    pub fn get_search_holder(&self) -> Result<DtbNodeNameSearchHolder, ()> {
        let mut pointer = self.base_pointer;
        Self::skip_nop(&mut pointer);
        if unsafe { *(pointer as *const u32) } != FDT_BEGIN_NODE {
            println!(
                "Expected FDT_BEGIN_NODE, but found {:#X}",
                u32::from_be(unsafe { *(pointer as *const u32) })
            );
            return Err(());
        }
        pointer += TOKEN_SIZE;

        while unsafe { *(pointer as *const u8) } != 0 {
            pointer += 1;
        }
        pointer += 1;
        Self::skip_padding(&mut pointer)?;

        Ok(DtbNodeNameSearchHolder {
            node: self.clone(),
            pointer,
        })
    }

    pub fn is_status_okay(&self, dtb: &DtbAnalyser) -> Result<Option<bool>, ()> {
        let mut s = self.clone();
        if let Some((p, _)) = s.search_pointer_to_property(PROP_STATUS, dtb)? {
            Ok(Some(Self::match_string(p, PROP_STATUS_OKAY)))
        } else {
            // A node is enabled if status property does not exist.
            Ok(Some(true))
        }
    }

    pub fn get_offset(&self) -> usize {
        self.address_offset
    }

    pub fn get_prop_as_u32(
        &self,
        prop_name: &[u8],
        dtb: &DtbAnalyser,
    ) -> Result<Option<&[u32]>, ()> {
        let mut s = self.clone();
        if let Some((p, len)) = s.search_pointer_to_property(prop_name, dtb)? {
            Ok(Some(unsafe {
                core::slice::from_raw_parts(
                    p as *const u32,
                    len as usize / core::mem::size_of::<u32>(),
                )
            }))
        } else {
            Ok(None)
        }
    }
}

impl DtbNodeNameSearchHolder {
    #[allow(dead_code)]
    pub fn search_next_device_by_node_name(
        &mut self,
        node_name: &[u8],
        dtb: &DtbAnalyser,
    ) -> Result<Option<DtbNode>, ()> {
        let result =
            self.node
                .__search_device_by_node_name(node_name, dtb, &mut self.pointer, false)?;
        if let Some(t) = &result {
            self.pointer = t.base_pointer;
            DtbNode::skip_to_end_of_node(&mut self.pointer)?;
        } else {
            if unsafe { *(self.pointer as *const u32) } != FDT_END {
                if self.pointer >= dtb.get_struct_block_limit() {
                    println!("Broken DTB");
                    return Err(());
                }
                self.node = dtb.get_root_node();
                self.node.base_pointer = self.pointer;
                return self.search_next_device_by_node_name(node_name, dtb);
            }
        }
        return Ok(result);
    }

    pub fn search_next_device_by_compatible(
        &mut self,
        compatible_devices: &[&[u8]],
        dtb: &DtbAnalyser,
    ) -> Result<Option<(DtbNode, usize)>, ()> {
        let result =
            self.node
                .__search_device_by_compatible(compatible_devices, dtb, &mut self.pointer)?;
        if let Some((t, _)) = &result {
            self.pointer = t.base_pointer;
            DtbNode::skip_to_end_of_node(&mut self.pointer)?;
        } else {
            if unsafe { *(self.pointer as *const u32) } != FDT_END {
                if self.pointer >= dtb.get_struct_block_limit() {
                    println!("Broken DTB");
                    return Err(());
                }
                self.node = dtb.get_root_node();
                self.node.base_pointer = self.pointer;
                return self.search_next_device_by_compatible(compatible_devices, dtb);
            }
        }
        return Ok(result);
    }
}

impl DtbAnalyser {
    pub fn new(base_address: usize) -> Result<Self, ()> {
        let dtb_header = unsafe { &*(base_address as *const DtbHeader) };
        if !dtb_header.check_magic() {
            println!("Failed to check magic code.");
            return Err(());
        }
        Ok(Self {
            struct_block_address: base_address + u32::from_be(dtb_header.off_dt_struct) as usize,
            struct_block_size: u32::from_be(dtb_header.size_dt_struct) as usize,
            strings_block_address: base_address + u32::from_be(dtb_header.off_dt_strings) as usize,
            strings_block_size: u32::from_be(dtb_header.size_dt_strings) as usize,
        })
    }

    pub fn get_root_node(&self) -> DtbNode {
        DtbNode {
            address_offset: 0,
            address_cells: DEFAULT_ADDRESS_CELLS,
            size_cells: DEFAULT_SIZE_CELLS,
            base_pointer: self.struct_block_address,
        }
    }

    fn get_name(&self, offset_of_segments: u32) -> Result<usize, ()> {
        if self.strings_block_size > offset_of_segments as usize {
            Ok(self.strings_block_address + offset_of_segments as usize)
        } else {
            Err(())
        }
    }

    fn get_struct_block_limit(&self) -> usize {
        self.struct_block_size + self.struct_block_address
    }
}

#[cfg(feature = "edit_dtb_memory")]
pub fn add_new_memory_reservation_entry_to_dtb(
    original_base_address: usize,
    new_base_address: usize,
    new_size: usize,
    reserved_address: usize,
    reserved_size: usize,
) -> Result<usize, ()> {
    let mut total_new_size = 0;
    let original_dtb_header = unsafe { &*(original_base_address as *const DtbHeader) };

    let new_dtb_header = unsafe { &mut *(new_base_address as *mut DtbHeader) };
    total_new_size += core::mem::size_of::<DtbHeader>();
    if new_size < total_new_size {
        return Err(());
    }

    new_dtb_header.magic = original_dtb_header.magic;
    new_dtb_header.version = original_dtb_header.version;
    new_dtb_header.last_comp_version = original_dtb_header.last_comp_version;
    new_dtb_header.boot_cpuid_phys = original_dtb_header.boot_cpuid_phys;
    new_dtb_header.size_dt_struct = original_dtb_header.size_dt_struct;
    new_dtb_header.size_dt_strings = original_dtb_header.size_dt_strings;

    // copy memory reservation block and add new reservation entry
    let original_reservation_block_address =
        original_base_address + u32::from_be(original_dtb_header.off_mem_rsv_map) as usize;
    let new_reservation_block_address = new_base_address + total_new_size;
    let mut pointer = original_reservation_block_address;
    loop {
        let address = unsafe { *(pointer as *const u64) };
        pointer += core::mem::size_of::<u64>();
        let size = unsafe { *(pointer as *const u64) };
        pointer += core::mem::size_of::<u64>();
        if address == 0 && size == 0 {
            break;
        }
    }
    // original reservation block size without terminal entry
    let reservation_block_section_size =
        pointer - original_reservation_block_address - core::mem::size_of::<u64>() * 2;
    // new total size will be  the size of original reservation block + new entry + terminal entry
    total_new_size += reservation_block_section_size + core::mem::size_of::<u64>() * 4;
    if new_size < total_new_size {
        return Err(());
    }
    unsafe {
        // copy original mrb to new mrb
        core::ptr::copy_nonoverlapping(
            original_reservation_block_address as *const u8,
            new_reservation_block_address as *mut u8,
            reservation_block_section_size,
        );
    }
    unsafe {
        // write new entries
        let new_reservation_entry_address_filed_address =
            new_reservation_block_address + reservation_block_section_size;
        let new_reservation_entry_size_field_address = new_reservation_block_address
            + reservation_block_section_size
            + core::mem::size_of::<u64>();
        *(new_reservation_entry_address_filed_address as *mut usize) = reserved_address.to_be();
        *(new_reservation_entry_size_field_address as *mut usize) = reserved_size.to_be();
        let new_termianal_entry_address = new_reservation_block_address
            + reservation_block_section_size
            + core::mem::size_of::<u64>() * 2;
        *(new_termianal_entry_address as *mut usize) = 0;
        *((new_termianal_entry_address + core::mem::size_of::<u64>()) as *mut usize) = 0;
    }

    // copy struct section
    let new_struct_base_address = new_base_address + total_new_size;
    let original_struct_base_address =
        original_base_address + u32::from_be(original_dtb_header.off_dt_struct) as usize;
    let struct_section_size = u32::from_be(original_dtb_header.size_dt_struct) as usize;
    total_new_size += struct_section_size;
    if total_new_size > new_size {
        return Err(());
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            original_struct_base_address as *const u8,
            new_struct_base_address as *mut u8,
            struct_section_size,
        );
    }

    // copy string section
    let new_string_section_address = new_base_address + total_new_size;
    let original_string_section_address =
        original_base_address + u32::from_be(original_dtb_header.off_dt_strings) as usize;
    let string_section_size = u32::from_be(original_dtb_header.size_dt_strings) as usize;
    total_new_size += string_section_size;
    if total_new_size > new_size {
        return Err(());
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            original_string_section_address as *const u8,
            new_string_section_address as *mut u8,
            u32::from_be(original_dtb_header.size_dt_strings) as usize,
        );
    }

    // edit header
    new_dtb_header.off_mem_rsv_map =
        ((new_reservation_block_address - new_base_address) as u32).to_be();
    new_dtb_header.off_dt_struct = ((new_struct_base_address - new_base_address) as u32).to_be();
    new_dtb_header.off_dt_strings =
        ((new_string_section_address - new_base_address) as u32).to_be();
    new_dtb_header.total_size = (total_new_size as u32).to_be();

    Ok(total_new_size)
}
