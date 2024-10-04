// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Executable and Linkable Format
//!
//! Supported Version: 1

const EI_NIDENT: usize = 16;
pub const ELF_IDENTIFIER: [u8; EI_NIDENT] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EM_AARCH64: Elf64Half = 183;
const PT_LOAD: Elf64Word = 1;
const ELF_VERSION: Elf64Word = 0x1;

type Elf64Addr = u64;
type Elf64Half = u16;
type Elf64Off = u64;
//type Elf64Sword = i32;
//type Elf64Sxword = i64;
type Elf64Word = u32;
//type Elf64Lword = u64;
type Elf64Xword = u64;

#[repr(C)]
pub struct Elf64Header {
    e_ident: [u8; EI_NIDENT],
    e_type: Elf64Half,
    e_machine: Elf64Half,
    e_version: Elf64Word,
    e_entry: Elf64Addr,
    e_phoff: Elf64Off,
    e_shoff: Elf64Off,
    e_flags: Elf64Word,
    e_ehsize: Elf64Half,
    e_phentsize: Elf64Half,
    e_phnum: Elf64Half,
    e_shentsize: Elf64Half,
    e_shnum: Elf64Half,
    e_shstrndx: Elf64Half,
}

#[repr(C)]
struct Elf64ProgramHeader {
    p_type: Elf64Word,
    p_flags: Elf64Word,
    p_offset: Elf64Off,
    p_vaddr: Elf64Addr,
    p_paddr: Elf64Addr,
    p_filesz: Elf64Xword,
    p_memsz: Elf64Xword,
    p_align: Elf64Xword,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub virtual_base_address: usize,
    pub physical_base_address: usize,
    pub file_offset: usize,
    pub memory_size: usize,
    pub file_size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Elf64Header {
    pub fn check_elf_header(&self) -> bool {
        if self.e_ident != ELF_IDENTIFIER {
            println!("Invalid elf identifier: {:?}", self.e_ident);
            return false;
        }
        if self.e_machine != EM_AARCH64 {
            println!("Target machine is not matched: {}", self.e_machine);
            return false;
        }
        if self.e_version < ELF_VERSION {
            println!("Unsupported ELF version: {}", self.e_version);
            return false;
        }
        true
    }

    pub fn get_entry_point(&self) -> usize {
        self.e_entry as usize
    }

    pub fn get_num_of_program_header_entries(&self) -> usize {
        self.e_phnum as usize
    }

    pub fn get_program_header_offset(&self) -> usize {
        self.e_phoff as usize
    }

    pub fn get_program_header_entry_size(&self) -> usize {
        self.e_phentsize as usize
    }

    pub fn get_segment_info(
        &self,
        index: usize,
        program_header_base: usize,
    ) -> Option<SegmentInfo> {
        if self.get_num_of_program_header_entries() <= index {
            return None;
        }
        let program_header = unsafe {
            &*((program_header_base + index * (self.e_phentsize as usize))
                as *const Elf64ProgramHeader)
        };
        if program_header.p_type == PT_LOAD {
            Some(SegmentInfo {
                file_offset: program_header.p_offset as usize,
                virtual_base_address: program_header.p_vaddr as usize,
                physical_base_address: program_header.p_paddr as usize,
                memory_size: program_header.p_memsz as usize,
                file_size: program_header.p_filesz as usize,
                readable: (program_header.p_flags & 0x4) != 0,
                writable: (program_header.p_flags & 0x2) != 0,
                executable: (program_header.p_flags & 0x1) != 0,
            })
        } else {
            None
        }
    }
}
