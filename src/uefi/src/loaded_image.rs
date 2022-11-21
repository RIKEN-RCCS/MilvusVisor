// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI Loaded Image Protocol
//!

use crate::{boot_service::EfiMemoryType, EfiHandle, EfiStatus, EfiSystemTable, Guid};

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid {
    d1: 0x5B1B31A1,
    d2: 0x9562,
    d3: 0x11d2,
    d4: [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

#[repr(C)]
pub struct EfiLoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *const EfiSystemTable,
    pub device_handle: EfiHandle,
    pub file_path: usize,
    pub reserved: usize,
    pub load_option_size: u32,
    pub load_options: usize,
    pub image_base: usize,
    pub image_code_type: EfiMemoryType,
    pub image_data_type: EfiMemoryType,
    pub unload: extern "efiapi" fn(image_handle: EfiHandle) -> EfiStatus,
}
