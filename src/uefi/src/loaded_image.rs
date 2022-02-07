//!
//! Loaded Image
//!

use super::boot_service::memory_service::EfiMemoryType;
use super::{EfiHandle, EfiStatus, EfiSystemTable};

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
    pub unload: extern "C" fn(image_handle: EfiHandle) -> EfiStatus,
}
