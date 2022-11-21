// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI Device Path Protocol
//!

use crate::loaded_image::{EfiLoadedImageProtocol, EFI_LOADED_IMAGE_PROTOCOL_GUID};
use crate::{boot_service, EfiHandle, EfiStatus, Guid};

const EFI_DEVICE_PATH_PROTOCOL_GUID: Guid = Guid {
    d1: 0x09576e91,
    d2: 0x6d3f,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

const EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID: Guid = Guid {
    d1: 0x379be4e,
    d2: 0xd706,
    d3: 0x437d,
    d4: [0xb0, 0x37, 0xed, 0xb8, 0x2f, 0xb7, 0x72, 0xa4],
};

const EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL_GUID: Guid = Guid {
    d1: 0x5c99a21,
    d2: 0xc70f,
    d3: 0x4ad2,
    d4: [0x8a, 0x5f, 0x35, 0xdf, 0x33, 0x43, 0xf5, 0x1e],
};

#[repr(C)]
pub struct EfiDevicePathProtocol {
    p_type: u8,
    sub_type: u8,
    length: [u8; 2],
}

#[repr(C)]
pub struct EfiDevicePathFromTextProtocol {
    convert_text_to_device_node:
        extern "efiapi" fn(node: *const u16) -> *const EfiDevicePathProtocol,
    convert_text_to_device_path:
        extern "efiapi" fn(path: *const u16) -> *const EfiDevicePathProtocol,
}

#[repr(C)]
struct EfiDevicePathUtilitiesProtocol {
    get_device_path_size: usize,
    duplicate_device_path: usize,
    append_device_path: extern "efiapi" fn(
        src1: *const EfiDevicePathProtocol,
        src2: *const EfiDevicePathProtocol,
    ) -> *const EfiDevicePathProtocol,
    append_device_node: extern "efiapi" fn(
        path: *const EfiDevicePathProtocol,
        node: *const EfiDevicePathProtocol,
    ) -> *const EfiDevicePathProtocol,
    append_device_path_instance: usize,
    get_next_device_path_instance: usize,
    is_device_path_multi_instance: usize,
    create_device_node: usize,
}

pub fn get_full_path_of_current_device(
    image_handle: EfiHandle,
    b_s: *const boot_service::EfiBootServices,
) -> Result<*const EfiDevicePathProtocol, EfiStatus> {
    let mut loaded_image_protocol: *const EfiLoadedImageProtocol = core::ptr::null();
    let mut device_path_protocol: *const EfiDevicePathProtocol = core::ptr::null();

    let status = unsafe {
        ((*b_s).open_protocol)(
            image_handle,
            &EFI_LOADED_IMAGE_PROTOCOL_GUID,
            &mut loaded_image_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            boot_service::EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    }
    let status = unsafe {
        ((*b_s).open_protocol)(
            (*loaded_image_protocol).device_handle,
            &EFI_DEVICE_PATH_PROTOCOL_GUID,
            &mut device_path_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            boot_service::EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    Ok(device_path_protocol)
}

pub fn create_full_path_of_device(
    image_handle: EfiHandle,
    b_s: *const boot_service::EfiBootServices,
    null_terminated_file_name: &[u16],
) -> Result<*const EfiDevicePathProtocol, EfiStatus> {
    let mut loaded_image_protocol: *const EfiLoadedImageProtocol = core::ptr::null();
    let mut device_path_utilities_protocol: *const EfiDevicePathUtilitiesProtocol =
        core::ptr::null();
    let mut device_path_protocol: *const EfiDevicePathProtocol = core::ptr::null();
    let mut device_path_from_text_protocol: *const EfiDevicePathFromTextProtocol =
        core::ptr::null();

    let status = unsafe {
        ((*b_s).open_protocol)(
            image_handle,
            &EFI_LOADED_IMAGE_PROTOCOL_GUID,
            &mut loaded_image_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            boot_service::EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    }
    let status = unsafe {
        ((*b_s).open_protocol)(
            (*loaded_image_protocol).device_handle,
            &EFI_DEVICE_PATH_PROTOCOL_GUID,
            &mut device_path_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            boot_service::EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    let status = unsafe {
        ((*b_s).locate_protocol)(
            &EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID,
            core::ptr::null(),
            &mut device_path_utilities_protocol as *mut _ as usize as *mut *const usize,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    }
    let status = unsafe {
        ((*b_s).locate_protocol)(
            &EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL_GUID,
            core::ptr::null(),
            &mut device_path_from_text_protocol as *mut _ as usize as *mut *const usize,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    let file_path = unsafe {
        ((*device_path_from_text_protocol).convert_text_to_device_node)(
            null_terminated_file_name.as_ptr(),
        )
    };
    if file_path.is_null() {
        return Err(EfiStatus::EfiInvalidParameter);
    }
    let full_path = unsafe {
        ((*device_path_utilities_protocol).append_device_node)(device_path_protocol, file_path)
    };
    if full_path.is_null() {
        return Err(EfiStatus::EfiInvalidParameter);
    }
    return Ok(full_path);
}
