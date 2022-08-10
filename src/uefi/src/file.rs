// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI Simple File System Protocol
//!

use crate::boot_service::{EfiBootServices, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL};
use crate::loaded_image::EfiLoadedImageProtocol;
use crate::{
    EfiHandle, EfiStatus, EfiTime, Guid, EFI_LOADED_IMAGE_PROTOCOL_GUID,
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
};

const EFI_FILE_MODE_READ: u64 = 0x0000000000000001;
#[allow(dead_code)]
const EFI_FILE_MODE_WRITE: u64 = 0x0000000000000002;
#[allow(dead_code)]
const EFI_FILE_MODE_CREATE: u64 = 0x8000000000000000;
#[allow(dead_code)]
const EFI_FILE_READ_ONLY: u64 = 0x0000000000000001;
#[allow(dead_code)]
const EFI_FILE_HIDDEN: u64 = 0x0000000000000002;
#[allow(dead_code)]
const EFI_FILE_SYSTEM: u64 = 0x0000000000000004;
#[allow(dead_code)]
const EFI_FILE_RESERVED: u64 = 0x0000000000000008;
#[allow(dead_code)]
const EFI_FILE_DIRECTORY: u64 = 0x0000000000000010;
#[allow(dead_code)]
const EFI_FILE_ARCHIVE: u64 = 0x0000000000000020;
#[allow(dead_code)]
const EFI_FILE_VALID_ATTR: u64 = 0x0000000000000037;

#[allow(dead_code)]
const EFI_FILE_INFO_ID: Guid = Guid {
    d1: 0x09576e92,
    d2: 0x6d3f,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

#[repr(C)]
pub struct EfiSimpleFileProtocol {
    revision: u64,
    open_volume:
        extern "efiapi" fn(this: *const Self, root: *mut *const EfiFileProtocol) -> EfiStatus,
}

#[derive(Debug)]
#[repr(C)]
pub struct EfiFileInfo {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: EfiTime,
    last_access_time: EfiTime,
    modification_time: EfiTime,
    attribute: u64,
    /* file_name: [u16]*/
}

#[repr(C)]
pub struct EfiFileProtocol {
    revision: u64,
    open: extern "efiapi" fn(
        this: *const Self,
        new_handle: *mut *const Self,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> EfiStatus,
    close: extern "efiapi" fn(this: *const Self) -> EfiStatus,
    delete: extern "efiapi" fn(this: *const Self) -> EfiStatus,
    read: extern "efiapi" fn(
        this: *const Self,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> EfiStatus,
    write: extern "efiapi" fn(
        this: *const Self,
        buffer_size: *mut usize,
        buffer: *const u8,
    ) -> EfiStatus,
    get_position: extern "efiapi" fn(this: *const Self, position: *mut u64) -> EfiStatus,
    set_position: extern "efiapi" fn(this: *const Self, position: u64) -> EfiStatus,
    get_info: extern "efiapi" fn(
        this: *const Self,
        information_type: *const Guid,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> EfiStatus,
    set_info: extern "efiapi" fn(
        this: *const Self,
        information_type: *const Guid,
        buffer_size: usize,
        buffer: *const u8,
    ) -> EfiStatus,
    flush: extern "efiapi" fn(this: *const Self) -> EfiStatus,
    open_ex: extern "efiapi" fn(
        this: *const Self,
        new_handle: *mut *const Self,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
        token: usize,
    ) -> EfiStatus,
    read_ex: extern "efiapi" fn(this: *const Self, token: usize) -> EfiStatus,
    write_ex: extern "efiapi" fn(this: *const Self, token: usize) -> EfiStatus,
    flush_ex: extern "efiapi" fn(this: *const Self, token: usize) -> EfiStatus,
}

pub fn open_root_dir(
    image_handle: EfiHandle,
    b_s: *const EfiBootServices,
) -> Result<*const EfiFileProtocol, EfiStatus> {
    let mut root_dir_protocol: *const EfiFileProtocol = core::ptr::null();
    let mut loaded_image_protocol: *const EfiLoadedImageProtocol = core::ptr::null();
    let mut simple_file_protocol: *const EfiSimpleFileProtocol = core::ptr::null();

    let status = unsafe {
        ((*b_s).open_protocol)(
            image_handle,
            &EFI_LOADED_IMAGE_PROTOCOL_GUID,
            &mut loaded_image_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    let status = unsafe {
        ((*b_s).open_protocol)(
            (*loaded_image_protocol).device_handle,
            &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
            &mut simple_file_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    let status = unsafe {
        ((*simple_file_protocol).open_volume)(
            simple_file_protocol,
            &mut root_dir_protocol as *mut _,
        )
    };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    };
    Ok(root_dir_protocol)
}

pub fn open_file(
    root_file_protocol: *const EfiFileProtocol,
    utf16_file_name: &[u16],
) -> Result<*const EfiFileProtocol, EfiStatus> {
    let mut file_handle: *const EfiFileProtocol = core::ptr::null();

    let status = unsafe {
        ((*root_file_protocol).open)(
            root_file_protocol,
            &mut file_handle,
            utf16_file_name.as_ptr(),
            EFI_FILE_MODE_READ,
            0,
        )
    };
    if status != EfiStatus::EfiSuccess || file_handle.is_null() {
        return Err(status);
    }
    Ok(file_handle)
}

pub fn read(
    file: *const EfiFileProtocol,
    buffer: *mut u8,
    buffer_size: usize,
) -> Result<usize, EfiStatus> {
    let mut read_size = buffer_size;
    let status = unsafe { ((*file).read)(file, &mut read_size as *mut _, buffer) };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    }
    Ok(read_size)
}

pub fn seek(file: *const EfiFileProtocol, position: usize) -> Result<(), EfiStatus> {
    let status = unsafe { ((*file).set_position)(file, position as u64) };
    if status != EfiStatus::EfiSuccess {
        return Err(status);
    }
    Ok(())
}

pub fn close_file(file: *const EfiFileProtocol) -> Result<(), EfiStatus> {
    let s = unsafe { ((*file).close)(file) };
    if s == EfiStatus::EfiSuccess {
        Ok(())
    } else {
        Err(s)
    }
}
