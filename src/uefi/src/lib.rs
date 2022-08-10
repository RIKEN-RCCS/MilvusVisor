// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Unified Extensible Firmware Interface
//!
//! Supported Version: 2.9
//!

#![no_std]
#![feature(abi_efiapi)]

pub mod boot_service;
pub mod file;
pub mod loaded_image;
pub mod output;

pub type EfiHandle = usize;

macro_rules! efi_error {
    ($code:expr) => {
        (1 << (usize::BITS - 1)) | $code
    };
}

macro_rules! efi_warn {
    ($code:expr) => {
        $code
    };
}

#[repr(usize)]
#[allow(dead_code)]
#[derive(Eq, PartialEq, Debug)]
pub enum EfiStatus {
    EfiSuccess = 0,
    EfiWarnUnknownGlyph = efi_warn!(1),
    EfiWarnDeleteFailure = efi_warn!(2),
    EfiWarnWriteFailure = efi_warn!(3),
    EfiWarnBufferTooSmall = efi_warn!(4),
    EfiWarnStaleData = efi_warn!(5),
    EfiWarnFileSystem = efi_warn!(6),
    EfiWarnResetRequired = efi_warn!(7),
    EfiLoadError = efi_error!(1),
    EfiInvalidParameter = efi_error!(2),
    EfiUnsupported = efi_error!(3),
    EfiBadBufferSize = efi_error!(4),
    EfiBufferTooSmall = efi_error!(5),
    EfiNotReady = efi_error!(6),
    EfiDeviceError = efi_error!(7),
    EfiWriteProtected = efi_error!(8),
    EfiOutOfResources = efi_error!(9),
    EfiVolumeCorrupted = efi_error!(10),
    EfiVolumeFull = efi_error!(11),
    EfiNoMedia = efi_error!(12),
    EfiMediaChanged = efi_error!(13),
    EfiNotFound = efi_error!(14),
    EfiNoResponse = efi_error!(16),
    EfiAccessDenied = efi_error!(15),
    EfiNoMapping = efi_error!(17),
    EfiTimeout = efi_error!(18),
    EfiNotStarted = efi_error!(19),
    EfiAlreadyStarted = efi_error!(20),
    EfiAborted = efi_error!(21),
    EfiIcmpError = efi_error!(22),
    EfiTftpError = efi_error!(23),
    EfiProtocolError = efi_error!(24),
    EfiIncompatibleVersion = efi_error!(25),
    EfiSecurityViolation = efi_error!(26),
    EfiCrcError = efi_error!(27),
    EfiEndOfMedia = efi_error!(28),
    EfiEndOfFile = efi_error!(31),
    EfiInvalidLanguage = efi_error!(32),
    EfiCompromisedData = efi_error!(33),
    EfiIpAddressConflict = efi_error!(34),
    EfiHttpError = efi_error!(35),
}

#[derive(Debug)]
#[repr(C)]
pub struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
pub struct EfiSystemTable {
    pub efi_table_header: EfiTableHeader,
    pub firmware_vendor: usize,
    pub firmware_version: u32,
    pub console_input_handler: EfiHandle,
    pub console_input_protocol: usize,
    pub console_output_handler: EfiHandle,
    pub console_output_protocol: *const output::EfiOutputProtocol,
    pub standard_error_handler: EfiHandle,
    pub standard_error_protocol: *const output::EfiOutputProtocol,
    pub efi_runtime_services: usize,
    pub efi_boot_services: *const boot_service::EfiBootServices,
    pub num_table_entries: usize,
    pub configuration_table: usize,
}

#[repr(C)]
pub struct EfiConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Guid {
    pub d1: u32,
    pub d2: u16,
    pub d3: u16,
    pub d4: [u8; 8],
}

const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid {
    d1: 0x5B1B31A1,
    d2: 0x9562,
    d3: 0x11d2,
    d4: [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid {
    d1: 0x0964e5b22,
    d2: 0x6459,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_DTB_TABLE_GUID: Guid = Guid {
    d1: 0xb1b621d5,
    d2: 0xf19c,
    d3: 0x41a5,
    d4: [0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0],
};

pub const EFI_ACPI_20_TABLE_GUID: Guid = Guid {
    d1: 0x8868e871,
    d2: 0xe4f1,
    d3: 0x11d3,
    d4: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};

#[derive(Debug)]
#[repr(C)]
pub struct EfiTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    pad_1: u8,
    nano_second: u32,
    time_zone: u16,
    day_light: u8,
    pad_2: u8,
}
