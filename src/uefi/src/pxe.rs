// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI PXE Base Code Protocol
//!

use crate::boot_service::{EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL, EfiBootServices};
use crate::loaded_image::{EFI_LOADED_IMAGE_PROTOCOL_GUID, EfiLoadedImageProtocol};
use crate::{EfiHandle, EfiStatus, Guid};

const DEFAULT_BLOCK_SIZE: usize = 2048;
const EFI_PXE_BASE_CODE_PROTOCOL_GUID: Guid = Guid {
    d1: 0x03C4E603,
    d2: 0xAC28,
    d3: 0x11d3,
    d4: [0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
};

type EfiIpAddress = [u32; 4];
type EfiPxeBaseCodePacket = [u8; 1472];

#[repr(C)]
struct EfiPxeBaseCodeDhcpv4Packet {
    bootp_opcode: u8,
    bootp_hw_type: u8,
    bootp_hw_addr_len: u8,
    bootp_gate_hops: u8,
    bootp_ident: u32,
    bootp_seconds: u16,
    bootp_flags: u16,
    bootp_ci_addr: [u8; 4],
    bootp_yi_addr: [u8; 4],
    bootp_si_addr: [u8; 4],
    bootp_gi_addr: [u8; 4],
    bootp_hw_addr: [u8; 16],
    bootp_srv_name: [u8; 64],
    bootp_boot_file: [u8; 128],
    dhcp_magik: u32,
    dhcp_options: [u8; 56],
}

#[repr(C)]
pub enum EfiPxeBaseCodeTftpOpcode {
    EfiPxeBaseCodeTftpFirst,
    EfiPxeBaseCodeTftpGetFileSize,
    EfiPxeBaseCodeTftpReadFile,
    EfiPxeBaseCodeTftpWriteFile,
    EfiPxeBaseCodeTftpReadDirectory,
    EfiPxeBaseCodeMtftpGetFileSize,
    EfiPxeBaseCodeMtftpReadFile,
    EfiPxeBaseCodeMtftpReadDirectory,
    EfiPxeBaseCodeMtftpLast,
}

#[repr(C)]
struct EfiPxeBaseCodeMode {
    started: bool,
    ipv6_available: bool,
    ipv6_supported: bool,
    using_ipv6: bool,
    bis_supported: bool,
    is_detected: bool,
    auto_arp: bool,
    send_guid: bool,
    dhcp_discover_valid: bool,
    dhcp_ack_received: bool,
    proxy_offer_received: bool,
    pxe_discover_valid: bool,
    pxe_reply_received: bool,
    pxe_bis_reply_received: bool,
    icmp_error_received: bool,
    tftp_error_received: bool,
    make_call_backs: bool,
    ttl: u8,
    tos: u8,
    station_ip: EfiIpAddress,
    subnet_mask: EfiIpAddress,
    dhcp_discover: EfiPxeBaseCodePacket,
    dhcp_ack: EfiPxeBaseCodePacket,
    proxy_offer: EfiPxeBaseCodePacket,
    pxe_discover: EfiPxeBaseCodePacket,
    pxe_reply: EfiPxeBaseCodePacket,
    pxe_bis_reply: EfiPxeBaseCodePacket,
    /*ip_filter: EFI_PXE_BASE_CODE_IP_FILTER,
    arp_cache_entries: u32,
    arp_cache: [EFI_PXE_BASE_CODE_ARP_ENTRY; EFI_PXE_BASE_CODE_MAX_ARP_ENTRIES],
    route_table: [EFI_PXE_BASE_CODE_ROUTE_ENTRY; EFI_PXE_BASE_CODE_MAX_ROUTE_ENTRIES],
    icmp_error: EFI_PXE_BASE_CODE_ICMP_ERROR,
    tftp_error: EFI_PXE_BASE_CODE_ICMP_ERROREFI_PXE_BASE_CODE_TFTP_ERROR,*/
}

#[repr(C)]
pub struct EfiPxeBaseCodeProtocol {
    revision: u64,
    start: usize,
    stop: usize,
    dhcp: usize,
    discover: usize,
    mtftp: extern "efiapi" fn(
        this: *const Self,
        operation: EfiPxeBaseCodeTftpOpcode,
        buffer: *mut u8,
        over_write: bool,
        buffer_size: *mut u64,
        block_size: *const usize,
        server_ip_address: *const EfiIpAddress,
        file_name: *const u8,
        info: usize,
        do_not_use_buffer: bool,
    ) -> EfiStatus,
    udp_write: usize,
    udp_read: usize,
    set_ip_fileter: usize,
    arp: usize,
    set_parameters: usize,
    set_station_ip: usize,
    set_packets: usize,
    mode: *mut EfiPxeBaseCodeMode,
}

impl EfiPxeBaseCodeProtocol {
    pub fn open_pxe_handler(
        image_handle: EfiHandle,
        b_s: &EfiBootServices,
    ) -> Result<&'static EfiPxeBaseCodeProtocol, EfiStatus> {
        let mut loaded_image_protocol: *const EfiLoadedImageProtocol = core::ptr::null();
        let mut pxe_protocol: *const EfiPxeBaseCodeProtocol = core::ptr::null();

        let status = (b_s.open_protocol)(
            image_handle,
            &EFI_LOADED_IMAGE_PROTOCOL_GUID,
            &mut loaded_image_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        );

        if status != EfiStatus::EfiSuccess || loaded_image_protocol.is_null() {
            return Err(status);
        };
        let status = (b_s.open_protocol)(
            unsafe { (*loaded_image_protocol).device_handle },
            &EFI_PXE_BASE_CODE_PROTOCOL_GUID,
            &mut pxe_protocol as *mut _ as usize as *mut *const usize,
            image_handle,
            0,
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        );
        if status != EfiStatus::EfiSuccess || pxe_protocol.is_null() {
            return Err(status);
        };
        Ok(unsafe { &*pxe_protocol })
    }

    pub fn get_server_ip_v4(&self) -> Result<[u8; 4], EfiStatus> {
        if self.mode.is_null() {
            return Err(EfiStatus::EfiUnsupported);
        }
        if unsafe { (*(self.mode)).dhcp_discover_valid } {
            Ok(unsafe {
                &*(&(*self.mode).dhcp_ack as *const _ as *const EfiPxeBaseCodeDhcpv4Packet)
            }
            .bootp_si_addr)
        } else {
            Err(EfiStatus::EfiUnsupported)
        }
    }

    pub fn get_file(
        &self,
        buffer: *mut u8,
        buffer_size: *mut u64,
        server_ip: [u8; 4],
        file_name: *const u8,
    ) -> Result<(), EfiStatus> {
        let mut block_size = DEFAULT_BLOCK_SIZE;
        let status = (self.mtftp)(
            self,
            EfiPxeBaseCodeTftpOpcode::EfiPxeBaseCodeTftpReadFile,
            buffer,
            false,
            buffer_size,
            &mut block_size,
            &server_ip as *const _ as usize as *const EfiIpAddress,
            file_name,
            0,
            false,
        );

        if status != EfiStatus::EfiSuccess {
            return Err(status);
        };
        Ok(())
    }
}
