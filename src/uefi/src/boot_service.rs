//!
//! UEFI Boot Services
//!

pub mod memory_service;

use memory_service::{EfiAllocateType, EfiMemoryDescriptor, EfiMemoryType};

use super::{EfiHandle, EfiStatus, EfiTableHeader, Guid};

#[derive(Debug)]
#[repr(C)]
pub struct EfiBootServices {
    efi_table_header: EfiTableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    pub allocate_pages: extern "C" fn(
        allocate_type: EfiAllocateType,
        memory_type: EfiMemoryType,
        pages: usize,
        memory: *mut usize,
    ) -> EfiStatus,
    free_pages: usize,
    pub get_memory_map: extern "C" fn(
        memory_map_size: *mut usize,
        memory_map: *mut EfiMemoryDescriptor,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    pub allocate_pool:
        extern "C" fn(pool_type: EfiMemoryType, size: usize, memory: *mut usize) -> EfiStatus,
    pub free_pool: extern "C" fn(memory: usize) -> EfiStatus,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: usize,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: usize,
    start_image: usize,
    pub exit: extern "C" fn(
        image_handler: EfiHandle,
        exit_status: EfiStatus,
        exit_data_size: usize,
        exit_data: *const u16,
    ) -> EfiStatus,
    unload_image: usize,
    exit_boot_services: usize,
    get_next_monotonic_count: usize,
    stall: usize,
    set_watchdog_timer: usize,
    connect_controller: usize,
    disconnect_controller: usize,
    pub open_protocol: extern "C" fn(
        handle: EfiHandle,
        protocol: *const Guid,
        interface: *mut *const usize,
        agent_handle: EfiHandle,
        controller_handle: EfiHandle,
        attributes: u32,
    ) -> EfiStatus,
    close_protocol: usize,
    open_protocol_information: usize,
    protocols_per_handle: usize,
    locate_handle_buffer: usize,
    pub locate_protocol: extern "C" fn(
        protocol: *const Guid,
        registration: *const usize,
        interface: *mut *const usize,
    ) -> EfiStatus,
    install_multiple_protocol_interfaces: usize,
    uninstall_multiple_protocol_interfaces: usize,
    calculate_crc32: usize,
    pub copy_mem: extern "C" fn(destination: usize, source: usize, length: usize),
    pub set_mem: extern "C" fn(buffer: usize, size: usize, value: u8),
    create_event_ex: usize,
}
