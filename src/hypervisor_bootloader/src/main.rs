// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;
use core::ptr::NonNull;

use common::{cpu::*, *};
use uefi::{
    EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiConfigurationTable, EfiHandle, EfiSystemTable,
    boot_service, boot_service::EfiBootServices,
};
#[cfg(feature = "tftp")]
use uefi::{EfiStatus, pxe};

#[macro_use]
mod console;
mod dtb;
mod elf;
mod paging;
mod panic;
mod pci;
mod serial_port;
mod smmu;

static mut ORIGINAL_PAGE_TABLE: usize = 0;
static mut ORIGINAL_VECTOR_BASE: u64 = 0;
static mut ORIGINAL_TCR_EL2: u64 = 0;
static mut INTERRUPT_FLAG: MaybeUninit<InterruptFlag> = MaybeUninit::uninit();

static mut IMAGE_HANDLE: EfiHandle = 0;
static mut SYSTEM_TABLE: *const EfiSystemTable = core::ptr::null();
static mut ACPI_20_TABLE_ADDRESS: Option<NonZeroUsize> = None;
static mut DTB_ADDRESS: Option<NonZeroUsize> = None;
static mut MEMORY_ALLOCATOR: MaybeUninit<MemoryAllocator> = MaybeUninit::uninit();
#[cfg(feature = "tftp")]
static mut PXE_PROTOCOL: *const pxe::EfiPxeBaseCodeProtocol = core::ptr::null();

#[no_mangle]
extern "C" fn efi_main(image_handle: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    let system_table = unsafe { &*system_table };
    let b_s = unsafe { &*system_table.efi_boot_services };
    unsafe {
        IMAGE_HANDLE = image_handle;
        SYSTEM_TABLE = system_table;
    }
    console::init_default_console(unsafe { &*system_table.console_output_protocol });

    if let Some(hash_info) = HYPERVISOR_HASH_INFO {
        println!(
            "{} Bootloader Version {}({hash_info})",
            HYPERVISOR_NAME,
            env!("CARGO_PKG_VERSION")
        );
    } else {
        println!(
            "{} Bootloader Version {}",
            HYPERVISOR_NAME,
            env!("CARGO_PKG_VERSION")
        );
    }
    if let Some(compiler_info) = COMPILER_INFO {
        println!("Compiler Information: {compiler_info}");
    }

    assert_eq!(get_current_el() >> 2, 2, "Expected CurrentEL is EL2");

    let allocated_memory_address = init_memory_pool(b_s);

    #[cfg(debug_assertions)]
    dump_memory_map(b_s);

    let entry_point = load_hypervisor(image_handle, b_s);

    #[cfg(debug_assertions)]
    paging::dump_page_table();

    paging::setup_stage_2_translation().expect("Failed to setup Stage2 Paging");
    map_memory_pool(allocated_memory_address, ALLOC_SIZE);

    detect_acpi_and_dtb(system_table);

    let mut serial =
        serial_port::detect_serial_port(unsafe { ACPI_20_TABLE_ADDRESS }, unsafe { DTB_ADDRESS });
    if let Some(s) = &mut serial {
        let aligned_address = s.physical_address & PAGE_MASK;
        paging::map_address(
            aligned_address,
            HYPERVISOR_SERIAL_BASE_ADDRESS,
            PAGE_SIZE,
            true,
            true,
            false,
            true,
        )
        .expect("Failed to map serial port");
        s.virtual_address = HYPERVISOR_SERIAL_BASE_ADDRESS + (s.physical_address - aligned_address);
    }

    let ecam_info = if let Some(rsdp) = unsafe { ACPI_20_TABLE_ADDRESS } {
        pci::detect_pci_space(rsdp.get())
    } else {
        None
    };

    let spin_table_info = if let Some(dtb_address) = unsafe { DTB_ADDRESS } {
        detect_spin_table(dtb_address.get())
    } else {
        None
    };

    #[cfg(feature = "smmu")]
    let smmu_v3_base_address = if let Some(acpi_address) = unsafe { ACPI_20_TABLE_ADDRESS } {
        smmu::detect_smmu(acpi_address.get()).and_then(|a| NonZeroUsize::new(a))
    } else {
        None
    };
    #[cfg(not(feature = "smmu"))]
    let smmu_v3_base_address = None;

    /* Stack for BSP */
    let stack_address = allocate_memory(STACK_PAGES, None).expect("Failed to alloc stack")
        + (STACK_PAGES << PAGE_SHIFT);

    #[cfg(feature = "fast_restore")]
    let memory_save_list = NonNull::new(create_memory_save_list(b_s));
    #[cfg(not(feature = "fast_restore"))]
    let memory_save_list = None;

    #[cfg(feature = "edit_dtb_memory")]
    if let Some(dtb_address) = unsafe { DTB_ADDRESS } {
        let page_num = 4 * 1024;
        let size = page_num << PAGE_SHIFT;
        let new_dtb_address = b_s
            .alloc_highest_memory(page_num, MAX_PHYSICAL_ADDRESS)
            .expect("Failed to allocate memory for u-boot");

        /* Edit DTB's memory region */
        let dtb_total_size = dtb::add_new_memory_reservation_entry_to_dtb(
            dtb_address.get(),
            new_dtb_address,
            size,
            allocated_memory_address,
            ALLOC_SIZE,
        )
        .expect("Failed to add new reservation entry to DTB");
        #[cfg(feature = "save_dtb")]
        save_dtb(new_dtb_address, dtb_total_size, image_handle, b_s);
        #[cfg(not(feature = "save_dtb"))]
        println!(
            "DTB_ADDRESS: {:#X} (Size: {:#X})",
            new_dtb_address, dtb_total_size
        );
    }

    println!("Call the hypervisor(Entry Point: {:#X})", entry_point);

    let mut system_info = SystemInformation {
        acpi_rsdp_address: unsafe { ACPI_20_TABLE_ADDRESS },
        vbar_el2: 0,
        available_memory_info: unsafe { MEMORY_ALLOCATOR.assume_init_mut().get_all_memory() },
        spin_table_info,
        memory_save_list,
        serial_port: serial,
        ecam_info,
        smmu_v3_base_address,
        exit_boot_service_address: NonZeroUsize::new(unsafe {
            (*(*SYSTEM_TABLE).efi_boot_services).exit_boot_services
        } as usize),
    };
    unsafe {
        (core::mem::transmute::<usize, HypervisorKernelMainType>(entry_point))(&mut system_info)
    };

    /* Do not call allocate_memory/free_memory from here */

    println!("Setup EL1");

    /* Disable IRQ/FIQ */
    /* After disabling IRQ/FIQ, we should avoid calling UEFI functions */
    unsafe { INTERRUPT_FLAG.write(local_irq_fiq_save()) };

    /* Setup registers */
    unsafe { ORIGINAL_VECTOR_BASE = get_vbar_el2() };
    set_vbar_el2(system_info.vbar_el2);

    set_up_el1();

    /* Jump to EL1(el1_main) */
    el2_to_el1(el1_main as *const fn() as usize, stack_address);

    /* Never come here */
    local_irq_fiq_restore(unsafe { INTERRUPT_FLAG.assume_init_ref().clone() });
    panic!("Failed to jump EL1");
}

/// Analyze EfiSystemTable and store [`ACPI_20_TABLE_ADDRESS`] and [`DTB_ADDRESS`]
///
/// # Arguments
/// * system_table: Efi System Table
/// * b_s: EfiBootService
fn detect_acpi_and_dtb(system_table: &EfiSystemTable) {
    for i in 0..system_table.num_table_entries {
        let table = unsafe {
            &*((system_table.configuration_table
                + i * core::mem::size_of::<EfiConfigurationTable>())
                as *const EfiConfigurationTable)
        };
        pr_debug!("GUID: {:#X?}", table.vendor_guid);
        if table.vendor_guid == EFI_DTB_TABLE_GUID {
            pr_debug!("Detect DTB");
            unsafe { DTB_ADDRESS = NonZeroUsize::new(table.vendor_table) };
        } else if table.vendor_guid == EFI_ACPI_20_TABLE_GUID {
            pr_debug!("Detect ACPI 2.0");
            unsafe { ACPI_20_TABLE_ADDRESS = NonZeroUsize::new(table.vendor_table) };
        }
    }
}

/// Allocate memory and setup [`MEMORY_ALLOCATOR`]
///
/// This function allocates [`ALLOC_SIZE`] and then, set it into [`MEMORY_ALLOCATOR`]
/// The attribute of allocated memory area will be changed to EfiUnusableMemory
///
/// # Arguments
/// * b_s: EfiBootService
///
/// # Panics
/// If the allocation is failed, this function will panic.
///
/// # Result
/// Returns the start_address allocated
fn init_memory_pool(b_s: &EfiBootServices) -> usize {
    let allocate_pages = ALLOC_SIZE >> PAGE_SHIFT;
    let allocated_address = b_s
        .alloc_highest_memory(allocate_pages, MAX_PHYSICAL_ADDRESS)
        .expect("Failed to init memory pool");
    println!(
        "Allocated {:#X} ~ {:#X}",
        allocated_address,
        allocated_address + ALLOC_SIZE
    );
    unsafe {
        MEMORY_ALLOCATOR
            .assume_init_mut()
            .init(allocated_address, ALLOC_SIZE)
    };
    allocated_address
}

/// Map allocated memory area into TTBR0_EL2 and set up not to be accessible from EL1/EL0
///
/// This function map memory allocated by [`init_memory_pool`] into new TTBR0_EL2.
/// Also, this function will setup the dummy page.
/// This sets VTTBR_EL2 up to convert access to the allocated memory area from EL1/EL0 to single dummy page.
/// Therefore, EL1/EL0 will not read/write allocated memory area.
///
/// # Arguments
/// * `allocated_memory_address` - base address of allocated memory by [`init_memory_pool`]
/// * `alloc_size` - allocated memory size
///
/// # Panics
/// If the mapping into new TTBR0_EL2 or VTTBR_EL2 is failed, this function will panic.
fn map_memory_pool(allocated_memory_address: usize, alloc_size: usize) {
    paging::map_address(
        allocated_memory_address,
        allocated_memory_address,
        alloc_size,
        true,
        true,
        true, /* For cpu_boot */
        false,
    )
    .expect("Failed to map allocated memory");
    /*paging::unmap_address_from_vttbr_el2(b_s, allocated_memory_address, ALLOC_SIZE)
    .expect("Failed to unmap allocated address.");*/
    let dummy_page = allocate_memory(1, None).expect("Failed to alloc dummy page");
    paging::map_dummy_page_into_vttbr_el2(allocated_memory_address, alloc_size, dummy_page)
        .expect("Failed to map dummy page");
}

/// Allocate memory from memory pool
///
/// # Arguments
/// * `pages` - The number of pages to allocate, the allocation size is `pages` << [`PAGE_SHIFT`]
/// * `align` - The alignment of the returned address, if `None`, [`PAGE_SHIFT`] will be used
///
/// # Result
/// If the allocation is succeeded, Ok(start_address), otherwise Err(())
pub fn allocate_memory(pages: usize, align: Option<usize>) -> Result<usize, MemoryAllocationError> {
    unsafe {
        MEMORY_ALLOCATOR
            .assume_init_mut()
            .allocate(pages << PAGE_SHIFT, align.unwrap_or(PAGE_SHIFT))
    }
}

/// Free memory to memory pool
///
/// # Arguments
/// * `address` - The start address to return to memory pool, it must be allocated by [`allocate_memory`]
/// * `pages` - The number of allocated pages
///
/// # Result
/// If succeeded, Ok(()), otherwise Err(())
pub fn free_memory(address: usize, pages: usize) -> Result<(), MemoryAllocationError> {
    unsafe {
        MEMORY_ALLOCATOR
            .assume_init_mut()
            .free(address, pages << PAGE_SHIFT)
    }
}

/// Detect spin table
///
/// When device tree is available, this function searches "cpu" node and check "cpu-release-addr".
/// When "cpu-release-addr" exists, secondary processors are enabled by spin-table,
/// This finds area of spin-table(this function assumes "cpu-release-addr" is continued linearly.)
fn detect_spin_table(
    dtb_address: usize,
) -> Option<(
    usize,        /* Base Address */
    NonZeroUsize, /* Length */
)> {
    let dtb_analyzer = dtb::DtbAnalyser::new(dtb_address).unwrap();
    let mut search_holder = dtb_analyzer.get_root_node().get_search_holder().unwrap();
    let Ok(Some(cpu_node)) = search_holder.search_next_device_by_node_name(b"cpu", &dtb_analyzer)
    else {
        pr_debug!("Failed to find CPU node");
        return None;
    };
    let Ok(Some(release_addr)) = cpu_node.get_prop_as_u32(b"cpu-release-addr", &dtb_analyzer)
    else {
        pr_debug!("Faiked to find cpu-release-addr");
        return None;
    };
    let base_address = ((u32::from_be(release_addr[0]) as usize) << u32::BITS)
        | (u32::from_be(release_addr[1]) as usize);
    let mut length = core::mem::size_of::<u64>();
    while let Ok(Some(node)) = search_holder.search_next_device_by_node_name(b"cpu", &dtb_analyzer)
    {
        let Ok(Some(release_addr)) = node.get_prop_as_u32(b"cpu-release-addr", &dtb_analyzer)
        else {
            return None;
        };
        let release_address = ((u32::from_be(release_addr[0]) as usize) << u32::BITS)
            | (u32::from_be(release_addr[1]) as usize);
        length = release_address + core::mem::size_of::<u64>() - base_address;
        pr_debug!("CPU Release Address: {:#X}", release_address);
    }
    Some((base_address, NonZeroUsize::new(length).unwrap()))
}

/// Load hypervisor_kernel to [`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`] via TFTP
///
/// This function loads hypervisor_kernel according to ELF header.
/// The hypervisor_kernel will be loaded from [`common::HYPERVISOR_PATH`]
///
/// Before loads the hypervisor, this will save original TTBR0_EL2 into [`ORIGINAL_PAGE_TABLE`] and
/// create new TTBR0_EL2 by copying original page table tree.
///
/// # Panics
/// If the loading is failed(including memory allocation, calling UEFI functions), this function panics
///
/// # Arguments
/// * image_handle: EFI Image Handle
/// * b_s: EfiBootService
///
/// # Result
/// Returns the entry point of hypervisor_kernel
#[cfg(feature = "tftp")]
fn load_hypervisor(image_handle: EfiHandle, b_s: &EfiBootServices) -> usize {
    let pxe_protocol = pxe::EfiPxeBaseCodeProtocol::open_pxe_handler(image_handle, b_s)
        .expect("Failed to open PXE Handler");
    unsafe { PXE_PROTOCOL = pxe_protocol };

    /* Open the server */
    let server_ip = pxe_protocol
        .get_server_ip_v4()
        .expect("Failed to get Server IP");
    pr_debug!("Server IP: {:?}", server_ip);

    /* Get the hypervisor_kernel size */
    let mut kernel_size = 0;
    let mut dummy_buffer = [0u8; 4];
    let result = pxe_protocol.get_file(
        dummy_buffer.as_mut_ptr(),
        &mut kernel_size,
        server_ip,
        HYPERVISOR_TFTP_PATH.as_bytes().as_ptr(),
    );
    assert_eq!(result, Err(EfiStatus::EfiBufferTooSmall));
    if kernel_size == 0 {
        kernel_size = 0x10000;
        println!(
            "Failed to get file size, assume file size: {:#X}",
            kernel_size
        );
    }
    pr_debug!("Kernel Size: {:#X}", kernel_size);

    /* Allocate pool */
    let kernel_pool = b_s
        .alloc_pool(kernel_size as usize)
        .expect("Failed to allocate memory pool");

    /* Get hypervisor_kernel via TFTP */
    let mut read_size = kernel_size;
    pxe_protocol
        .get_file(
            kernel_pool as *mut u8,
            &mut read_size,
            server_ip,
            HYPERVISOR_TFTP_PATH.as_bytes().as_ptr(),
        )
        .expect("Failed to receive file from server");
    assert_eq!(
        read_size, kernel_size,
        "Expected {:#X} Bytes, but read size is {:#X} Bytes.",
        kernel_size, read_size
    );

    let read_data = |buffer: *mut u8, offset: usize, read_size: usize| -> Result<usize, ()> {
        if offset + read_size > kernel_size as usize {
            println!(
                "Tried to read {:#X} bytes from {:#X}, but the binaries size is {:#X}",
                read_size, offset, kernel_size
            );
            return Err(());
        }
        unsafe {
            core::ptr::copy_nonoverlapping((kernel_pool + offset) as *const u8, buffer, read_size)
        };
        Ok(read_size)
    };

    let entry_point = _load_hypervisor(b_s, read_data);

    if let Err(e) = b_s.free_pool(kernel_pool) {
        println!("Failed to free the pool: {:?}", e);
    }
    return entry_point;
}

/// Load hypervisor_kernel to [`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`] from the embedded binary
///
/// This function loads hypervisor_kernel according to ELF header.
/// The hypervisor_kernel must be embedded.
///
/// Before loads the hypervisor, this will save original TTBR0_EL2 into [`ORIGINAL_PAGE_TABLE`] and
/// create new TTBR0_EL2 by copying original page table tree.
///
/// # Panics
/// If the loading is failed(including memory allocation, calling UEFI functions), this function panics
///
/// # Arguments
/// * image_handle: Unused
/// * b_s: EfiBootService
///
/// # Result
/// Returns the entry point of hypervisor_kernel
#[cfg(feature = "embed_kernel")]
fn load_hypervisor(_image_handle: EfiHandle, b_s: &EfiBootServices) -> usize {
    let hypervisor_kernel = include_bytes!(env!("HYPERVISOR_PATH"));
    println!("Reading the embedded hypervisor_kernel");

    let read_data = |buffer: *mut u8, offset: usize, read_size: usize| -> Result<usize, ()> {
        if offset + read_size > hypervisor_kernel.len() {
            println!(
                "Tried to read {:#X} bytes from {:#X}, but the binaries size is {:#X}",
                read_size,
                offset,
                hypervisor_kernel.len()
            );
            return Err(());
        }
        unsafe {
            core::ptr::copy_nonoverlapping(hypervisor_kernel[offset..].as_ptr(), buffer, read_size)
        };
        Ok(read_size)
    };

    _load_hypervisor(b_s, read_data)
}

/// Load hypervisor_kernel to [`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`]
///
/// This function loads hypervisor_kernel according to ELF header.
/// The hypervisor_kernel will be loaded from [`common::HYPERVISOR_PATH`]
///
/// Before loads the hypervisor, this will save original TTBR0_EL2 into [`ORIGINAL_PAGE_TABLE`] and
/// create new TTBR0_EL2 by copying original page table tree.
///
/// # Panics
/// If the loading is failed(including memory allocation, calling UEFI functions), this function panics
///
/// # Arguments
/// * image_handle: EFI Image Handle
/// * b_s: EfiBootService
///
/// # Result
/// Returns the entry point of hypervisor_kernel
#[cfg(not(any(feature = "tftp", feature = "embed_kernel")))]
fn load_hypervisor(image_handle: EfiHandle, b_s: &EfiBootServices) -> usize {
    use uefi::file;
    let root_protocol =
        file::EfiFileProtocol::open_root_dir(image_handle, b_s).expect("Failed to open the volume");
    let mut file_name_utf16: [u16; HYPERVISOR_PATH.len() + 1] = [0; HYPERVISOR_PATH.len() + 1];

    for (i, e) in HYPERVISOR_PATH.encode_utf16().enumerate() {
        file_name_utf16[i] = e;
    }
    let hypervisor_protocol = file::EfiFileProtocol::open_file(root_protocol, &file_name_utf16)
        .expect("Failed to open the hypervisor binary file");

    let read_data = |buffer: *mut u8, offset: usize, read_size: usize| -> Result<usize, ()> {
        if let Err(e) = hypervisor_protocol.seek(offset) {
            println!("Failed to seek: {:?}", e);
            return Err(());
        }
        match hypervisor_protocol.read(buffer, read_size) {
            Ok(s) => Ok(s),
            Err(e) => {
                println!("Failed to read data from the file: {:?}", e);
                Err(())
            }
        }
    };

    let entry_point = _load_hypervisor(b_s, read_data);

    if let Err(e) = hypervisor_protocol.close_file() {
        println!("Failed to clone the HypervisorProtocol: {:?}", e);
    }
    if let Err(e) = root_protocol.close_file() {
        println!("Failed to clone the RootProtocol: {:?}", e);
    }

    entry_point
}

/// Load hypervisor_kernel to [`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`]
///
/// This function loads hypervisor_kernel according to ELF header.
/// The data will be loaded by `read_data`
///
/// Before loads the hypervisor, this will save original TTBR0_EL2 into [`ORIGINAL_PAGE_TABLE`] and
/// create new TTBR0_EL2 by copying original page table tree.
///
/// # Panics
/// If the loading is failed(including memory allocation, calling UEFI functions), this function panics
///
/// # Arguments
/// * b_s: EfiBootService
/// * read_data: the closure to read hypervisor_kernel, this should return the read size, or error if failed
///   * buffer: the buffer to write the data
///   * offset: the offset to start reading
///   * read_size: the size to read
///
/// # Result
/// Returns the entry point of hypervisor_kernel
fn _load_hypervisor<F>(b_s: &EfiBootServices, read_data: F) -> usize
where
    F: Fn(*mut u8, usize, usize) -> Result<usize, ()>,
{
    /* Read ElfHeader */
    let mut elf_header: MaybeUninit<elf::Elf64Header> = MaybeUninit::uninit();
    const ELF64_HEADER_SIZE: usize = core::mem::size_of::<elf::Elf64Header>();
    let read_size = read_data(elf_header.as_mut_ptr() as *mut u8, 0, ELF64_HEADER_SIZE)
        .expect("Failed to read Elf header");
    assert_eq!(
        read_size, ELF64_HEADER_SIZE,
        "Expected {} bytes, but read {} bytes",
        ELF64_HEADER_SIZE, read_size
    );
    let elf_header = unsafe { elf_header.assume_init() };
    assert!(elf_header.check_elf_header(), "Hypervisor is not ELF file");

    /* Read program headers */
    let program_headers_size =
        elf_header.get_program_header_entry_size() * elf_header.get_num_of_program_header_entries();
    let program_header_pool = b_s
        .alloc_pool(program_headers_size)
        .expect("Failed to allocate the pool for the program header");
    let read_size = read_data(
        program_header_pool as *mut u8,
        elf_header.get_program_header_offset(),
        program_headers_size,
    )
    .expect("Failed to read program headers");
    assert_eq!(
        read_size, program_headers_size,
        "Expected {} bytes, but read {} bytes",
        program_headers_size, read_size
    );

    /* Switch PageTable */
    let cloned_page_table = paging::clone_page_table();
    unsafe {
        ORIGINAL_PAGE_TABLE = get_ttbr0_el2() as usize;
        ORIGINAL_TCR_EL2 = get_tcr_el2();
    };
    set_ttbr0_el2(cloned_page_table as u64);
    pr_debug!(
        "Switched TTBR0_EL2 from {:#X} to {:#X}",
        unsafe { ORIGINAL_PAGE_TABLE },
        cloned_page_table
    );

    for index in 0..elf_header.get_num_of_program_header_entries() {
        if let Some(info) = elf_header.get_segment_info(index, program_header_pool) {
            pr_debug!("{:#X?}", info);
            if info.memory_size == 0 {
                continue;
            }
            let pages = (((info.memory_size - 1) & PAGE_MASK) >> PAGE_SHIFT) + 1;
            let physical_base_address =
                allocate_memory(pages, None).expect("Failed to allocate memory for hypervisor");

            if info.file_size > 0 {
                let read_size = read_data(
                    physical_base_address as *mut u8,
                    info.file_offset,
                    info.file_size,
                )
                .expect("Failed to read hypervisor segments");
                assert_eq!(
                    read_size, info.file_size,
                    "Expected {} bytes, but read {} bytes",
                    info.file_size, read_size
                );
            }
            if info.memory_size - info.file_size > 0 {
                unsafe {
                    core::ptr::write_bytes(
                        (physical_base_address + info.file_size) as *mut u8,
                        0,
                        info.memory_size - info.file_size,
                    )
                };
            }
            assert!(
                info.virtual_base_address >= HYPERVISOR_VIRTUAL_BASE_ADDRESS,
                "Expected VirtualBaseAddress:{:#X} >= HYPERVISOR_VIRTUAL_BASE_ADDRESS:{:#X}",
                info.virtual_base_address,
                HYPERVISOR_VIRTUAL_BASE_ADDRESS
            );
            assert!(
                info.virtual_base_address < HYPERVISOR_SERIAL_BASE_ADDRESS,
                "Expected VirtualBaseAddress:{:#X} >= HYPERVISOR_SERIAL_BASE_ADDRESS:{:#X}",
                info.virtual_base_address,
                HYPERVISOR_SERIAL_BASE_ADDRESS
            );

            paging::map_address(
                physical_base_address,
                info.virtual_base_address,
                pages << PAGE_SHIFT,
                info.readable,
                info.writable,
                info.executable,
                false,
            )
            .expect("Failed to map hypervisor");
        }
    }

    let entry_point = elf_header.get_entry_point();
    if let Err(e) = b_s.free_pool(program_header_pool) {
        println!("Failed to free the pool: {:?}", e);
    }

    /* Flush the data cache */
    clean_data_cache_all();

    entry_point
}

/// Save DTB
///
/// This function saves DTB into [`common::DTB_WRITTEN_PATH`]
/// This process needed by passing the edited DTB to U-Boot.
///
/// # Panics
/// When opening file or writing into file fail, this function will panic
///
/// # Arguments
/// * `dtb_address` - The address to save
/// * `dtb_size` - The total size of DTB
/// * image_handle: EFI Image Handle
/// * b_s: EfiBootService
#[cfg(feature = "save_dtb")]
fn save_dtb(dtb_address: usize, dtb_size: usize, image_handle: EfiHandle, b_s: &EfiBootServices) {
    use uefi::file;
    let root_protocol =
        file::EfiFileProtocol::open_root_dir(image_handle, b_s).expect("Failed to open the volume");
    let mut file_name_utf16: [u16; DTB_WRITTEN_PATH.len() + 1] = [0; DTB_WRITTEN_PATH.len() + 1];

    for (i, e) in DTB_WRITTEN_PATH.encode_utf16().enumerate() {
        file_name_utf16[i] = e;
    }
    let dtb_protocol = file::EfiFileProtocol::create_file(root_protocol, &file_name_utf16)
        .expect("Failed to create the DTB binary file");

    let written_size = dtb_protocol
        .write(dtb_address as *mut u8, dtb_size)
        .expect("Failed to write DTB");
    assert_eq!(dtb_size, written_size);

    if let Err(e) = dtb_protocol.close_file() {
        println!("Failed to clone the HypervisorProtocol: {:?}", e);
    }
    if let Err(e) = root_protocol.close_file() {
        println!("Failed to clone the RootProtocol: {:?}", e);
    }
}

#[cfg(feature = "fast_restore")]
fn create_memory_save_list(b_s: &EfiBootServices) -> &'static mut [MemorySaveListEntry] {
    const MEMORY_SAVE_LIST_PAGES: usize = 3;
    const MEMORY_SAVE_LIST_SIZE: usize = MEMORY_SAVE_LIST_PAGES << PAGE_SHIFT;
    let memory_map_info = b_s.get_memory_map().expect("Failed to get the memory map");
    let list = unsafe {
        core::slice::from_raw_parts_mut(
            allocate_memory(MEMORY_SAVE_LIST_PAGES, None)
                .expect("Failed to allocate memory for memory saving list")
                as *mut MemorySaveListEntry,
            MEMORY_SAVE_LIST_SIZE / core::mem::size_of::<MemorySaveListEntry>(),
        )
    };

    let mut base_address = memory_map_info.descriptor_address;
    let mut list_pointer = 0usize;

    for _ in 0..memory_map_info.num_of_entries {
        use boot_service::EfiMemoryType;
        let e = unsafe { &*(base_address as *const boot_service::EfiMemoryDescriptor) };
        if e.memory_type == EfiMemoryType::EfiBootServicesData
            || e.memory_type == EfiMemoryType::EfiRuntimeServicesCode
            || e.memory_type == EfiMemoryType::EfiRuntimeServicesData
        {
            pr_debug!(
                "Add the area({:?}, Pages: {:#X}, Start: {:#X}) to save list",
                e.memory_type,
                e.number_of_pages,
                e.physical_start
            );
            list[list_pointer] = MemorySaveListEntry {
                memory_start: e.physical_start,
                saved_address: 0,
                num_of_pages: e.number_of_pages,
            };
            list_pointer += 1;
        } else if e.memory_type == EfiMemoryType::EfiConventionalMemory
            || e.memory_type == EfiMemoryType::EfiLoaderCode
            || e.memory_type == EfiMemoryType::EfiLoaderData
        {
            pr_debug!(
                "Add the area({:?}, Pages: {:#X}, Start: {:#X}) to on-demand save list",
                e.memory_type,
                e.number_of_pages,
                e.physical_start
            );
            list[list_pointer] = MemorySaveListEntry {
                memory_start: e.physical_start,
                saved_address: MEMORY_SAVE_ADDRESS_ONDEMAND_FLAG,
                num_of_pages: e.number_of_pages,
            };
            list_pointer += 1;
        }
        base_address += memory_map_info.actual_descriptor_size;
    }
    list[list_pointer] = MemorySaveListEntry {
        memory_start: 0,
        saved_address: 0,
        num_of_pages: 0,
    };

    if let Err(e) = b_s.free_pool(memory_map_info.descriptor_address) {
        println!("Failed to free pool for the memory map: {:?}", e);
    }
    list
}

#[cfg(debug_assertions)]
fn dump_memory_map(b_s: &EfiBootServices) {
    let memory_map_info = match b_s.get_memory_map() {
        Ok(info) => info,
        Err(e) => {
            println!("Failed to get memory_map: {:?}", e);
            return;
        }
    };
    let default_descriptor_size = core::mem::size_of::<boot_service::EfiMemoryDescriptor>();

    if default_descriptor_size != memory_map_info.actual_descriptor_size {
        println!(
            "Expected descriptor_size: {}, but returned descriptor_size: {}.",
            default_descriptor_size, memory_map_info.actual_descriptor_size
        );
    }

    println!(
        "Memory Map\n Key: {:#X}\n NumOfDescriptors: {}",
        memory_map_info.key, memory_map_info.num_of_entries,
    );
    let mut base_address = memory_map_info.descriptor_address;
    for index in 0..memory_map_info.num_of_entries {
        println!("{:02}: {:?}", index, unsafe {
            &*(base_address as *const boot_service::EfiMemoryDescriptor)
        });
        base_address += memory_map_info.actual_descriptor_size;
    }

    if let Err(e) = b_s.free_pool(memory_map_info.descriptor_address) {
        println!("Failed to free pool for the memory map: {:?}", e);
    }
}

fn set_up_el1() {
    let is_e2h_enabled = (get_hcr_el2() & HCR_EL2_E2H) != 0;

    /* CNTHCTL_EL2 & CNTVOFF_EL2 */
    set_cnthctl_el2(CNTHCTL_EL2_EL1PCEN | CNTHCTL_EL2_EL1PCTEN);
    set_cntvoff_el2(0);

    /* HSTR_EL2 */
    unsafe { asm!("msr hstr_el2, xzr") };

    /* VPIDR_EL2 & VMPIDR_EL2 */
    unsafe {
        asm!("  mrs {t}, midr_el1
                msr vpidr_el2, {t}
                mrs {t}, mpidr_el1
                msr vmpidr_el2, {t}", t = out(reg) _)
    };

    /* ACTLR_EL1 */
    /* Ignore it currently... */

    /* AMAIR_EL1 */
    /* Ignore it currently... */

    /* CPACR_EL1 & CPTR_EL2 */
    #[cfg(feature = "raspberrypi")]
    set_cptr_el2(0x0);
    let cptr_el2_current = get_cptr_el2();
    let mut cpacr_el1: u64 = 0;

    cpacr_el1 |= ((((cptr_el2_current) & CPTR_EL2_ZEN) >> CPTR_EL2_ZEN_BITS_OFFSET)
        << CPACR_EL1_ZEN_BITS_OFFSET)
        | ((((cptr_el2_current) & CPTR_EL2_FPEN) >> CPTR_EL2_FPEN_BITS_OFFSET)
            << CPACR_EL1_FPEN_BITS_OFFSET);
    cpacr_el1 |= 0b11 << CPACR_EL1_FPEN_BITS_OFFSET; /* TODO: inspect why we must set 0b11 */

    if is_e2h_enabled {
        cpacr_el1 |= ((cptr_el2_current & CPTR_EL2_TTA_WITH_E2H)
            >> CPTR_EL2_TTA_BIT_OFFSET_WITH_E2H)
            << CPACR_EL1_TTA_BIT_OFFSET;
    } else {
        cpacr_el1 |= ((cptr_el2_current & CPTR_EL2_TTA_WITHOUT_E2H)
            >> CPTR_EL2_TTA_BIT_OFFSET_WITHOUT_E2H)
            << CPACR_EL1_TTA_BIT_OFFSET;
    }

    let mut cptr_el2: u64 = cptr_el2_current | CPTR_EL2_ZEN_NO_TRAP | CPTR_EL2_FPEN_NO_TRAP /*| CPTR_EL2_RES1*/;
    cptr_el2 &= !((1 << 28) | (1 << 30) | (1 << 31));
    set_cpacr_el1(cpacr_el1);
    isb();
    /* CPTR_EL2 will be set after HCR_EL2 */

    let id_aa64pfr0_el1 = get_id_aa64pfr0_el1();
    if (id_aa64pfr0_el1 & ID_AA64PFR0_EL1_SVE) != 0 {
        /* ZCR_EL2 */
        unsafe {
            asm!("  mov {t}, 0x1ff
                msr S3_4_C1_C2_0, {t}", t = out(reg) _)
        };
    }

    if (id_aa64pfr0_el1 & ID_AA64PFR0_EL1_GIC) != 0 {
        /* GICv3~ */
        /*unsafe {
            asm!("  mrs {t}, icc_sre_el2
                    orr {t}, {t}, 1 << 0
                    orr {t}, {t}, 1 << 3
                    msr icc_sre_el2, {t}
                    isb
                    mrs {t}, icc_sre_el2
                    tbz {t}, 0, 1f
                    msr ich_hcr_el2, xzr
                    1:", t = out(reg) _)
        };*/
    }

    /* MAIR_EL1(Copy MAIR_EL2) */
    set_mair_el1(get_mair_el2());

    /* TTBR0_EL1 */
    set_ttbr0_el1(unsafe { ORIGINAL_PAGE_TABLE } as u64);

    /* TCR_EL1 */
    if is_e2h_enabled {
        set_tcr_el1(unsafe { ORIGINAL_TCR_EL2 });
    } else {
        let mut tcr_el1: u64 = 0;
        let tcr_el2 = unsafe { ORIGINAL_TCR_EL2 };
        /* Copy same bitfields */
        tcr_el1 |= tcr_el2 & ((1 << 16) - 1);

        tcr_el1 |= ((tcr_el2 & TCR_EL2_DS_WITHOUT_E2H) >> TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_DS_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_TCMA_WITHOUT_E2H) >> TCR_EL2_TCMA_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_TCMA0_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_TBID_WITHOUT_E2H) >> TCR_EL2_TBID_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_TBID0_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_HWU_WITHOUT_E2H) >> TCR_EL2_HWU_BITS_OFFSET_WITHOUT_E2H)
            << TCR_EL1_HWU_BITS_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_HPD_WITHOUT_E2H) >> TCR_EL2_HPD_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_HPD0_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_HD_WITHOUT_E2H) >> TCR_EL2_HD_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_HD_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_HA_WITHOUT_E2H) >> TCR_EL2_HA_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_HA_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_TBI_WITHOUT_E2H) >> TCR_EL2_TBI_BIT_OFFSET_WITHOUT_E2H)
            << TCR_EL1_TBI0_BIT_OFFSET;
        tcr_el1 |= ((tcr_el2 & TCR_EL2_PS_WITHOUT_E2H) >> TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H)
            << TCR_EL1_IPS_BITS_OFFSET;
        tcr_el1 |= TCR_EL1_EPD1; /* Disable TTBR1_EL1 */

        set_tcr_el1(tcr_el1);
    }

    /* SCTLR_EL1(Copy SCTLR_EL2) */
    set_sctlr_el1(get_sctlr_el2());

    /* VBAR_EL1 */
    set_vbar_el1(unsafe { ORIGINAL_VECTOR_BASE });

    #[cfg(feature = "a64fx")]
    {
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_TBO0_BIT_OFFSET: u32 = 0;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_TBO0: u32 =
            1 << IMP_FJ_TAG_ADDRESS_CTRL_EL2_TBO0_BIT_OFFSET;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL1_TBO0_BIT_OFFSET: u32 = 0;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_SCE0_BIT_OFFSET: u32 = 8;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_SCE0: u32 =
            1 << IMP_FJ_TAG_ADDRESS_CTRL_EL2_SCE0_BIT_OFFSET;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL1_SCE0_BIT_OFFSET: u32 = 8;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_PFE0_BIT_OFFSET: u32 = 8;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL2_PFE0: u32 =
            1 << IMP_FJ_TAG_ADDRESS_CTRL_EL2_PFE0_BIT_OFFSET;
        const IMP_FJ_TAG_ADDRESS_CTRL_EL1_PFE0_BIT_OFFSET: u32 = 8;
        const IMP_SCCR_CTRL_EL1_EL1AE: u64 = 1 << 63;
        const IMP_SCCR_CTRL_EL1_EL0AE: u64 = 1 << 62;
        const IMP_PF_CTRL_EL1_EL1AE: u64 = 1 << 63;
        const IMP_PF_CTRL_EL1_EL0AE: u64 = 1 << 62;
        const IMP_BARRIER_CTRL_EL1_EL1AE: u64 = 1 << 63;
        const IMP_BARRIER_CTRL_EL1_EL0AE: u64 = 1 << 62;

        let mut imp_fj_tag_address_ctrl_el2: u32;
        let mut imp_fj_tag_address_ctrl_el1: u32 = 0;
        /* Is it ok including IMP_SCCR_CTRL_EL1_EL0AE? */
        let imp_sccr_ctrl_el1: u64 = IMP_SCCR_CTRL_EL1_EL1AE | IMP_SCCR_CTRL_EL1_EL0AE;
        /* Is it ok including IMP_PF_CTRL_EL1_EL0AE? */
        let imp_pf_ctrl_el1: u64 = IMP_PF_CTRL_EL1_EL1AE | IMP_PF_CTRL_EL1_EL0AE;
        /* Is it ok including IMP_BARRIER_CTRL_EL1_EL0AE? */
        let imp_barrier_ctrl_el1: u64 = IMP_BARRIER_CTRL_EL1_EL1AE | IMP_BARRIER_CTRL_EL1_EL0AE;

        unsafe { asm!("mrs {:x}, S3_4_C11_C2_0", out(reg) imp_fj_tag_address_ctrl_el2) };
        if is_e2h_enabled {
            imp_fj_tag_address_ctrl_el1 = imp_fj_tag_address_ctrl_el2;
        } else {
            imp_fj_tag_address_ctrl_el1 |= ((imp_fj_tag_address_ctrl_el2
                & IMP_FJ_TAG_ADDRESS_CTRL_EL2_TBO0)
                >> IMP_FJ_TAG_ADDRESS_CTRL_EL2_TBO0_BIT_OFFSET)
                << IMP_FJ_TAG_ADDRESS_CTRL_EL1_TBO0_BIT_OFFSET;
            imp_fj_tag_address_ctrl_el1 |= ((imp_fj_tag_address_ctrl_el2
                & IMP_FJ_TAG_ADDRESS_CTRL_EL2_SCE0)
                >> IMP_FJ_TAG_ADDRESS_CTRL_EL2_SCE0_BIT_OFFSET)
                << IMP_FJ_TAG_ADDRESS_CTRL_EL1_SCE0_BIT_OFFSET;
            imp_fj_tag_address_ctrl_el1 |= ((imp_fj_tag_address_ctrl_el2
                & IMP_FJ_TAG_ADDRESS_CTRL_EL2_PFE0)
                >> IMP_FJ_TAG_ADDRESS_CTRL_EL2_PFE0_BIT_OFFSET)
                << IMP_FJ_TAG_ADDRESS_CTRL_EL1_PFE0_BIT_OFFSET;
        }
        imp_fj_tag_address_ctrl_el2 = 0;
        unsafe { asm!("msr S3_4_C11_C2_0, {:x}", in(reg) imp_fj_tag_address_ctrl_el2) };
        unsafe { asm!("msr S3_0_C11_C2_0, {:x}", in(reg) imp_fj_tag_address_ctrl_el1) };
        unsafe { asm!("msr S3_0_C11_C8_0, {:x}", in(reg) imp_sccr_ctrl_el1) };
        unsafe { asm!("msr S3_0_C11_C4_0, {:x}", in(reg) imp_pf_ctrl_el1) };
        unsafe { asm!("msr S3_0_C11_C12_0, {:x}", in(reg) imp_barrier_ctrl_el1) };
    }

    /* HCR_EL2 */
    let hcr_el2 = HCR_EL2_FIEN | HCR_EL2_API | HCR_EL2_APK | HCR_EL2_RW | HCR_EL2_TSC | HCR_EL2_VM;
    set_hcr_el2(hcr_el2);
    isb();
    set_cptr_el2(cptr_el2);
}

#[cfg(feature = "tftp")]
fn run_payload() -> EfiStatus {
    let image_handle = unsafe { IMAGE_HANDLE };
    let mut payload_handle = 0;
    let b_s = unsafe { &*((*SYSTEM_TABLE).efi_boot_services) };
    let device_path = uefi::device_path::get_full_path_of_current_device(image_handle, b_s)
        .expect("Failed to get payload path");
    let pxe_protocol = unsafe { &*PXE_PROTOCOL };
    let mut file_name_ascii: [u8; UEFI_PAYLOAD_PATH.len() + 1] = [0; UEFI_PAYLOAD_PATH.len() + 1];
    for (i, e) in UEFI_PAYLOAD_PATH.as_bytes().iter().enumerate() {
        file_name_ascii[i] = *e;
    }
    let server_ip = pxe_protocol
        .get_server_ip_v4()
        .expect("Failed to get Server IP");

    /* Get Payload Binary via TFTP */
    let mut file_size = 0;
    let mut dummy_buffer = [0u8; 4];
    let result = pxe_protocol.get_file(
        dummy_buffer.as_mut_ptr(),
        &mut file_size,
        server_ip,
        file_name_ascii.as_ptr(),
    );
    assert_eq!(result, Err(EfiStatus::EfiBufferTooSmall));

    if file_size == 0 {
        file_size = 0x10000;
        println!(
            "Failed to get file size, assume file size: {:#X}",
            file_size
        );
    }

    pr_debug!("Kernel Size: {:#X}", file_size);

    /* Allocate pool */
    let file_pool = b_s
        .alloc_pool(file_size as usize)
        .expect("Failed to allocate memory pool");

    /* Receive Binary */
    let mut read_size = file_size;
    pxe_protocol
        .get_file(
            file_pool as *mut u8,
            &mut read_size,
            server_ip,
            file_name_ascii.as_ptr(),
        )
        .expect("Failed to receive file from server");
    if read_size != file_size {
        panic!(
            "Expected {:#X} Bytes, but read size is {:#X} Bytes.",
            file_size, read_size
        );
    }

    /* Load Binary into UEFI */
    let status = (b_s.load_image)(
        false,
        image_handle,
        device_path,
        file_pool,
        file_size as usize,
        &mut payload_handle,
    );

    let _ = b_s.free_pool(file_pool);
    if status != EfiStatus::EfiSuccess {
        panic!("Failed to load image: {:?}", status);
    }
    let mut data_size = 0usize;
    /* Run */
    (b_s.start_image)(payload_handle, &mut data_size, 0)
}

#[cfg(feature = "tftp")]
fn exit_bootloader() -> ! {
    unsafe {
        ((*(*SYSTEM_TABLE).efi_boot_services).exit)(
            IMAGE_HANDLE,
            run_payload(),
            0,
            core::ptr::null(),
        );
    }
    panic!("Failed to exit");
}

#[cfg(not(feature = "tftp"))]
fn exit_bootloader() -> ! {
    unsafe {
        ((*(*SYSTEM_TABLE).efi_boot_services).exit)(
            IMAGE_HANDLE,
            uefi::EfiStatus::EfiSuccess,
            0,
            core::ptr::null(),
        );
    }
    panic!("Failed to exit");
}

extern "C" fn el1_main() -> ! {
    local_irq_fiq_restore(unsafe { INTERRUPT_FLAG.assume_init_ref().clone() });

    assert_eq!(get_current_el() >> 2, 1, "Failed to jump to EL1");
    println!("Hello,world! from EL1");

    exit_bootloader();
}

fn el2_to_el1(el1_entry_point: usize, el1_stack_pointer: usize) {
    unsafe {
        asm!("
            msr elr_el2, {entry_point}
            mov {tmp}, sp
            msr sp_el1, {tmp}
            mov sp, {stack_pointer}
            mov {tmp}, (1 << 7) |(1 << 6) | (1 << 2) | (1) // EL1h(EL1 + Use SP_EL1)
            msr spsr_el2, {tmp}
            isb
            eret",
        tmp = in(reg) 0u64,
        entry_point = in(reg) el1_entry_point,
        stack_pointer = in(reg) el1_stack_pointer,
        options(noreturn)
        )
    }
}
