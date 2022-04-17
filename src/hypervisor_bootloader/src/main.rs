// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]
#![feature(asm_sym)]
#![feature(const_maybe_uninit_uninit_array)]
#![feature(maybe_uninit_uninit_array)]
#![feature(naked_functions)]
#![feature(panic_info_message)]

#[macro_use]
mod console;
mod dtb;
mod elf;
mod paging;
mod panic;
mod pci;
mod serial_port;
mod smmu;

use common::cpu::*;
use common::{
    HypervisorKernelMainType, SystemInformation, ALLOC_SIZE, HYPERVISOR_PATH,
    HYPERVISOR_SERIAL_BASE_ADDRESS, HYPERVISOR_VIRTUAL_BASE_ADDRESS, MAX_PHYSICAL_ADDRESS,
    PAGE_MASK, PAGE_SHIFT, PAGE_SIZE, STACK_PAGES,
};

use uefi::{
    boot_service, boot_service::EfiBootServices, file, EfiConfigurationTable, EfiHandle, EfiStatus,
    EfiSystemTable, EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID,
};

use core::arch::asm;
use core::mem::{transmute, MaybeUninit};

static mut ORIGINAL_PAGE_TABLE: usize = 0;
static mut ORIGINAL_VECTOR_BASE: u64 = 0;
static mut ORIGINAL_TCR_EL2: u64 = 0;
static mut INTERRUPT_FLAG: MaybeUninit<InterruptFlag> = MaybeUninit::uninit();

static mut MEMORY_POOL: ([MaybeUninit<usize>; ALLOC_SIZE / PAGE_SIZE], usize) =
    (MaybeUninit::uninit_array(), 0);

static mut IMAGE_HANDLE: EfiHandle = 0;
static mut SYSTEM_TABLE: *const EfiSystemTable = core::ptr::null();
static mut ACPI_20_TABLE_ADDRESS: Option<usize> = None;
static mut DTB_ADDRESS: Option<usize> = None;

#[no_mangle]
extern "C" fn efi_main(image_handle: EfiHandle, system_table: *mut EfiSystemTable) {
    unsafe {
        /* Initialize console to use UEFI Output Protocol */
        console::DEFAULT_CONSOLE.init((*system_table).console_output_protocol);
        IMAGE_HANDLE = image_handle;
        SYSTEM_TABLE = system_table;
    }

    println!("Hello,world!");

    let efi_boot_services = unsafe { (*system_table).efi_boot_services };
    init_memory_pool(efi_boot_services);
    dump_memory_map(efi_boot_services);

    let current_el: usize;
    unsafe { asm!("mrs {:x}, CurrentEL", out(reg) current_el) };
    let current_el = current_el >> 2;
    println!("CurrentEL: {}", current_el);
    if current_el != 2 {
        panic!("Expected current_el == 2");
    }

    let entry_point = load_hypervisor(image_handle, efi_boot_services);

    #[cfg(debug_assertions)]
    paging::dump_page_table();

    paging::setup_stage_2_translation().expect("Failed to setup Stage2 Paging");
    map_memory_pool();

    detect_acpi_and_dtb(system_table);

    let mut serial = serial_port::detect_serial_port();
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
        pci::detect_pci_space(rsdp)
    } else {
        None
    };

    let smmu_v3_base_address = if let Some(acpi_address) = unsafe { ACPI_20_TABLE_ADDRESS } {
        smmu::detect_smmu(acpi_address)
    } else {
        None
    };

    let stack_address = allocate_memory(STACK_PAGES).expect("Failed to alloc stack");
    println!(
        "Stack for BSP: {:#X}",
        stack_address + (STACK_PAGES << PAGE_SHIFT)
    );

    println!("Call the hypervisor(Entry Point: {:#X})", entry_point);
    let mut system_info = SystemInformation {
        acpi_rsdp_address: unsafe { ACPI_20_TABLE_ADDRESS },
        vbar_el2: 0,
        memory_pool: unsafe { &MEMORY_POOL },
        serial_port: serial,
        ecam_info,
        smmu_v3_base_address,
    };
    unsafe { (transmute::<usize, HypervisorKernelMainType>(entry_point))(&mut system_info) };
    println!("Returned from the hypervisor");
    unsafe { MEMORY_POOL.1 = 0 }; /* Do not call allocate_memory after calling hypervisor */

    println!("Setup EL1");

    /* Disable IRQ/FIQ */
    /* After disabling IRQ/FIQ, we should avoid calling UEFI functions */
    unsafe { INTERRUPT_FLAG.write(local_irq_fiq_save()) };

    /* Setup registers */
    unsafe {
        asm!("mrs {:x}, vbar_el2", out(reg) ORIGINAL_VECTOR_BASE);
        asm!("msr vbar_el2, {:x}", in(reg) system_info.vbar_el2);
    }
    set_up_el1();

    /* Jump to EL1(el1_main) */
    el2_to_el1(stack_address + (STACK_PAGES << PAGE_SHIFT));

    /* Never come here */
    local_irq_fiq_restore(unsafe { INTERRUPT_FLAG.assume_init_ref().clone() });
    panic!("Failed to jump EL1");
}

/// SystemTableを解析し、ACPI 2.0とDTBのアドレスを記録
///
/// SystemTableを解析し、[`EFI_ACPI_20_TABLE_GUID`]と[`EFI_DTB_TABLE_GUID`]に記録
fn detect_acpi_and_dtb(system_table: *const EfiSystemTable) {
    let num_of_entries = unsafe { (*system_table).num_table_entries };
    for i in 0..num_of_entries {
        let table = unsafe {
            &*(((*system_table).configuration_table
                + i * core::mem::size_of::<EfiConfigurationTable>())
                as *const EfiConfigurationTable)
        };
        println!("GUID: {:#X?}", table.vendor_guid);
        if table.vendor_guid == EFI_DTB_TABLE_GUID {
            println!("Detect DTB");
            unsafe { DTB_ADDRESS = Some(table.vendor_table) };
        } else if table.vendor_guid == EFI_ACPI_20_TABLE_GUID {
            println!("Detect ACPI 2.0");
            unsafe { ACPI_20_TABLE_ADDRESS = Some(table.vendor_table) };
        }
    }
}
/// UEFIからメモリを確保して[`MEMORY_POOL`]に格納
///
/// ALLOC_SIZE分をUEFIから確保する。確保したメモリ領域の属性はEfiUnusableMemoryに変更する。
fn init_memory_pool(b_s: *const EfiBootServices) {
    let allocate_pages = ALLOC_SIZE >> PAGE_SHIFT;
    let mut allocated_address = boot_service::memory_service::alloc_highest_memory(
        b_s,
        allocate_pages,
        MAX_PHYSICAL_ADDRESS,
    )
    .expect("Failed to init memory pool");
    println!(
        "Allocated {:#X} ~ {:#X}",
        allocated_address,
        allocated_address + ALLOC_SIZE
    );
    for e in unsafe { &mut MEMORY_POOL.0 } {
        e.write(allocated_address);
        allocated_address += PAGE_SIZE;
    }
    unsafe { MEMORY_POOL.1 = MEMORY_POOL.0.len() };
}

/// [`MEMORY_POOL`]をTTBR0_EL2にマップし、更にEL1からアクセスできないようにする
///
/// [`init_memory_pool`]で確保したメモリ領域をTTBR0_EL2にストレートマップし、ハイパーバイザーから
/// アクセスできるようにする。
///
/// また該当領域をVTTBR_EL2でダミーのページへのアクセスするように設定する。
fn map_memory_pool() {
    let allocated_memory = unsafe { MEMORY_POOL.0[0].assume_init() };
    paging::map_address(
        allocated_memory,
        allocated_memory,
        ALLOC_SIZE,
        true,
        true,
        true, /* For cpu_boot */
        false,
    )
    .expect("Failed to map allocated memory");
    /*paging::unmap_address_from_vttbr_el2(b_s, allocated_memory, ALLOC_SIZE)
    .expect("Failed to unmap allocated address.");*/
    let dummy_page = allocate_memory(1).expect("Failed to alloc dummy page");
    paging::map_dummy_page_into_vttbr_el2(allocated_memory, ALLOC_SIZE, dummy_page)
        .expect("Failed to map dummy page");
}

/// メモリをメモリプールから確保
///
/// メモリを[`pages`]だけメモリプールから確保する。
/// 失敗した場合はErr(())を返却する。
///
/// # Arguments
/// * pages: 確保するメモリページ数
///
/// # Return Value
/// 確保に成功した場合はOk(address)、失敗した場合はErr(())
pub fn allocate_memory(pages: usize) -> Result<usize, ()> {
    if unsafe { MEMORY_POOL.1 < pages } {
        return Err(());
    }
    unsafe { MEMORY_POOL.1 -= pages };
    return Ok(unsafe { MEMORY_POOL.0[MEMORY_POOL.1].assume_init() });
}

/// ハイパーバイザー本体を[`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`]にに配置
///
/// EFIを使用し、[`common::HYPERVISOR_PATH`]よりハイパーバイザー本体を読み込みELFヘッダに従って配置する。
/// メモリに読み込む前に[`ORIGINAL_PAGE_TABLE`]に元のTTBR0_EL2を保存し、ページテーブルをコピーしたものに
/// 切り替える。読み込みに失敗した場合この関数はpanicする。
///
/// # Return Value
/// ハイパーバイザー本体の初期化用エントリポイント
fn load_hypervisor(image_handle: EfiHandle, b_s: *const boot_service::EfiBootServices) -> usize /* Entry Point */
{
    let root_protocol = file::open_root_dir(image_handle, b_s).expect("Failed to open the volume");
    let mut file_name_utf16: [u16; HYPERVISOR_PATH.len() + 1] = [0; HYPERVISOR_PATH.len() + 1];

    for (i, e) in HYPERVISOR_PATH.encode_utf16().enumerate() {
        file_name_utf16[i] = e;
    }
    let hypervisor_protocol = file::open_file(root_protocol, &file_name_utf16)
        .expect("Failed to open the hypervisor binary file");

    /* Read ElfHeader */
    let mut elf_header: MaybeUninit<elf::Elf64Header> = MaybeUninit::uninit();
    const ELF64_HEADER_SIZE: usize = core::mem::size_of::<elf::Elf64Header>();
    let read_size = file::read(
        hypervisor_protocol,
        elf_header.as_mut_ptr() as *mut u8,
        ELF64_HEADER_SIZE,
    )
    .expect("Failed to read Elf header");
    if read_size != core::mem::size_of_val(&elf_header) {
        panic!(
            "Expected {} bytes, but read {} bytes",
            ELF64_HEADER_SIZE, read_size
        );
    }

    let elf_header = unsafe { elf_header.assume_init() };
    if !elf_header.check_elf_header() {
        panic!("Failed to load the hypervisor");
    }
    let program_header_entries_size =
        elf_header.get_program_header_entry_size() * elf_header.get_num_of_program_header_entries();
    let program_header_pool =
        boot_service::memory_service::alloc_pool(b_s, program_header_entries_size)
            .expect("Failed to allocate the pool for the program header");
    file::seek(hypervisor_protocol, elf_header.get_program_header_offset())
        .expect("Failed to seek for the program header");
    let read_size = file::read(
        hypervisor_protocol,
        program_header_pool as *mut u8,
        program_header_entries_size,
    )
    .expect("Failed to read hypervisor");
    if read_size != program_header_entries_size {
        panic!(
            "Expected {} bytes, but read {} bytes",
            program_header_entries_size, read_size
        );
    }

    /* Switch PageTable */
    let cloned_page_table = paging::copy_page_table();
    unsafe {
        ORIGINAL_PAGE_TABLE = get_ttbr0_el2() as usize;
        ORIGINAL_TCR_EL2 = get_tcr_el2();
    };
    set_ttbr0_el2(cloned_page_table as u64);
    println!(
        "Switched TTBR0_EL2 from {:#X} to {:#X}",
        unsafe { ORIGINAL_PAGE_TABLE },
        cloned_page_table
    );

    for index in 0..elf_header.get_num_of_program_header_entries() {
        if let Some(info) = elf_header.get_segment_info(index, program_header_pool) {
            println!("{:?}", info);
            if info.memory_size == 0 {
                continue;
            }
            let pages = (((info.memory_size - 1) & PAGE_MASK) >> PAGE_SHIFT) + 1;
            let physical_base_address =
                allocate_memory(pages).expect("Failed to allocate memory for hypervisor");

            if info.file_size > 0 {
                file::seek(hypervisor_protocol, info.file_offset)
                    .expect("Failed to seek for hypervisor segments");
                let read_size = file::read(
                    hypervisor_protocol,
                    physical_base_address as *mut u8,
                    info.file_size,
                )
                .expect("Failed to read hypervisor segments");
                if read_size != info.file_size {
                    panic!(
                        "Expected {} bytes, but read {} bytes",
                        info.file_size, read_size
                    );
                }
            }

            if info.memory_size - info.file_size > 0 {
                unsafe {
                    ((*b_s).set_mem)(
                        physical_base_address + info.file_size,
                        info.memory_size - info.file_size,
                        0,
                    )
                };
            }
            if info.virtual_base_address < HYPERVISOR_VIRTUAL_BASE_ADDRESS {
                panic!(
                    "Expected VirtualBaseAddress:{:#X} >= HYPERVISOR_VIRTUAL_BASE_ADDRESS:{:#X}",
                    info.virtual_base_address, HYPERVISOR_VIRTUAL_BASE_ADDRESS
                );
            } else if info.virtual_base_address >= HYPERVISOR_SERIAL_BASE_ADDRESS {
                panic!(
                    "Expected VirtualBaseAddress:{:#X} >= HYPERVISOR_SERIAL_BASE_ADDRESS:{:#X}",
                    info.virtual_base_address, HYPERVISOR_SERIAL_BASE_ADDRESS
                );
            }
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
    if let Err(e) = boot_service::memory_service::free_pool(b_s, program_header_pool) {
        println!("Failed to free the pool: {:?}", e);
    }
    if let Err(e) = file::close_file(hypervisor_protocol) {
        println!("Failed to clone the HypervisorProtocol: {:?}", e);
    }
    if let Err(e) = file::close_file(root_protocol) {
        println!("Failed to clone the RootProtocol: {:?}", e);
    }

    return elf_header.get_entry_point();
}

fn dump_memory_map(b_s: *const EfiBootServices) {
    let memory_map_info = match boot_service::memory_service::get_memory_map(b_s) {
        Ok(info) => info,
        Err(e) => {
            println!("Failed to get memory_map: {:?}", e);
            return;
        }
    };
    let default_descriptor_size =
        core::mem::size_of::<boot_service::memory_service::EfiMemoryDescriptor>();

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
            &*(base_address as *const boot_service::memory_service::EfiMemoryDescriptor)
        });
        base_address += memory_map_info.actual_descriptor_size;
    }

    if let Err(e) = boot_service::memory_service::free_pool(b_s, memory_map_info.descriptor_address)
    {
        println!("Failed to free pool for the memory map: {:?}", e);
    }
}

/// EL2での各システムレジスタの値を適宜EL1にコピーし、EL2の各システムレジスタを適切な値に変更
fn set_up_el1() {
    let is_e2h_enabled = {
        let hcr_el2: u64;
        unsafe { asm!("mrs {:x}, hcr_el2", out(reg) hcr_el2) };
        (hcr_el2 & HCR_EL2_E2H) != 0
    };

    /* CNTHCTL_EL2 */
    let mut cnthctl_el2: u64;
    unsafe { asm!("mrs {:x}, cnthctl_el2", out(reg) cnthctl_el2) };
    cnthctl_el2 |=
        CNTHCTL_EL2_EL1PTEN | CNTHCTL_EL2_EL1PCTEN | CNTHCTL_EL2_EL0PTEN | CNTHCTL_EL2_EL0PCTEN;
    unsafe { asm!("msr cnthctl_el2, {:x}", in(reg) cnthctl_el2) };

    /* ACTLR_EL1 */
    /* Ignore it currently... */

    /* AMAIR_EL1 */
    /* Ignore it currently... */

    /* CPACR_EL1 & CPTR_EL2 */
    let cptr_el2_current: u64;
    let mut cpacr_el1: u64 = 0;
    unsafe { asm!("mrs {:x}, cptr_el2",out(reg) cptr_el2_current) };

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
    /* TODO: CPTR_EL2を0から必要なBitのみONにするようにする */
    let mut cptr_el2: u64 = cptr_el2_current | CPTR_EL2_ZEN_NO_TRAP | CPTR_EL2_FPEN_NO_TRAP /*| CPTR_EL2_RES1*/;
    cptr_el2 &= !((1 << 28) | (1 << 30) | (1 << 31));
    unsafe {
        asm!("msr cpacr_el1, {:x}",in(reg) cpacr_el1);
        asm!("isb")
        /* CPTR_EL2 will be set after HCR_EL2 */
    }

    /* MAIR_EL1(Copy MAIR_EL2) */
    unsafe {
        asm!("  mrs {t}, mair_el2
                msr mair_el1, {t}", t = out(reg) _ )
    };

    /* TTBR0_EL1 */
    set_ttbr0_el1(unsafe { ORIGINAL_PAGE_TABLE } as u64);

    /* TCR_EL1 */
    if is_e2h_enabled {
        unsafe { asm!("msr tcr_el1, {:x}",in(reg) ORIGINAL_TCR_EL2) };
    } else {
        let mut tcr_el1: u64 = 0;
        let tcr_el2 = unsafe { ORIGINAL_TCR_EL2 };
        /*Copy same bitfields */
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

        unsafe { asm!("msr tcr_el1, {:x}", in(reg) tcr_el1) };
    }

    /* SCTLR_EL1(Copy SCTLR_EL2) */
    unsafe {
        asm!("  mrs {t}, sctlr_el2
                msr sctlr_el1, {t}",t = out(reg) _)
    };

    /* VBAR_EL1 */
    unsafe {
        asm!("msr vbar_el1, {:x}",in(reg) ORIGINAL_VECTOR_BASE);
    }

    /* HCR_EL2 */
    let hcr_el2: u64 =
        HCR_EL2_FIEN | HCR_EL2_API | HCR_EL2_APK | HCR_EL2_RW | HCR_EL2_TSC | HCR_EL2_VM;
    unsafe {
        asm!("msr hcr_el2, {:x}",in(reg) hcr_el2);
        asm!("isb");
        asm!("msr cptr_el2, {:x}",in(reg) cptr_el2);
    }
}

extern "C" fn el1_main() -> ! {
    local_irq_fiq_restore(unsafe { INTERRUPT_FLAG.assume_init_ref().clone() });

    println!("Hello,world! from EL1");
    let mut current_el: usize;
    unsafe { asm!("mrs {:x}, CurrentEL", out(reg) current_el) };
    let current_el = current_el >> 2;
    println!("CurrentEL: {}", current_el);
    if current_el != 1 {
        panic!("Failed to jump into EL1");
    }

    println!("Return to UEFI.");
    unsafe {
        ((*(*SYSTEM_TABLE).efi_boot_services).exit)(
            IMAGE_HANDLE,
            EfiStatus::EfiSuccess,
            0,
            core::ptr::null(),
        )
    };
    panic!("Failed to exit");
}

#[naked]
extern "C" fn el2_to_el1(stack_pointer: usize) {
    unsafe {
        asm!(
            "
            adr x8, {}
            msr elr_el2, x8
            mov x8, sp
            msr sp_el1, x8
            mov sp, x0 // x0 contains stack_pointer
            mov x0, (1 << 7) |(1 << 6) | (1 << 2) | (1) // EL1h(EL1 + Use SP_EL1)
            msr spsr_el2, x0
            isb
            eret
        ", 
        sym el1_main,
        options(noreturn)
        )
    }
}
