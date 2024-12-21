// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Booting Multi Linux
//!

use common::{LinuxBootInformation, PAGE_SHIFT, STACK_PAGES, cpu};

use crate::drivers::{virtio, virtio_net};
use crate::paging;
use crate::psci::{PsciFunctionId, PsciReturnCode, call_psci_function};
use crate::{GeneralPurposeRegisters, allocate_memory, free_memory};

/// **Depended on the machine**: The base address of PL011
const PL011_BASE_ADDRESS: usize = 0x1000000;
/// **Depended on the machine**: The base address of GIC Distributor
const GICD_BASE_ADDRESS: usize = 0x12000000;
/// **Depended on the machine**: The base address of GIC Redistributor
const GICR_BASE_ADDRESS: usize = 0x12200000;
/// **Depended on the machine**: The range of GIC Redistributor
const GICR_SIZE: usize = 0x00200000;
/// **Depended on the machine**: The base address for virtio-mmio of BSP
const BSP_VIRTIO_BASE_ADDRESS: usize = 0x45000000;
/// **Depended on the machine**: The base number for init_id of BSP
const BSP_VIRTIO_INTID_BASE: u32 = 32 /* SPI Base */ + 100;
/// **Depended on the machine**: The base number for init_id of AP
const AP_VIRTIO_BASE_ADDRESS: usize = 0xA000000;

#[repr(C, align(16))]
struct HypervisorRegisters {
    cnthctl_el2: u64,
    cptr_el2: u64,
    ttbr0_el2: u64,
    mair_el2: u64,
    tcr_el2: u64,
    vbar_el2: u64,
    vttbr_el2: u64,
    vtcr_el2: u64,
    sctlr_el2: u64,
    hcr_el2: u64,
    boot_info: LinuxBootInformation,
}

pub const HVC_BOOT_LINUX: u16 = 0xFFE0;
pub const HVC_BOOT_LINUX_AFTER: u16 = 0xFFE1;

static mut DEVICE_NUMBER: u8 = 0;

pub fn boot(regs: &mut GeneralPurposeRegisters) {
    let stack_address = (allocate_memory(STACK_PAGES, Some(STACK_PAGES))
        .expect("Failed to allocate stack")
        + (STACK_PAGES << PAGE_SHIFT)) as u64;

    /* Write System Registers */
    let register_buffer = unsafe {
        &mut *((stack_address as usize - core::mem::size_of::<HypervisorRegisters>())
            as *mut HypervisorRegisters)
    };
    register_buffer.cnthctl_el2 = cpu::get_cnthctl_el2();
    register_buffer.cptr_el2 = cpu::get_cptr_el2();
    register_buffer.ttbr0_el2 = cpu::get_ttbr0_el2();
    register_buffer.mair_el2 = cpu::get_mair_el2();
    register_buffer.tcr_el2 = cpu::get_tcr_el2();
    register_buffer.vbar_el2 = cpu::get_vbar_el2();
    register_buffer.vttbr_el2 = cpu::get_vttbr_el2();
    register_buffer.vtcr_el2 = cpu::get_vtcr_el2();
    register_buffer.sctlr_el2 = cpu::get_sctlr_el2();
    register_buffer.hcr_el2 = cpu::get_hcr_el2();
    register_buffer.boot_info = unsafe { (*(regs[0] as *const LinuxBootInformation)).clone() };

    cpu::dsb();
    /* Flush Memory Cache for Application Processors */
    cpu::clean_data_cache_all();

    let cpu_boot_address_real_address =
        cpu::convert_virtual_address_to_physical_address_el2_read(cpu_boot as *const fn() as usize)
            .expect("Failed to convert virtual address to real address");

    let result = call_psci_function(
        PsciFunctionId::CpuOn,
        unsafe { &*(regs[0] as *const LinuxBootInformation) }.mpidr_el1,
        cpu_boot_address_real_address as u64,
        register_buffer as *const _ as usize as u64,
    );
    if result as i32 != PsciReturnCode::Success as i32 {
        if let Err(err) = free_memory(
            stack_address as usize - (STACK_PAGES << PAGE_SHIFT),
            STACK_PAGES,
        ) {
            println!("Failed to free memory: {:?}", err);
        }
        println!(
            "Failed to power on the cpu (MPIDR: {:#X}): {:?}",
            unsafe { &*(regs[0] as *const LinuxBootInformation) }.mpidr_el1,
            PsciReturnCode::try_from(result as i32)
        );
        return;
    }
    println!("Boot kick is finished.");

    let boot_info = unsafe { &*(regs[0] as *const LinuxBootInformation) };

    /* Create Virtio-Network */
    let virtio_base_address =
        BSP_VIRTIO_BASE_ADDRESS + ((boot_info.mpidr_el1 - 1) as usize * common::STAGE_2_PAGE_SIZE);
    let virtio_intid = BSP_VIRTIO_INTID_BASE + boot_info.mpidr_el1 as u32 - 1;
    virtio_net::VirtioNetwork::setup_new_device_bsp(
        virtio_intid,
        virtio_base_address,
        boot_info.mpidr_el1,
    );
    if let Some(rsdp_address) = unsafe { crate::ACPI_RSDP } {
        virtio::append_virtio_ssdt(
            rsdp_address.get(),
            [b'V', b'N', b'T', b'0' + unsafe { DEVICE_NUMBER }],
            virtio_base_address,
            virtio_intid,
        );
    }
    unsafe { DEVICE_NUMBER += 1 };
    crate::gic::add_gic_distributor_protector(boot_info.mpidr_el1, boot_info.virtio_int_id);
}

pub fn jump_to_linux(regs: &mut GeneralPurposeRegisters) {
    let linux_info = unsafe { (*(regs[0] as *const HypervisorRegisters)).boot_info.clone() };
    let vttbr_el2 = paging::remake_stage2_page_table(true).expect("Failed to make page table");
    cpu::set_vttbr_el2(vttbr_el2 as u64);

    /* Map Address */
    paging::remove_memory_access_trap(linux_info.ram_physical_address, linux_info.ram_size)
        .expect("Failed to map RAM");
    paging::remove_memory_access_trap(PL011_BASE_ADDRESS, 0x1000).expect("Failed to map PL011");
    paging::remove_memory_access_trap(GICD_BASE_ADDRESS, 0x10000)
        .expect("Failed to map GIC Distributor");
    paging::remove_memory_access_trap(GICR_BASE_ADDRESS, GICR_SIZE)
        .expect("Failed to map GIC Redistributor");

    /* Setup Virtio */
    virtio_net::VirtioNetwork::setup_new_device(linux_info.virtio_int_id, AP_VIRTIO_BASE_ADDRESS);

    /* Add GIC Distributor Protector */
    crate::gic::add_gic_distributor_protector_ap();

    cpu::set_spsr_el2(
        (1 << 7) | (1 << 6) | (1 << 2) | (1), /* EL1h(EL1 + Use SP_EL1) */
    );
    cpu::set_elr_el2(linux_info.boot_address as u64);
    regs[0] = linux_info.dtb_address as u64;
    regs[1] = 0;
    regs[2] = 0;
    regs[3] = 0;
}

/* cpu_boot must use position-relative code */
#[naked]
extern "C" fn cpu_boot() {
    unsafe {
        core::arch::naked_asm!("
    ldp x1,   x2, [x0, 16 * 0]
    ldp x3,   x4, [x0, 16 * 1]
    ldp x5,   x6, [x0, 16 * 2]
    ldp x7,   x8, [x0, 16 * 3]
    ldp x9,  x10, [x0, 16 * 4]

    mov sp, x0
    msr cnthctl_el2,     x1
    msr cntvoff_el2,    xzr
    msr cptr_el2,        x2
    msr ttbr0_el2,       x3
    msr mair_el2,        x4
    msr tcr_el2,         x5
    msr vbar_el2,        x6
    msr vttbr_el2,       x7
    msr vtcr_el2,        x8
    msr sctlr_el2,       x9
    msr hcr_el2,        x10

    // TODO: Adjust Stack Pointer after jump_to_linux
    // Do not use x0

    // MIDR_EL1 & MPIDR_EL1
    mrs x15, midr_el1
    msr vpidr_el2, x15
    mrs x16, mpidr_el1
    msr vmpidr_el2, x16

    mrs x17, id_aa64pfr0_el1

    // SVE
    ubfx x18, x17, 32, 4
    cbz x18, 2f
    mov x15, {MAX_ZCR_EL2_LEN}
    msr S3_4_C1_C2_0, x15 // ZCR_EL2

2:  // GIC v3/4/4.1
    ubfx x18, x17, 24, 4
    cbz x18, 3f
    mrs x15, icc_sre_el2
    and x16, x15, 1
    cbz x16, 3f
    mov x18, {ICC_SRE_EL2}
    msr icc_sre_el2, x18
    isb
    msr ich_hcr_el2, xzr

3:  // A64FX
    mov x15, {A64FX}
    cbz x15, 4f
    msr S3_4_C11_C2_0, xzr // IMP_FJ_TAG_ADDRESS_CTRL_EL2

4:
    isb
    hvc {HVC_NUMBER}",
    MAX_ZCR_EL2_LEN = const cpu::MAX_ZCR_EL2_LEN,
    ICC_SRE_EL2 = const (cpu::ICC_SRE_EL2_ENABLE | cpu::ICC_SRE_EL2_SRE),
    A64FX = const cfg!(feature = "a64fx") as u64,
    HVC_NUMBER = const HVC_BOOT_LINUX_AFTER)
    }
}
