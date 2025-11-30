use common::acpi;

/// Dump the DMA controller information described in ACPI (IORT)
pub fn dump_acpi_dma_controller_info(rsdp_address: usize) {
    match acpi::get_acpi_table(rsdp_address, &acpi::iort::IORT::SIGNATURE) {
        Ok(iort_address) => {
            let iort = unsafe { &*(iort_address as *const acpi::iort::IORT) };
            dump_smmu_information(iort);
        }
        Err(acpi::AcpiError::TableNotFound) => {
            println!("ACPI DMA Controller: IORT table is not found");
        }
        Err(e) => {
            println!("ACPI DMA Controller: Failed to parse IORT ({e:?})");
        }
    }
}

fn dump_smmu_information(iort: &acpi::iort::IORT) {
    if let Some(smmu) = iort.get_smmu_v3_information() {
        println!("ACPI DMA Controller:");
        println!("  Type: SMMUv3");
        println!("  Base Address: {:#X}", smmu.get_base_address());
        println!("  Flags: {:#X}", smmu.get_flags());
        println!("  Model: {:#X}", smmu.get_model());
        println!("  VATOS Address: {:#X}", smmu.get_vatos_address());
        println!("  Event GSIV: {:#X}", smmu.get_event_gsiv());
        println!("  PRI GSIV: {:#X}", smmu.get_pri_gsiv());
        println!("  GERROR GSIV: {:#X}", smmu.get_gerr_gsiv());
        println!("  SYNC GSIV: {:#X}", smmu.get_sync_gsiv());
        println!("  Proximity Domain: {:#X}", smmu.get_proximity_domain());
        println!(
            "  Device ID Mapping Index: {:#X}",
            smmu.get_device_id_mapping_index()
        );
        println!("  ID Mappings: {}", smmu.get_number_of_mappings());
        for (index, mapping) in smmu.get_array_of_id_mappings().enumerate() {
            if mapping.is_single_map() {
                println!(
                    "    Mapping #{index}: StreamID {:#X} (single)",
                    mapping.get_output_base()
                );
            } else {
                let start = mapping.get_output_base();
                let end = start + mapping.get_number_of_ids() - 1;
                println!("    Mapping #{index}: StreamID {start:#X}~{end:#X}",);
            }
        }
    } else {
        println!("ACPI DMA Controller: SMMUv3 node is not present in IORT");
    }
}
