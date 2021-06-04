//! ACPI parsing functionality for relevant topology information.
use libacpica::*;

use core::mem;
use core::ptr;

use crate::alloc::alloc;
use crate::alloc::vec::Vec;
use core::alloc::Layout;

use crate::acpi_types::*;

use cstr_core::CStr;
use log::{debug, info, trace};

const ACPI_FULL_PATHNAME: u32 = 0;
const ACPI_TYPE_INTEGER: u32 = 0x01;

#[allow(unused)]
fn acpi_get_integer(handle: ACPI_HANDLE, name: *const i8, reg: &mut ACPI_INTEGER) -> ACPI_STATUS {
    unsafe {
        let mut object: ACPI_OBJECT = mem::zeroed();
        let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
            Length: mem::size_of::<ACPI_OBJECT>() as u64,
            Pointer: &mut object as *mut _ as *mut libacpica::c_void,
        };

        let ret = AcpiEvaluateObjectTyped(
            handle,
            name as *mut i8,
            ptr::null_mut(),
            &mut namebuf,
            ACPI_TYPE_INTEGER,
        );

        if ret == AE_OK {
            *reg = (*object.Integer()).Value;
        }
        ret
    }
}

#[allow(unused)]
pub fn process_pcie() {
    unsafe {
        let pcie_exp = CStr::from_bytes_with_nul_unchecked(b"PNP0A03\0");

        unsafe extern "C" fn call_back(
            handle: ACPI_HANDLE,
            _nexting: u32,
            _context: *mut libacpica::c_void,
            _return_value: *mut *mut libacpica::c_void,
        ) -> u32 {
            let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
                Length: 256,
                Pointer: alloc::alloc(Layout::from_size_align_unchecked(128, 0x1))
                    as *mut libacpica::c_void,
            };
            let _ret = AcpiGetName(handle, ACPI_FULL_PATHNAME, &mut namebuf);
            let name = CStr::from_ptr(namebuf.Pointer as *const i8)
                .to_str()
                .unwrap_or("");

            let mut address: ACPI_INTEGER = 0x0;
            let adr_cstr = CStr::from_bytes_with_nul_unchecked(b"_ADR\0");
            acpi_get_integer(handle, adr_cstr.as_ptr() as *const i8, &mut address);

            let mut bus_number: ACPI_INTEGER = 0x0;
            let adr_cstr = CStr::from_bytes_with_nul_unchecked(b"_BBN\0");
            let bbn_ret = acpi_get_integer(handle, adr_cstr.as_ptr() as *const i8, &mut bus_number);

            let bus = if bbn_ret == AE_OK {
                bus_number as u16
            } else {
                0u16
            };

            let device: u16 = (address >> 16) as u16 & 0xffff;
            let function: u16 = address as u16 & 0xffff;

            info!(
                "PCIe bridge name={} bus={} device={} function={}",
                name, bus, device, function
            );

            AE_OK
        }

        let _ret = AcpiGetDevices(
            pcie_exp.as_ptr() as *mut cstr_core::c_char,
            Some(call_back),
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }
}

/// Parse the SRAT table (static resource allocation structures for the platform).
///
/// This essentially figures out the NUMA topology of your system.
///
/// Returns entries of
/// * LocalApicAffinity: to inform about which core belongs to which NUMA node.
/// * LocalX2ApicAffinity: to inform about which core belongs to which NUMA node.
/// * MemoryAffinity: to inform which memory region belongs to which NUMA node.
pub fn process_srat() -> (
    Vec<LocalApicAffinity>,
    Vec<LocalX2ApicAffinity>,
    Vec<MemoryAffinity>,
) {
    let mut apic_affinity = Vec::with_capacity(24);
    let mut x2apic_affinity = Vec::with_capacity(24);
    let mut mem_affinity = Vec::with_capacity(8);

    unsafe {
        let srat_handle = CStr::from_bytes_with_nul_unchecked(b"SRAT\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            srat_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );

        if ret == AE_OK {
            let srat_tbl_ptr = table_header as *const ACPI_TABLE_SRAT;
            let srat_table_len = (*srat_tbl_ptr).Header.Length as usize;
            let srat_table_end = (srat_tbl_ptr as *const c_void).add(srat_table_len);

            debug!(
                "SRAT Table: Rev={} Len={} OemID={:?}",
                (*srat_tbl_ptr).Header.Revision,
                srat_table_len,
                (*srat_tbl_ptr).Header.OemId
            );

            let mut iterator =
                (srat_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_SRAT>());
            while iterator < srat_table_end {
                let entry: *const ACPI_SUBTABLE_HEADER = iterator as *const ACPI_SUBTABLE_HEADER;
                let entry_type: Enum_AcpiSratType = mem::transmute((*entry).Type as i32);

                match entry_type {
                    Enum_AcpiSratType::ACPI_SRAT_TYPE_CPU_AFFINITY => {
                        const ACPI_SRAT_ENABLED: u32 = 0x1;

                        let local_apic_affinity: *const ACPI_SRAT_CPU_AFFINITY =
                            entry as *const ACPI_SRAT_CPU_AFFINITY;

                        let apic_id = (*local_apic_affinity).ApicId;
                        let sapic_eid = (*local_apic_affinity).LocalSapicEid;
                        let proximity_domain: u32 = (*local_apic_affinity).ProximityDomainLo as u32
                            | (((*local_apic_affinity).ProximityDomainHi[0] as u32) << 8)
                            | (((*local_apic_affinity).ProximityDomainHi[1] as u32) << 16)
                            | (((*local_apic_affinity).ProximityDomainHi[2] as u32) << 24);
                        let clock_domain = (*local_apic_affinity).ClockDomain;
                        let enabled = (*local_apic_affinity).Flags & ACPI_SRAT_ENABLED > 0;

                        let parsed_entry = LocalApicAffinity {
                            apic_id,
                            sapic_eid,
                            proximity_domain,
                            clock_domain,
                            enabled,
                        };

                        trace!("SRAT entry: {:?}", parsed_entry);
                        if enabled {
                            apic_affinity.push(parsed_entry);
                        }

                        debug_assert_eq!((*entry).Length, 16);
                    }
                    Enum_AcpiSratType::ACPI_SRAT_TYPE_MEMORY_AFFINITY => {
                        const ACPI_SRAT_ENABLED: u32 = 0x1;
                        const ACPI_SRAT_HOTPLUGGABLE: u32 = 0x1 << 1;
                        const ACPI_SRAT_NON_VOLATILE: u32 = 0x1 << 2;

                        let mem_affinity_entry: *const ACPI_SRAT_MEM_AFFINITY =
                            entry as *const ACPI_SRAT_MEM_AFFINITY;

                        let proximity_domain = (*mem_affinity_entry).ProximityDomain;
                        let base_address = (*mem_affinity_entry).BaseAddress;
                        let length = (*mem_affinity_entry).Length;
                        let enabled = (*mem_affinity_entry).Flags & ACPI_SRAT_ENABLED > 0;
                        let hotplug_capable =
                            (*mem_affinity_entry).Flags & ACPI_SRAT_HOTPLUGGABLE > 0;
                        let non_volatile = (*mem_affinity_entry).Flags & ACPI_SRAT_NON_VOLATILE > 0;

                        let parsed_entry = MemoryAffinity {
                            proximity_domain,
                            base_address,
                            length,
                            enabled,
                            hotplug_capable,
                            non_volatile,
                        };

                        trace!("SRAT entry: {:?}", parsed_entry);
                        if enabled {
                            mem_affinity.push(parsed_entry);
                        }

                        debug_assert_eq!((*entry).Length, 40);
                    }
                    Enum_AcpiSratType::ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY => {
                        const ACPI_SRAT_ENABLED: u32 = 0x1;

                        let x2apic_affinity_entry: *const ACPI_SRAT_X2APIC_CPU_AFFINITY =
                            entry as *const ACPI_SRAT_X2APIC_CPU_AFFINITY;

                        let x2apic_id: u32 = (*x2apic_affinity_entry).ApicId;
                        let proximity_domain: u32 = (*x2apic_affinity_entry).ProximityDomain;
                        let clock_domain: u32 = (*x2apic_affinity_entry).ClockDomain;
                        let enabled: bool = (*x2apic_affinity_entry).Flags & ACPI_SRAT_ENABLED > 0;

                        let parsed_entry = LocalX2ApicAffinity {
                            x2apic_id,
                            proximity_domain,
                            clock_domain,
                            enabled,
                        };

                        trace!("SRAT entry: {:?}", parsed_entry);
                        if enabled {
                            x2apic_affinity.push(parsed_entry);
                        }

                        debug_assert_eq!((*entry).Length, 24);
                    }
                    _ => trace!("Unhandled SRAT entry"),
                }

                assert!((*entry).Length > 0);
                iterator = iterator.add((*entry).Length as usize);
            }
        } else {
            debug!("ACPI SRAT Table not found.");
        }
    }

    (apic_affinity, x2apic_affinity, mem_affinity)
}

/// Parse the MADT table.
///
/// This will find all
///  - Local APICs (cores)
///  - IO APICs (IRQ controllers)
/// in the system, and return them.
///
/// # Note
/// Some cores may be disabled (i.e., if we disabled hyper-threading),
/// we ignore them at the moment.
pub fn process_madt() -> (Vec<LocalApic>, Vec<LocalX2Apic>, Vec<IoApic>) {
    let mut cores = Vec::with_capacity(24);
    let mut x2apic_cores = Vec::with_capacity(24);
    let mut io_apics = Vec::with_capacity(24);

    unsafe {
        let madt_handle = CStr::from_bytes_with_nul_unchecked(b"APIC\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            madt_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        assert_eq!(ret, AE_OK);

        let madt_tbl_ptr = table_header as *const ACPI_TABLE_MADT;
        let madt_table_len = (*madt_tbl_ptr).Header.Length as usize;
        let madt_table_end = (madt_tbl_ptr as *const c_void).add(madt_table_len);

        trace!(
            "MADT Table: Rev={} Len={} OemID={:?}",
            (*madt_tbl_ptr).Header.Revision,
            madt_table_len,
            (*madt_tbl_ptr).Header.OemId
        );

        let mut iterator = (madt_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_MADT>());
        while iterator < madt_table_end {
            let entry: *const ACPI_SUBTABLE_HEADER = iterator as *const ACPI_SUBTABLE_HEADER;
            let entry_type: Enum_AcpiMadtType = mem::transmute((*entry).Type as i32);

            const ACPI_MADT_ENABLED: u32 = 0x1;

            match entry_type {
                Enum_AcpiMadtType::ACPI_MADT_TYPE_LOCAL_APIC => {
                    let local_apic: *const ACPI_MADT_LOCAL_APIC =
                        entry as *const ACPI_MADT_LOCAL_APIC;

                    let processor_id = (*local_apic).ProcessorId;
                    let apic_id = (*local_apic).Id;
                    let enabled: bool = (*local_apic).LapicFlags & ACPI_MADT_ENABLED > 0;

                    if enabled {
                        let core = LocalApic {
                            processor_id,
                            apic_id,
                            enabled,
                        };
                        trace!("MADT Entry: {:?}", core);
                        cores.push(core);
                    }
                }
                Enum_AcpiMadtType::ACPI_MADT_TYPE_LOCAL_X2APIC => {
                    let local_x2apic: *const ACPI_MADT_LOCAL_X2APIC =
                        entry as *const ACPI_MADT_LOCAL_X2APIC;

                    let processor_id = (*local_x2apic).Uid;
                    let apic_id = (*local_x2apic).LocalApicId;
                    let enabled: bool = (*local_x2apic).LapicFlags & ACPI_MADT_ENABLED > 0;

                    if enabled {
                        let core = LocalX2Apic {
                            processor_id,
                            apic_id,
                            enabled,
                        };
                        trace!("MADT Entry: {:?}", core);
                        x2apic_cores.push(core);
                    }
                }
                Enum_AcpiMadtType::ACPI_MADT_TYPE_IO_APIC => {
                    let io_apic: *const ACPI_MADT_IO_APIC = entry as *const ACPI_MADT_IO_APIC;

                    let apic = IoApic {
                        id: (*io_apic).Id,
                        address: (*io_apic).Address as u32,
                        global_irq_base: (*io_apic).GlobalIrqBase as u32,
                    };
                    trace!("MADT Entry: {:?}", apic);
                    io_apics.push(apic);
                }
                _ => trace!("Unhandled MADT entry"),
            }

            assert!((*entry).Length > 0, "Length is 0?");
            iterator = iterator.add((*entry).Length as usize);
        }
    }

    (cores, x2apic_cores, io_apics)
}

/// Parse the MSCT table (maximum system characteristics for the platform).
/// Returns all entries as a vector of MaximumSystemCharacteristics (or an empty vector
/// if table does not exist).
///
/// The Maximum Proximity Domain Information Structure is used to report system
/// maximum characteristics. It is likely that these characteristics may be the
/// same for many proximity domains, but they can vary from one proximity domain to
/// another.
///
/// These structures are organized in ascending order of the proximity domain
/// enumerations. All proximity domains within the Maximum Number of Proximity
/// Domains reported in the MSCT must be covered by one of these structures.
///
/// If the system maximum topology is not known up front at boot time, then this
/// table is not present. OSPM will use information provided by the MSCT only when
/// the System Resource Affinity Table (SRAT) exists. The MSCT must contain all
/// proximity and clock domains defined in the SRAT.
pub fn process_msct() -> (
    MaximumSystemCharacteristics,
    Vec<MaximumProximityDomainInfo>,
) {
    unsafe {
        let msct_handle = CStr::from_bytes_with_nul_unchecked(b"MSCT\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            msct_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        if ret != AE_OK {
            return (Default::default(), Vec::new());
        }

        let msct_tbl_ptr = table_header as *const ACPI_TABLE_MSCT;
        let msct_table_len = (*msct_tbl_ptr).Header.Length as usize;
        let msct_table_end = (msct_tbl_ptr as *const c_void).add(msct_table_len);

        let msc = MaximumSystemCharacteristics {
            proximity_offset: (*msct_tbl_ptr).ProximityOffset,
            max_proximity_domain: (*msct_tbl_ptr).MaxProximityDomains,
            max_clock_domains: (*msct_tbl_ptr).MaxClockDomains,
            max_address: (*msct_tbl_ptr).MaxAddress,
        };

        debug!(
            "MSCT Table: Rev={} Len={} OemID={:?} Characteristics {:?}",
            (*msct_tbl_ptr).Header.Revision,
            msct_table_len,
            (*msct_tbl_ptr).Header.OemId,
            msc
        );

        let mut max_prox_domains = Vec::with_capacity(24);
        let mut iterator = (msct_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_MSCT>());
        while iterator < msct_table_end {
            let entry: *const ACPI_MSCT_PROXIMITY = iterator as *const ACPI_MSCT_PROXIMITY;

            let mpdi = MaximumProximityDomainInfo {
                range_start: (*entry).RangeEnd,
                range_end: (*entry).RangeStart,
                processor_capacity: (*entry).ProcessorCapacity,
                memory_capacity: (*entry).MemoryCapacity,
            };
            trace!("MSCT entry: {:?}", mpdi);
            max_prox_domains.push(mpdi);

            assert_eq!((*entry).Length, 22);
            iterator = iterator.add((*entry).Length as usize);
        }

        (msc, max_prox_domains)
    }
}
