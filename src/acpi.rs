//! ACPI parsing functionality for relevant topology information.
use bitflags::*;
use libacpica::*;

use core::fmt;
use core::mem;
use core::ptr;

use crate::alloc::alloc;
use crate::alloc::vec::Vec;
use core::alloc::Layout;

use crate::acpi_types::*;

use cstr_core::CStr;
use log::{debug, info, trace, warn};

use x86::current::paging::BASE_PAGE_SIZE;

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
            *reg = object.Integer.Value;
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
                let entry_type: AcpiSratType = mem::transmute((*entry).Type as i32);

                match entry_type {
                    AcpiSratType::ACPI_SRAT_TYPE_CPU_AFFINITY => {
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
                    AcpiSratType::ACPI_SRAT_TYPE_MEMORY_AFFINITY => {
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
                    AcpiSratType::ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY => {
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
            let entry_type: AcpiMadtType = mem::transmute((*entry).Type as i32);

            const ACPI_MADT_ENABLED: u32 = 0x1;

            match entry_type {
                AcpiMadtType::ACPI_MADT_TYPE_LOCAL_APIC => {
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
                AcpiMadtType::ACPI_MADT_TYPE_LOCAL_X2APIC => {
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
                AcpiMadtType::ACPI_MADT_TYPE_IO_APIC => {
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

//TODO: Move this to acpica-sys repo.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Struct_acpi_nfit_platform_capabilities {
    pub Header: ACPI_NFIT_HEADER,
    pub HighestValidCapability: UINT8,
    pub Reserved: [UINT8; 3usize],
    pub Capabilities: UINT32,
    pub Reserved1: UINT32,
}
pub type ACPI_NFIT_PLATFORM_CAPABILITIES = Struct_acpi_nfit_platform_capabilities;

// https://uefi.org/specs/ACPI/6.4/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#nvdimm-firmware-interface-table-nfit
pub fn process_nfit() -> Vec<MemoryDescriptor> {
    let mut pmem_descriptors = Vec::with_capacity(8);

    unsafe {
        let nfit_handle = CStr::from_bytes_with_nul_unchecked(b"NFIT\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            nfit_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        if ret == AE_OK {
            let nfit_tbl_ptr = table_header as *const ACPI_TABLE_NFIT;
            let nfit_table_len = (*nfit_tbl_ptr).Header.Length as usize;
            let nfit_table_end = (nfit_tbl_ptr as *const c_void).add(nfit_table_len);
            debug!("Discoverd NVDIMM(s), table length {:?}", nfit_table_len);

            let mut iterator =
                (nfit_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_NFIT>());
            while iterator < nfit_table_end {
                let header = iterator as *const ACPI_NFIT_HEADER;
                let entry_type: Enum_AcpiNfitType = mem::transmute((*header).Type as i32);

                match entry_type {
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_SYSTEM_ADDRESS => {
                        let entry = iterator as *const ACPI_NFIT_SYSTEM_ADDRESS;
                        let mem_desc = parse_nfit_spa_range_structure(entry);
                        pmem_descriptors.push(mem_desc);
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_MEMORY_MAP => {
                        let entry = iterator as *const ACPI_NFIT_MEMORY_MAP;
                        log_nfit_region_mapping_structure(entry);
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_INTERLEAVE => {
                        let entry = iterator as *const ACPI_NFIT_INTERLEAVE;
                        log_nfit_interleave_structure(entry);
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_SMBIOS => {
                        warn!("Unable to handle ACPI_NFIT_SMBIOS table")
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_CONTROL_REGION => {
                        let entry = iterator as *const ACPI_NFIT_CONTROL_REGION;
                        log_nfit_control_region_structure(entry);
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_DATA_REGION => {
                        warn!("Unable to handle ACPI_NFIT_DATA_REGION table")
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_FLUSH_ADDRESS => {
                        let entry = iterator as *const ACPI_NFIT_FLUSH_ADDRESS;
                        log_nfit_flush_hint_structure(entry);
                    }
                    Enum_AcpiNfitType::ACPI_NFIT_TYPE_RESERVED => {
                        let entry = iterator as *const ACPI_NFIT_PLATFORM_CAPABILITIES;
                        log_nfit_platform_capabilities_structure(entry);
                    }
                    _ => unreachable!(),
                }
                iterator = iterator.add((*header).Length as usize);
            }
        } else {
            debug!("ACPI NFIT Table not found.");
        }
        pmem_descriptors
    }
}

#[repr(C, packed)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    index8: u8,
    index9: u8,
    index10: u8,
    index11: u8,
    index12: u8,
    index13: u8,
    index14: u8,
    index15: u8,
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X}, {:#X} }}",
            self.data1,
            self.data2,
            self.data3,
            self.index8,
            self.index9,
            self.index10,
            self.index11,
            self.index12,
            self.index13,
            self.index14,
            self.index15
        )
    }
}

impl From<&[u8; 16]> for Guid {
    fn from(slice: &[u8; 16]) -> Guid {
        // Check size and alignment for Guid
        static_assertions::assert_eq_size!([u8; 16], Guid);
        static_assertions::assert_eq_align!([u8; 16], Guid);

        let p: *const [u8; core::mem::size_of::<Guid>()] =
            slice.as_ptr() as *const [u8; core::mem::size_of::<Guid>()];
        unsafe { core::mem::transmute(*p) }
    }
}

// To parse DeviceHandle in ACPI_NFIT_MEMORY_MAP and ACPI_NFIT_FLUSH_ADDRESS subtables
const ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK: u32 = 0xf;
const ACPI_NFIT_DEVICE_HANDLE_12BIT_MASK: u32 = 0xfff;

// NFIT subtable type = 0x0
fn parse_nfit_spa_range_structure(entry: *const ACPI_NFIT_SYSTEM_ADDRESS) -> MemoryDescriptor {
    unsafe {
        assert_eq!((*entry).Header.Type, 0);
        debug!(
            "ACPI_NFIT_SYSTEM_ADDRESS - Type {}, Length {},
                RangeIndex: {},
                Flags: {},
                ProximityDomain: {},
                RangeGuid: {:x?},
                Address: 0x{:x},
                Length: {} Bytes,
                MemoryMapping: {:?}",
            (*entry).Header.Type,
            (*entry).Header.Length,
            (*entry).RangeIndex,
            (*entry).Flags,
            (*entry).ProximityDomain,
            Guid::from(&(*entry).RangeGuid),
            (*entry).Address,
            (*entry).Length,
            MemoryAttribute::from((*entry).MemoryMapping)
        );

        assert_eq!(
            (*entry).Length % BASE_PAGE_SIZE as u64,
            0,
            "Not multiple of page-size."
        );
        MemoryDescriptor {
            ty: MemoryType::PERSISTENT_MEMORY,
            padding: 0,
            phys_start: (*entry).Address,
            virt_start: 0,
            page_count: (*entry).Length / BASE_PAGE_SIZE as u64,
            att: MemoryAttribute::from((*entry).MemoryMapping),
        }
    }
}

// NFIT subtable type = 0x1
fn log_nfit_region_mapping_structure(entry: *const ACPI_NFIT_MEMORY_MAP) {
    // To parse Flags
    const ACPI_NFIT_MEM_SAVE_FAILED: u32 = 0x1; /* 00: Last SAVE to Memory Device failed */
    const ACPI_NFIT_MEM_RESTORE_FAILED: u32 = 0x1 << 1; /* 01: Last RESTORE from Memory Device failed */
    const ACPI_NFIT_MEM_FLUSH_FAILED: u32 = 0x1 << 2; /* 02: Platform flush failed */
    const ACPI_NFIT_MEM_NOT_ARMED: u32 = 0x1 << 3; /* 03: Memory Device is not armed */
    const ACPI_NFIT_MEM_HEALTH_OBSERVED: u32 = 0x1 << 4; /* 04: Memory Device observed SMART/health events */
    const ACPI_NFIT_MEM_HEALTH_ENABLED: u32 = 0x1 << 5; /* 05: SMART/health events enabled */
    const ACPI_NFIT_MEM_MAP_FAILED: u32 = 0x1 << 6; /* 06: Mapping to SPA failed */

    unsafe {
        assert_eq!((*entry).Header.Type, 1);
        debug!(
            "ACPI_NFIT_TYPE_MEMORY_MAP - Type {}, Length {}
                NfitDeviceHandle: 0x{:x},
                NfitDeviceHandle.DimmNumber: 0x{:x},
                NfitDeviceHandle.MemChannel: 0x{:x},
                NfitDeviceHandle.MemControllerId: 0x{:x},
                NfitDeviceHandle.SocketId: 0x{:x},
                NfitDeviceHandle.NodeControllerId: 0x{:x},
                PhysicalId: {},
                RegionId: {},
                RangeIndex: {},
                RegionIndex: {},
                RegionSize: {},
                RegionOffset: {},
                Address: {},
                InterleaveIndex: {},
                InterleaveWays: {},
                Flags: {}",
            (*entry).Header.Type,
            (*entry).Header.Length,
            (*entry).DeviceHandle,
            (*entry).DeviceHandle & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 4) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 8) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 12) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 16) & ACPI_NFIT_DEVICE_HANDLE_12BIT_MASK,
            (*entry).PhysicalId,
            (*entry).RegionId,
            (*entry).RangeIndex,
            (*entry).RegionIndex,
            (*entry).RegionSize,
            (*entry).RegionOffset,
            (*entry).Address,
            (*entry).InterleaveIndex,
            (*entry).InterleaveWays,
            (*entry).Flags,
        );
    }
}

// NFIT subtable type = 0x2
fn log_nfit_interleave_structure(entry: *const ACPI_NFIT_INTERLEAVE) {
    unsafe {
        assert_eq!((*entry).Header.Type, 2);
        debug!(
            "ACPI_NFIT_TYPE_INTERLEAVE - Type {}, Length {}
            InterleaveStructureIndex: {:#x}
            NumberOfLinesDescribed: {:#x}
            LineOffset: {:#x}
            LineSize: {:#x}",
            (*entry).Header.Type,
            (*entry).Header.Length,
            (*entry).InterleaveIndex,
            (*entry).LineCount,
            (*entry).LineOffset[0],
            (*entry).LineSize
        );
    }
}

// NFIT subtable type = 0x4
fn log_nfit_control_region_structure(entry: *const ACPI_NFIT_CONTROL_REGION) {
    unsafe {
        assert_eq!((*entry).Header.Type, 4);
        debug!(
            "ACPI_NFIT_TYPE_CONTROL_REGION - Type {}, Length {}
                RegionIndex: {},
                VendorId: {},
                DeviceId: {},
                RevisionId: {},
                SubsystemVendorId: {},
                SubsystemDeviceId: {},
                SubsystemRevisionId: {},
                Reserved: {:?},
                SerialNumber: {},
                Code: {},
                Windows: {},
                WindowSize: {},
                CommandOffset: {},
                CommandSize: {},
                StatusOffset: {},
                StatusSize: {},
                Flags: {}",
            (*entry).Header.Type,
            (*entry).Header.Length,
            (*entry).RegionIndex,
            (*entry).VendorId,
            (*entry).DeviceId,
            (*entry).RevisionId,
            (*entry).SubsystemVendorId,
            (*entry).SubsystemDeviceId,
            (*entry).SubsystemRevisionId,
            (*entry).Reserved,
            (*entry).SerialNumber,
            (*entry).Code,
            (*entry).Windows,
            (*entry).WindowSize,
            (*entry).CommandOffset,
            (*entry).CommandSize,
            (*entry).StatusOffset,
            (*entry).StatusSize,
            (*entry).Flags,
        );
    }
}

// NFIT subtable type 0x6
fn log_nfit_flush_hint_structure(entry: *const ACPI_NFIT_FLUSH_ADDRESS) {
    unsafe {
        assert_eq!((*entry).Header.Type, 6);
        debug!(
            "ACPI_NFIT_TYPE_FLUSH_ADDRESS - Type {}, Length {}
            NfitDeviceHandle: {:#x}
            NfitDeviceHandle.DimmNumber: {:#x}
            NfitDeviceHandle.MemChannel: {:#x}
            NfitDeviceHandle.MemControllerId: {:#x}
            NfitDeviceHandle.SocketId: {:#x}
            NfitDeviceHandle.NodeControllerId: {:#x}
            NumberOfFlushHintAddresses: {:#x}
            FlushHintAddress 0: {:#x}",
            (*entry).Header.Type,
            (*entry).Header.Length,
            (*entry).DeviceHandle,
            (*entry).DeviceHandle & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 4) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 8) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 12) & ACPI_NFIT_DEVICE_HANDLE_4BIT_MASK,
            ((*entry).DeviceHandle >> 16) & ACPI_NFIT_DEVICE_HANDLE_12BIT_MASK,
            (*entry).HintCount,
            (*entry).HintAddress[0],
        );
    }
}

// NFIT subtable type = 0x7
fn log_nfit_platform_capabilities_structure(entry: *const ACPI_NFIT_PLATFORM_CAPABILITIES) {
    unsafe {
        const ACPI_NFIT_CACHE_FLUSH_ENABLED: u32 = 0x1;
        const ACPI_NFIT_CONTROLLER_FLUSH_ENABLED: u32 = 0x1 << 1;
        const ACPI_NFIT_HARDWARE_MIRRORING_CAPABLE: u32 = 0x1 << 2;

        assert_eq!((*entry).Header.Type, 7);
        debug!(
            "Capability {{ eADR: {}, ADR: {}, Mirroring: {} }}",
            (*entry).Capabilities & ACPI_NFIT_CACHE_FLUSH_ENABLED > 0,
            (*entry).Capabilities & ACPI_NFIT_CONTROLLER_FLUSH_ENABLED > 0,
            (*entry).Capabilities & ACPI_NFIT_HARDWARE_MIRRORING_CAPABLE > 0
        );
    }
}
