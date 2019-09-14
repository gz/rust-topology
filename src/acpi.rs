//! ACPI parsing functionality for relevant topology information.
use acpica_sys::*;

use core::fmt;
use core::mem;
use core::ptr;

use crate::alloc::alloc;
use crate::alloc::vec::Vec;
use core::alloc::Layout;

use cstr_core::CStr;
use log::{debug, info, trace, warn};

const ACPI_FULL_PATHNAME: u32 = 0;
const ACPI_TYPE_INTEGER: u32 = 0x01;

/// The I/O APIC structure declares which global system interrupts are uniquely
/// associated with the I/O APIC interrupt inputs
///
/// Each I/O APIC has a series of interrupt inputs, referred to as INTn, where the
/// value of n is from 0 to the number of the last interrupt input on the I/O APIC.
#[derive(Eq, PartialEq)]
pub struct IoApic {
    /// The I/O APIC’s ID.
    pub id: u8,
    /// The 32-bit physical address to access this I/O APIC.
    /// Each I/O APIC resides at a unique address.
    pub address: u32,
    /// The global system interrupt number where this I/O APIC’s interrupt
    /// inputs start. The number of interrupt inputs is determined by the I/O
    /// APIC’s max redir entry register.
    pub global_irq_base: u32,
}

impl fmt::Debug for IoApic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Hex(u32);
        impl fmt::Debug for Hex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }
        let mut s = f.debug_struct("IoApic");
        s.field("id", &self.id);
        s.field("address", &Hex(self.address));
        s.field("global_irq_base", &self.global_irq_base);

        s.finish()
    }
}

/// Association between the APIC ID or SAPIC ID/EID of a processor
/// and the proximity domain to which the processor belongs.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalApicAffinity {
    /// Processor local APIC ID.
    pub apic_id: u8,
    /// Processor local SAPIC EID.
    pub sapic_eid: u8,
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// The clock domain to which the processor belongs to.
    pub clock_domain: u32,
    /// True if the entry refers to an enabled local APIC.
    pub enabled: bool,
}

/// The Memory Affinity structure provides the following topology information
/// statically to the operating system:
///
/// - The association between a range of memory and the proximity domain to which it belongs
/// - Information about whether the range of memory can be hot-plugged.
#[derive(Eq, PartialEq)]
pub struct MemoryAffinity {
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// Base Address of the memory range.
    pub base_address: u64,
    /// Length of the memory range.
    pub length: u64,
    /// True if the entry refers to enabled memory.
    pub enabled: bool,
    /// System hardware supports hot-add and hot-remove of this memory region.
    pub hotplug_capable: bool,
    /// The memory region represents Non-Volatile memory.
    pub non_volatile: bool,
}

impl MemoryAffinity {
    fn start(&self) -> u64 {
        self.base_address
    }

    fn end(&self) -> u64 {
        self.base_address + self.length
    }
}

impl fmt::Debug for MemoryAffinity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MemoryAffinity {{ {:#x} -- {:#x}, node#{} }}",
            self.start(),
            self.end(),
            self.proximity_domain
        )
    }
}

/// Processor Local x2APIC Affinity structure provides the association
/// between the local x2APIC ID of a processor and the proximity domain
/// to which the processor belongs.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalX2ApicAffinity {
    /// Processor local x2APIC ID.
    pub x2apic_id: u32,
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// The clock domain to which the processor belongs to.
    pub clock_domain: u32,
    /// True if the entry refers to an enabled local x2APIC.
    pub enabled: bool,
}

/// Information about local APICs (cores) in the system.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalApic {
    /// The processor’s local APIC ID.
    pub apic_id: u8,
    /// The ProcessorId for which this processor is listed in the ACPI
    /// Processor declaration operator. For a definition of the Processor
    /// operator, see Section 19.5.100, “Processor (Declare Processor).”
    pub processor_id: u8,
    /// If zero, this processor is unusable, and the operating system support will not attempt to use it.
    pub enabled: bool,
}

/// Information about local APICs (cores) in the system with ID's higher than 255.
///
/// ACPI will store the first 255 cores as LocalApics, and afterwards will use
/// LocalX2APIC entries.
///
/// # Note
/// The Processor X2APIC structure is very similar to the processor local APIC
/// structure. When using the X2APIC interrupt model, logical processors with APIC
/// ID values of 255 and greater are required to have a Processor Device object and
/// must convey the processor’s APIC information to OSPM using the Processor Local
/// X2APIC structure. Logical processors with APIC ID values less than 255 must use
/// the Processor Local APIC structure to convey their APIC information to OSPM.
/// OSPM does not expect the information provided in this table to be updated if
/// the processor information changes during the lifespan of an OS boot. While in
/// the sleeping state, logical processors must not be added or removed, nor can
/// their X2APIC ID or x2APIC Flags change. When a logical processor is not
/// present, the processor local X2APIC information is either not reported or
/// flagged as disabled.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalX2Apic {
    /// The processor’s local x2APIC ID.
    pub apic_id: u32,
    /// Corresponding processor
    ///
    /// OSPM associates the X2APIC Structure with a processor object declared in
    /// the namespace using the Device statement, when the
    /// _UID child object of the processor device evaluates to a numeric
    /// value, by matching the numeric value with this field
    pub processor_id: u32,
    /// If zero, this processor is unusable, and the operating system support will not attempt to use it.
    pub enabled: bool,
}

/// Information about maximum supported instances in the system.
#[derive(Debug, Eq, PartialEq)]
pub struct MaximumProximityDomainInfo {
    /// Offset in bytes to the Proximity Domain Information Structure table entry.
    proximity_offset: u32,

    /// Indicates the maximum number of Proximity Domains ever possible in the system.
    /// The number reported in this field is (maximum domains – 1).
    max_proximity_domain: u32,

    /// Indicates the maximum number of Clock Domains ever possible in the system.
    /// The number reported in this field is (maximum domains – 1).
    ///
    /// See also: “_CDM (Clock Domain)”.
    max_clock_domains: u32,

    /// Indicates the maximum Physical Address ever possible in the system.
    ///
    /// # Note
    /// This is the top of the reachable physical address.
    max_address: u64,
}

#[allow(unused)]
fn acpi_get_integer(handle: ACPI_HANDLE, name: *const i8, reg: &mut ACPI_INTEGER) -> ACPI_STATUS {
    unsafe {
        let mut object: ACPI_OBJECT = mem::zeroed();
        let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
            Length: mem::size_of::<ACPI_OBJECT>() as u64,
            Pointer: &mut object as *mut _ as *mut acpica_sys::c_void,
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
            _context: *mut acpica_sys::c_void,
            _return_value: *mut *mut acpica_sys::c_void,
        ) -> u32 {
            let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
                Length: 256,
                Pointer: alloc::alloc(Layout::from_size_align_unchecked(128, 0x1))
                    as *mut acpica_sys::c_void,
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
                    _ => warn!("Unhandled SRAT entry {:?}", entry_type),
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
                _ => warn!("Unhandled entry {:?}", entry_type),
            }

            assert!((*entry).Length > 0);
            iterator = iterator.add((*entry).Length as usize);
        }
    }

    (cores, x2apic_cores, io_apics)
}

/// Parse the MSCT table (maximum system characteristics for the platform).
/// Returns all entries as a vector of MaximumProximityDomainInfo (or an empty vector
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
pub fn process_msct() -> Vec<MaximumProximityDomainInfo> {
    unsafe {
        let msct_handle = CStr::from_bytes_with_nul_unchecked(b"MSCT");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            msct_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        if ret != AE_OK {
            return Vec::new();
        }

        let msct_tbl_ptr = table_header as *const ACPI_TABLE_MSCT;
        let msct_table_len = (*msct_tbl_ptr).Header.Length as usize;
        let msct_table_end = (msct_tbl_ptr as *const c_void).add(msct_table_len);

        debug!(
            "MSCT Table: Rev={} Len={} OemID={:?}",
            (*msct_tbl_ptr).Header.Revision,
            msct_table_len,
            (*msct_tbl_ptr).Header.OemId
        );

        let mut max_prox_domains = Vec::with_capacity(24);
        let mut iterator = (msct_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_MSCT>());
        while iterator < msct_table_end {
            let entry: *const Struct_acpi_table_msct = iterator as *const Struct_acpi_table_msct;

            trace!("MSCT entry: {:?}", entry);
            max_prox_domains.push(MaximumProximityDomainInfo {
                proximity_offset: (*entry).ProximityOffset,
                max_proximity_domain: (*entry).MaxProximityDomains,
                max_clock_domains: (*entry).MaxClockDomains,
                max_address: (*entry).MaxAddress,
            });
            assert_eq!((*entry).Header.Length, 22);
            iterator = iterator.add((*entry).Header.Length as usize);
        }

        max_prox_domains
    }
}
