//! ACPI types which are parsed from tables (see also `acpi.rs`).

use core::fmt;

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
    /// Proximity domain to which the processor belongs.
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
    /// Start of the affinity region
    pub fn start(&self) -> u64 {
        self.base_address
    }

    /// End of the affinity region
    pub fn end(&self) -> u64 {
        self.base_address + self.length
    }

    /// Splits a provided memory range into three sub-ranges (a, b, c).
    /// where
    ///  - a is the sub-range of input that comes before this MemoryAffinity.
    ///  - b is the sub-range of input that fits within this MemoryAffinity.
    ///  - c is the sub-range of input that comes after this MemoryAffinity.
    ///
    /// At any point two of (a, b, c) may return (0, 0) is there is no overlap.
    pub fn contains(&self, start: u64, end: u64) -> ((u64, u64), (u64, u64), (u64, u64)) {
        debug_assert!(start <= end);

        let below_range = if start < self.start() {
            (start, self.start())
        } else {
            (0, 0)
        };

        let in_range = if start <= self.start() && end >= self.end() {
            // Contains the self
            (self.start(), self.end())
        } else if end < self.end() && start > self.start() {
            // Range fully contained within self
            (start, end)
        } else if end > self.start() && end < self.end() {
            // Contains beginning of self
            (self.start(), end)
        } else if start > self.start() && start < self.end() {
            // Contains end of self
            (start, self.end())
        } else {
            (0, 0)
        };

        let above_range = if end > self.end() {
            (self.end(), end)
        } else {
            (0, 0)
        };

        (below_range, in_range, above_range)
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
#[derive(Debug, Eq, PartialEq, Default)]
pub struct MaximumSystemCharacteristics {
    /// Offset in bytes to the Proximity Domain Information Structure table entry.
    pub proximity_offset: u32,

    /// Indicates the maximum number of Proximity Domains ever possible in the system.
    /// The number reported in this field is (maximum domains – 1).
    pub max_proximity_domain: u32,

    /// Indicates the maximum number of Clock Domains ever possible in the system.
    /// The number reported in this field is (maximum domains – 1).
    ///
    /// See also: “_CDM (Clock Domain)”.
    pub max_clock_domains: u32,

    /// Indicates the maximum Physical Address ever possible in the system.
    ///
    /// # Note
    /// This is the top of the reachable physical address.
    pub max_address: u64,
}

/// Information about maximum supported instances in the system.
#[derive(Debug, Eq, PartialEq)]
pub struct MaximumProximityDomainInfo {
    /// The starting proximity domain for the proximity domain range that
    /// this structure is providing information.
    pub range_start: u32,
    /// The ending proximity domain for the proximity domain range that
    /// this structure is providing information.
    pub range_end: u32,
    /// The Maximum Processor Capacity of each of the Proximity Domains specified in the range.
    ///
    /// A value of 0 means that the proximity domains do not contain processors.
    /// This field must be>= the number of processor entries for the domain in the SRAT.
    pub processor_capacity: u32,
    /// Maximum Memory Capacity (size in bytes) of the Proximity Domains specified in the range.
    /// A value of 0 means that the proximity domains do not contain memory
    pub memory_capacity: u64,
}
