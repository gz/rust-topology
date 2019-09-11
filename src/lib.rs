//! Interface to query information about the underlying hardware.
//!
//! Our naming scheme follows the Intel x86/ACPI convention
//! which has a thread/core/package/NUMA node hierarchy:
//!
//! * thread: Hardware scheduling unit (has an APIC, is an app or core bsp core)
//! * core: one or more threads (usually 2)
//! * package: one or more cores (usually a socket with a shared LLC)
//! * affinity region: a NUMA node (consists of a bunch of threads/core/packages and memory regions)
//!
//! Intel Topology is a pretty complicated subject (unfortunately), relevant documentation is here:
//! * https://software.intel.com/en-us/articles/intel-64-architecture-processor-topology-enumeration/
//! * https://acpica.org/documentation
//!
#![no_std]

extern crate alloc;
extern crate core;
#[macro_use]
extern crate lazy_static;

mod acpi;

use alloc::vec::Vec;
use core::fmt;

use log::info;

/// Silly helper trait for computing power of two
trait PowersOf2 {
    fn log2(self) -> u8;
}

impl PowersOf2 for u8 {
    fn log2(self) -> u8 {
        7 - self.leading_zeros() as u8
    }
}

use acpi::{
    process_madt, process_msct, process_srat, IoApic, LocalApic, LocalX2Apic,
    MaximumProximityDomainInfo, MemoryAffinity,
};

/// A system global ID for a CPU.
pub type GlobalThreadId = u64;

/// A hardware scheduling unit (has an APIC), (unique within a core).
pub type ThreadId = u64;

/// A core, with one or more threads (unique within a packet).
pub type CoreId = u64;

/// A socket with one or more cores (usually with a shared LLC).
pub type PackageId = u64;

/// Affinity region, a NUMA node (consists of a bunch of threads/core/packages and memory regions).
pub type NodeId = u64;

/// Identifies a thread by its x2APIC ID (unique in the system).
pub type X2ApicId = u32;

/// Identifies a thread by its APIC ID (unique in the system).
pub type ApicId = u8;

/// Differentiate between local APICs and X2APICs.
#[derive(Eq, PartialEq, Debug, Ord, PartialOrd)]
enum ApicThreadInfo {
    Apic(LocalApic),
    X2Apic(LocalX2Apic),
}

impl ApicThreadInfo {
    fn id(&self) -> u32 {
        match &self {
            ApicThreadInfo::Apic(apic) => apic.apic_id.into(),
            ApicThreadInfo::X2Apic(x2apic) => x2apic.apic_id,
        }
    }
}

/// Represents an SMT thread in the system.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct Thread {
    /// ID the thread, global within a system.
    pub id: GlobalThreadId,
    /// ID of the NUMA node (system global)
    pub node_id: Option<NodeId>,
    /// ID of the package (system global)
    pub package_id: PackageId,
    /// ID of the core
    pub core_id: CoreId,
    /// ID of the thread (usually between 0..1)
    pub thread_id: ThreadId,
    /// Thread is represented either by a LocalApic or LocalX2Apic entry.
    apic: ApicThreadInfo,
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Thread")
            .field("id", &self.id)
            .field("apic_id", &self.apic.id())
            .field(
                "thread/core/package",
                &(self.thread_id, self.core_id, self.package_id),
            )
            .field("numa_node", &self.node_id)
            .finish()
    }
}

impl Thread {
    /// Construct a thread with a LocalApic struct.
    fn new_with_apic(
        global_id: GlobalThreadId,
        apic: LocalApic,
        node_id: Option<NodeId>,
    ) -> Thread {
        let (thread_id, core_id, package_id) = get_topology_from_apic_id(apic.apic_id);
        Thread {
            id: global_id,
            apic: ApicThreadInfo::Apic(apic),
            thread_id: thread_id,
            core_id: core_id,
            package_id: package_id,
            node_id: node_id,
        }
    }

    /// Construct a thread with a LocalX2Apic struct.
    fn new_with_x2apic(
        global_id: GlobalThreadId,
        apic: LocalX2Apic,
        node_id: Option<NodeId>,
    ) -> Thread {
        let (thread_id, core_id, package_id) = get_topology_from_x2apic_id(apic.apic_id);

        Thread {
            id: global_id,
            apic: ApicThreadInfo::X2Apic(apic),
            thread_id: thread_id,
            core_id: core_id,
            package_id: package_id,
            node_id: node_id,
        }
    }

    /// APIC ID (unique in the system)
    pub fn apic_id(&self) -> Option<ApicId> {
        match &self.apic {
            ApicThreadInfo::Apic(apic) => Some(apic.apic_id),
            _ => None,
        }
    }

    /// x2APIC ID (unique in the system)
    pub fn x2apic_id(&self) -> Option<X2ApicId> {
        match &self.apic {
            ApicThreadInfo::X2Apic(x2apic) => Some(x2apic.apic_id),
            _ => None,
        }
    }

    /// All neighboring threads (on the same core)
    pub fn siblings(&'static self) -> impl Iterator<Item = &'static Thread> {
        MACHINE_TOPOLOGY
            .threads()
            .filter(move |t| t.package_id == self.package_id && t.core_id == self.core_id)
    }

    /// Return the `Core` this thread belongs to.
    pub fn core(&'static self) -> &'static Core {
        MACHINE_TOPOLOGY
            .cores()
            .filter(move |core| core.package_id == self.package_id && core.id == self.core_id)
            .next()
            .unwrap()
    }

    /// Return the `Package` this thread belongs to.
    pub fn package(&'static self) -> &'static Package {
        MACHINE_TOPOLOGY
            .packages()
            .filter(move |package| package.id == self.package_id)
            .next()
            .unwrap()
    }

    /// Return the NUMA node this thread belongs to.
    pub fn node(&'static self) -> Option<&'static Node> {
        self.node_id.and_then(|nid| {
            MACHINE_TOPOLOGY
                .nodes()
                .filter(move |node| node.id == nid)
                .next()
        })
    }
}

/// Represents a core in the system.
///
/// # Note
/// The order is important here, when Ord is derived on structs, it will produce a
/// lexicographic ordering based on the top-to-bottom declaration order of the struct's members.
#[derive(Eq, PartialEq, Debug, Ord, PartialOrd)]
pub struct Core {
    /// NUMA node
    pub node_id: Option<NodeId>,
    /// Package ID
    pub package_id: PackageId,
    /// Core ID (which is relative within the package).
    pub id: CoreId,
}

impl Core {
    fn new(node_id: Option<NodeId>, package_id: PackageId, id: CoreId) -> Core {
        Core {
            node_id,
            package_id,
            id,
        }
    }

    /// All neighboring cores (on the same package)
    pub fn siblings(&'static self) -> impl Iterator<Item = &'static Core> {
        MACHINE_TOPOLOGY
            .cores()
            .filter(move |c| c.package_id == self.package_id)
    }

    /// All threads of the core.
    pub fn threads(&'static self) -> impl Iterator<Item = &'static Thread> {
        MACHINE_TOPOLOGY
            .threads()
            .filter(move |t| t.package_id == self.package_id && t.core_id == self.id)
    }

    /// Return the `Package` this core belongs to.
    pub fn package(&'static self) -> &'static Package {
        MACHINE_TOPOLOGY
            .packages()
            .filter(move |package| package.id == self.package_id)
            .next()
            .unwrap()
    }

    /// Return the NUMA node this core belongs to.
    pub fn node(&'static self) -> Option<&'static Node> {
        self.node_id.and_then(|nid| {
            MACHINE_TOPOLOGY
                .nodes()
                .filter(move |node| node.id == nid)
                .next()
        })
    }
}

/// Represents a package/socket in the system.
#[derive(Eq, PartialEq, Debug, Ord, PartialOrd)]
pub struct Package {
    /// Package ID
    pub id: PackageId,
    /// NUMA node
    pub node_id: Option<NodeId>,
}

impl Package {
    fn new(id: PackageId, node_id: Option<NodeId>) -> Package {
        Package { id, node_id }
    }

    /// All packages of the machine.
    pub fn siblings(&self) -> impl Iterator<Item = &'static Package> {
        MACHINE_TOPOLOGY.packages()
    }

    /// All threads of the package.
    pub fn threads(&'static self) -> impl Iterator<Item = &'static Thread> {
        MACHINE_TOPOLOGY
            .threads()
            .filter(move |t| t.package_id == self.id)
    }

    /// All cores of the package.
    pub fn cores(&'static self) -> impl Iterator<Item = &'static Core> {
        MACHINE_TOPOLOGY
            .cores()
            .filter(move |c| c.package_id == self.id)
    }

    /// Return the NUMA node this core belongs to.
    pub fn node(&'static self) -> Option<&'static Node> {
        self.node_id.and_then(|nid| {
            MACHINE_TOPOLOGY
                .nodes()
                .filter(move |node| node.id == nid)
                .next()
        })
    }
}

/// Represents a NUMA node in the system.
#[derive(Eq, PartialEq, Debug, Ord, PartialOrd)]
pub struct Node {
    pub id: NodeId,
}

impl Node {
    /// Construct a node
    fn new(id: NodeId) -> Node {
        Node { id }
    }

    /// All NUMA nodes of the system.
    pub fn siblings(&self) -> impl Iterator<Item = &'static Node> {
        MACHINE_TOPOLOGY.nodes()
    }

    pub fn memory(&'static self) -> impl Iterator<Item = &'static MemoryAffinity> {
        MACHINE_TOPOLOGY
            .memory_affinity
            .iter()
            .filter(move |ma| ma.proximity_domain as NodeId == self.id)
    }

    /// All threads of the NUMA node.
    pub fn threads(&'static self) -> impl Iterator<Item = &'static Thread> {
        MACHINE_TOPOLOGY
            .threads()
            .filter(move |t| t.node_id == Some(self.id))
    }

    /// All cores of the NUMA node.
    pub fn cores(&'static self) -> impl Iterator<Item = &'static Core> {
        MACHINE_TOPOLOGY
            .cores()
            .filter(move |c| c.node_id == Some(self.id))
    }

    /// All packages of the NUMA node.
    pub fn packages(&'static self) -> impl Iterator<Item = &'static Package> {
        MACHINE_TOPOLOGY
            .packages()
            .filter(move |p| p.node_id == Some(self.id))
    }
}

/// Given APIC ID, figure out package, core and thread ID.
fn get_topology_from_apic_id(xapic_id: u8) -> (ThreadId, CoreId, PackageId) {
    let cpuid = x86::cpuid::CpuId::new();

    // Determine the maximum processors count
    let max_logical_processor_ids = cpuid
        .get_feature_info()
        .map_or_else(|| 0, |finfo| finfo.max_logical_processor_ids());

    // Determine max cores per package
    let mut smt_max_cores_for_package: u8 = 0;
    cpuid.get_cache_parameters().map_or_else(
        || (/* Out of luck */),
        |cparams| {
            for (ecx, cache) in cparams.enumerate() {
                if ecx == 0 {
                    smt_max_cores_for_package = cache.max_cores_for_package() as u8;
                }
            }
        },
    );

    let smt_mask_width: u8 =
        u8::log2(max_logical_processor_ids.next_power_of_two() / (smt_max_cores_for_package));
    let smt_select_mask: u8 = !(u8::max_value() << smt_mask_width);

    let core_mask_width: u8 = u8::log2(smt_max_cores_for_package);
    let core_only_select_mask =
        (!(u8::max_value() << (core_mask_width + smt_mask_width))) ^ smt_select_mask;

    let pkg_select_mask = u8::max_value() << (core_mask_width + smt_mask_width);

    let smt_id = xapic_id & smt_select_mask;
    let core_id = (xapic_id & core_only_select_mask) >> smt_mask_width;
    let pkg_id = (xapic_id & pkg_select_mask) >> (core_mask_width + smt_mask_width);

    (smt_id.into(), core_id.into(), pkg_id.into())
}

/// Given x2APIC ID, figure out package, core and thread ID.
fn get_topology_from_x2apic_id(x2apic_id: u32) -> (ThreadId, CoreId, PackageId) {
    use x86::cpuid::{ExtendedTopologyLevel, TopologyType};
    let cpuid = x86::cpuid::CpuId::new();
    let mut smt_x2apic_shift: u32 = 0;
    let mut core_x2apic_shift: u32 = 0;

    cpuid.get_extended_topology_info().map_or_else(
        || (/* No topology information available */),
        |topoiter| {
            let topology: Vec<ExtendedTopologyLevel> = topoiter.collect();
            for topolevel in topology.iter() {
                match topolevel.level_type() {
                    TopologyType::SMT => {
                        smt_x2apic_shift = topolevel.shift_right_for_next_apic_id();
                    }
                    TopologyType::Core => {
                        core_x2apic_shift = topolevel.shift_right_for_next_apic_id();
                    }
                    _ => panic!("Topology category not supported."),
                };
            }
        },
    );

    let smt_select_mask = !(u32::max_value() << smt_x2apic_shift);
    let core_select_mask = (!((u32::max_value()) << core_x2apic_shift)) ^ smt_select_mask;
    let pkg_select_mask = u32::max_value() << core_x2apic_shift;

    let smt_id = x2apic_id & smt_select_mask;
    let core_id = (x2apic_id & core_select_mask) >> smt_x2apic_shift;
    let pkg_id = (x2apic_id & pkg_select_mask) >> core_x2apic_shift;

    (smt_id.into(), core_id.into(), pkg_id.into())
}

lazy_static! {
    /// A struct that contains all information about current machine
    /// we're running on (discovered from ACPI Tables and cpuid).
    ///
    /// Should have some of the following:
    /// - Cores, NUMA nodes, Memory regions
    /// - Interrupt routing (I/O APICs, overrides) (TODO)
    /// - PCIe root complexes (TODO)
    pub static ref MACHINE_TOPOLOGY: MachineInfo = {
        // Let's get all the APIC information and transform it into a MachineInfo struct
        let (mut local_apics, mut local_x2apics, ioapics) = process_madt();
        let (mut core_affinity, mut x2apic_affinity, memory_affinity) = process_srat();
        let max_proximity_info = process_msct();

        local_apics.sort_by(|a, b| a.apic_id.cmp(&b.apic_id));
        local_x2apics.sort_by(|a, b| a.apic_id.cmp(&b.apic_id));

        core_affinity.sort_by(|a, b| a.apic_id.cmp(&b.apic_id));
        x2apic_affinity.sort_by(|a, b| a.x2apic_id.cmp(&b.x2apic_id));

        assert!(local_apics.len() == core_affinity.len() || core_affinity.len() == 0,
            "Either we have matching entries for core in affinity table or no affinity information at all.");

        // Make Thread objects out of APIC MADT entries:
        let mut global_thread_id: GlobalThreadId = 0;
        let mut threads = Vec::with_capacity(local_apics.len() + local_x2apics.len());

        // Add all local APIC entries
        for local_apic in local_apics {
            let affinity = core_affinity.pop();
            affinity.as_ref().map(|a| assert_eq!(a.apic_id, local_apic.apic_id, "The core_affinity and local_apic are not in the same order?"));
            let t = Thread::new_with_apic(global_thread_id, local_apic, affinity.map(|a| a.proximity_domain as u64));
            info!("Found {:?}", t);
            threads.push(t);
            global_thread_id = global_thread_id + 1;
        }

        // Add all x2APIC entries
        for local_x2apic in local_x2apics {
            let affinity = x2apic_affinity.pop();
            affinity.as_ref().map(|a| assert_eq!(a.x2apic_id, local_x2apic.apic_id, "The x2apic_affinity and local_x2apic are not in the same order?"));
            let t = Thread::new_with_x2apic(global_thread_id, local_x2apic, affinity.map(|a| a.proximity_domain as u64));
            info!("Found {:?}", t);
            global_thread_id = global_thread_id + 1;
        }

        // Next, we can construct the cores, packages, and nodes from threads
        let mut cores: Vec<Core> = threads.iter().map(|t| Core::new(t.node_id, t.package_id, t.core_id)).collect();
        cores.sort();
        cores.dedup();

        // Gather all packages
        let mut packages: Vec<Package> = threads.iter().map(|t| Package::new(t.package_id, t.node_id)).collect();
        packages.sort();
        packages.dedup();

        // Gather all nodes
        let mut nodes: Vec<Node> = threads
            .iter()
            .filter(|t| t.node_id.is_some())
            .map(|t| Node::new(t.node_id.unwrap_or(0)))
            .collect::<Vec<Node>>();
        nodes.sort();
        nodes.dedup();

        MachineInfo::new(
            threads,
            cores,
            packages,
            nodes,
            ioapics,
            memory_affinity,
            max_proximity_info,
        )
    };
}

/// Contains a condensed and filtered version of all data queried from ACPI and CPUID.
#[derive(Debug)]
pub struct MachineInfo {
    threads: Vec<Thread>,
    cores: Vec<Core>,
    packages: Vec<Package>,
    nodes: Vec<Node>,
    memory_affinity: Vec<MemoryAffinity>,
    io_apics: Vec<IoApic>,
    max_proximity_info: Vec<MaximumProximityDomainInfo>,
}

impl MachineInfo {
    /// Create a MachineInfo struct from ACPI information.
    fn new(
        threads: Vec<Thread>,
        cores: Vec<Core>,
        packages: Vec<Package>,
        nodes: Vec<Node>,
        io_apics: Vec<IoApic>,
        memory_affinity: Vec<MemoryAffinity>,
        max_proximity_info: Vec<MaximumProximityDomainInfo>,
    ) -> MachineInfo {
        MachineInfo {
            threads,
            cores,
            packages,
            nodes,
            memory_affinity,
            io_apics,
            max_proximity_info,
        }
    }

    /// Return the amount of threads in the system.
    pub fn num_threads(&self) -> usize {
        self.threads.len()
    }

    /// Return iterator over all threads in the system.
    pub fn threads(&'static self) -> impl Iterator<Item = &Thread> {
        self.threads.iter()
    }

    /// Return the amount of cores in the system.
    pub fn num_cores(&self) -> usize {
        self.cores.len()
    }

    /// Return iterator over all cores in the system.
    pub fn cores(&'static self) -> impl Iterator<Item = &Core> {
        self.cores.iter()
    }

    /// Return the amount of packages in the system.
    pub fn num_packages(&self) -> usize {
        self.packages.len()
    }

    /// Return iterator over all packages in the system.
    pub fn packages(&'static self) -> impl Iterator<Item = &Package> {
        self.packages.iter()
    }

    /// Return iterator over all NUMA nodes in the system.
    pub fn nodes(&'static self) -> impl Iterator<Item = &Node> {
        self.nodes.iter()
    }

    /// Return the amount of NUMA nodes in the system.
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Return an iterator over all I/O APICs in the system.
    pub fn io_apics(&'static self) -> impl Iterator<Item = &IoApic> {
        self.io_apics.iter()
    }
}
