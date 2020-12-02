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
#![no_std]

extern crate alloc;
extern crate core;
#[macro_use]
extern crate lazy_static;
extern crate cstr_core;
extern crate log;

mod acpi;
mod cpuid;

use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt;

use log::debug;

use x86::apic::ApicId;

use acpi::{
    process_madt, process_msct, process_srat, IoApic, LocalApic, LocalX2Apic,
    MaximumProximityDomainInfo, MaximumSystemCharacteristics, MemoryAffinity,
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

/// Differentiate between local APICs and X2APICs.
#[derive(Eq, PartialEq, Debug, Ord, PartialOrd)]
enum ApicThreadInfo {
    Apic(LocalApic),
    X2Apic(LocalX2Apic),
}

impl ApicThreadInfo {
    fn id(&self) -> ApicId {
        match &self {
            ApicThreadInfo::Apic(apic) => ApicId::XApic(apic.apic_id),
            ApicThreadInfo::X2Apic(x2apic) => ApicId::X2Apic(x2apic.apic_id),
        }
    }
}

/// Represents an SMT thread in the system.
#[derive(Ord, PartialOrd)]
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

impl PartialEq for Thread {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Thread {}

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
        let (thread_id, core_id, package_id) = cpuid::get_topology_from_apic_id(apic.apic_id);
        Thread {
            id: global_id,
            apic: ApicThreadInfo::Apic(apic),
            thread_id,
            core_id,
            package_id,
            node_id,
        }
    }

    /// Construct a thread with a LocalX2Apic struct.
    fn new_with_x2apic(
        global_id: GlobalThreadId,
        apic: LocalX2Apic,
        node_id: Option<NodeId>,
    ) -> Thread {
        let (thread_id, core_id, package_id) = cpuid::get_topology_from_x2apic_id(apic.apic_id);

        Thread {
            id: global_id,
            apic: ApicThreadInfo::X2Apic(apic),
            thread_id,
            core_id,
            package_id,
            node_id,
        }
    }

    /// APIC ID (unique in the system).
    pub fn apic_id(&self) -> ApicId {
        self.apic.id()
    }

    /// All neighboring threads (on the same core)
    pub fn siblings(&'static self) -> impl Iterator<Item = &'static Thread> {
        MACHINE_TOPOLOGY
            .threads()
            // Find all threads of our parent core
            .filter(move |t| t.package_id == self.package_id && t.core_id == self.core_id)
            // Exclude self
            .filter(move |t| t != &self)
    }

    /// Return the `Core` this thread belongs to.
    pub fn core(&'static self) -> &'static Core {
        MACHINE_TOPOLOGY
            .cores()
            .find(move |core| core.package_id == self.package_id && core.id == self.core_id)
            .unwrap()
    }

    /// Return the `Package` this thread belongs to.
    pub fn package(&'static self) -> &'static Package {
        MACHINE_TOPOLOGY
            .packages()
            .find(move |package| package.id == self.package_id)
            .unwrap()
    }

    /// Return the NUMA node this thread belongs to.
    pub fn node(&'static self) -> Option<&'static Node> {
        self.node_id
            .and_then(|nid| MACHINE_TOPOLOGY.nodes().find(move |node| node.id == nid))
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

    /// All neighboring cores (on the same core)
    pub fn siblings(&'static self) -> impl Iterator<Item = &'static Core> {
        MACHINE_TOPOLOGY
            .cores()
            // Find all cores on parent package
            .filter(move |c| c.package_id == self.package_id)
            // Exclude self
            .filter(move |c| c != &self)
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
            .find(move |package| package.id == self.package_id)
            .unwrap()
    }

    /// Return the NUMA node this core belongs to.
    pub fn node(&'static self) -> Option<&'static Node> {
        self.node_id
            .and_then(|nid| MACHINE_TOPOLOGY.nodes().find(move |node| node.id == nid))
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
    pub fn siblings(&'static self) -> impl Iterator<Item = &'static Package> {
        MACHINE_TOPOLOGY
            .packages()
            // Exclude self
            .filter(move |p| p != &self)
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
        self.node_id
            .and_then(|nid| MACHINE_TOPOLOGY.nodes().find(move |node| node.id == nid))
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
        let (max_proximity_info, prox_domain_info) = process_msct();

        local_apics.sort_by(|a, b| a.apic_id.cmp(&b.apic_id));
        local_x2apics.sort_by(|a, b| a.apic_id.cmp(&b.apic_id));

        // These to are sorted in decending order since we pop from the stack:
        core_affinity.sort_by(|a, b| b.apic_id.cmp(&a.apic_id));
        x2apic_affinity.sort_by(|a, b| b.x2apic_id.cmp(&a.x2apic_id));

        assert!(local_apics.len() == core_affinity.len() || core_affinity.is_empty(),
            "Either we have matching entries for core in affinity table or no affinity information at all.");

        // Make Thread objects out of APIC MADT entries:
        let mut global_thread_id: GlobalThreadId = 0;
        let mut threads = Vec::with_capacity(local_apics.len() + local_x2apics.len());

        // Add all local APIC entries
        for local_apic in local_apics {

            // Try to figure out which proximity domain (NUMA node) a thread belongs to:
            let mut proximity_domain = None;
            if !core_affinity.is_empty() {
                let affinity_entry = core_affinity.pop();
                if affinity_entry.as_ref().unwrap().apic_id == local_apic.apic_id {
                    proximity_domain = affinity_entry.as_ref().map(|a| a.proximity_domain as u64);
                }
                else {
                    core_affinity.push(affinity_entry.unwrap());
                }
            }

            // Cores with IDs < 255 appear as local apic entries, cores above
            // 255 appear as x2apic entries. However, for SRAT entries (to
            // figure out NUMA affinity), some machines will put all entries as
            // X2APIC affinities :S. So we have to check the x2apic_affinity too
            if proximity_domain.is_none() && !x2apic_affinity.is_empty() {
                let affinity_entry = x2apic_affinity.pop();
                let x2apic_id: u8 = affinity_entry.as_ref().unwrap().x2apic_id.try_into().unwrap();
                if x2apic_id == local_apic.apic_id {
                    proximity_domain = affinity_entry.as_ref().map(|a| a.proximity_domain as u64);
                }
                else {
                    x2apic_affinity.push(affinity_entry.unwrap());
                }
            }

            let t = Thread::new_with_apic(global_thread_id, local_apic, proximity_domain);
            debug!("Found {:?}", t);
            threads.push(t);
            global_thread_id += 1;
        }

        // Add all x2APIC entries
        for local_x2apic in local_x2apics {
            let affinity = x2apic_affinity.pop();
            if let Some(affinity_entry) = affinity.as_ref() {
                assert_eq!(affinity_entry.x2apic_id, local_x2apic.apic_id, "The x2apic_affinity and local_x2apic are not in the same order?");
            }
            let t = Thread::new_with_x2apic(global_thread_id, local_x2apic, affinity.map(|a| a.proximity_domain as u64));
            debug!("Found {:?}", t);
            threads.push(t);
            global_thread_id += 1;
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
            prox_domain_info
        )
    };
}

/// Contains a condensed and filtered version of all data queried from ACPI and CPUID.
#[derive(Debug)]
pub struct MachineInfo {
    /// All hardware threads in the system, indexed by GlobalThreadId.
    pub threads: Vec<Thread>,
    cores: Vec<Core>,
    packages: Vec<Package>,
    nodes: Vec<Node>,
    memory_affinity: Vec<MemoryAffinity>,
    io_apics: Vec<IoApic>,
    max_proximity_info: MaximumSystemCharacteristics,
    proximity_domains: Vec<MaximumProximityDomainInfo>,
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
        max_proximity_info: MaximumSystemCharacteristics,
        proximity_domains: Vec<MaximumProximityDomainInfo>,
    ) -> MachineInfo {
        MachineInfo {
            threads,
            cores,
            packages,
            nodes,
            memory_affinity,
            io_apics,
            max_proximity_info,
            proximity_domains,
        }
    }

    fn determine_apic_id_with_cpuid() -> x86::apic::ApicId {
        let cpuid = x86::cpuid::CpuId::new();
        let xapic_id: Option<u8> = cpuid
            .get_feature_info()
            .as_ref()
            .map(|finfo| finfo.initial_local_apic_id());

        let x2apic_id: Option<u32> = cpuid
            .get_extended_topology_info()
            .and_then(|mut topiter| topiter.next().as_ref().map(|t| t.x2apic_id()));

        match (x2apic_id, xapic_id) {
            (None, None) => {
                unreachable!("Can't determine APIC ID, bad. (Maybe try fallback on APIC_BASE_MSR")
            }
            (Some(x2id), None) => ApicId::X2Apic(x2id),
            (None, Some(xid)) => ApicId::XApic(xid),
            (Some(x2id), Some(xid)) => {
                // 10.12.8.1 Consistency of APIC IDs and CPUID: "Initial APIC ID (CPUID.01H:EBX[31:24]) is always equal to CPUID.0BH:EDX[7:0]."
                debug_assert!(
                    (x2id & 0xff) == xid.into(),
                    "xAPIC ID is first byte of X2APIC ID"
                );
                if (xid as u32) == x2id {
                    ApicId::XApic(xid)
                } else {
                    ApicId::X2Apic(x2id)
                }
            }
        }
    }

    /// Returns the current thread we're running on.
    ///
    /// # Notes
    /// Uses cpuid to determine the current APIC ID,
    /// then uses the id to find the corresponding thread.
    ///
    /// This is not an incredibly fast function since cpuid will clobber
    /// your registers unnecessarily. Ideally, call this once then cache.
    ///
    /// You also need to ensure that execution is not migrated to
    /// another core during execution of `current_thread`.
    pub fn current_thread(&'static self) -> &'static Thread {
        let apic_id = MachineInfo::determine_apic_id_with_cpuid();

        self.threads()
            .find(move |t| t.apic_id() == apic_id)
            .unwrap()
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
