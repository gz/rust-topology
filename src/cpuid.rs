//! CPUID related functionality for relevant topology information.
use alloc::vec::Vec;

use crate::{CoreId, PackageId, ThreadId};

/// Silly helper trait for computing power of two
trait PowersOf2 {
    fn log2(self) -> u8;
}

impl PowersOf2 for u8 {
    fn log2(self) -> u8 {
        7 - self.leading_zeros() as u8
    }
}

/// Given APIC ID, figure out package, core and thread ID.
pub fn get_topology_from_apic_id(xapic_id: u8) -> (ThreadId, CoreId, PackageId) {
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
pub fn get_topology_from_x2apic_id(x2apic_id: u32) -> (ThreadId, CoreId, PackageId) {
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
