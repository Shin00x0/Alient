//! N02: declarative engine capability contract, independent of the protocol renderer.
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Support {
    Supported,
    Partial,
    Unavailable,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Feature {
    pub id: &'static str,
    pub support: Support,
    pub detail: &'static str,
}
pub const ARCHITECTURES: &[Feature] = &[
    Feature {
        id: "AARCH64:LE:64",
        support: Support::Supported,
        detail: "ARM64 little-endian 64-bit",
    },
    Feature {
        id: "x86:LE:64",
        support: Support::Supported,
        detail: "x86-64 little-endian",
    },
];
pub const FORMATS: &[Feature] = &[
    Feature {
        id: "ELF64 LE",
        support: Support::Supported,
        detail: "Executables and shared libraries",
    },
    Feature {
        id: "Mach-O64 LE",
        support: Support::Supported,
        detail: "Thin 64-bit Mach-O images",
    },
    Feature {
        id: "PE32+",
        support: Support::Supported,
        detail: "64-bit PE images",
    },
    Feature {
        id: "relocatable-object",
        support: Support::Unavailable,
        detail: "Relocation application is not implemented",
    },
];
pub const MODULES: &[Feature] = &[
    Feature {
        id: "N01",
        support: Support::Supported,
        detail: "Program model and revisions",
    },
    Feature {
        id: "N02",
        support: Support::Supported,
        detail: "Capability contract",
    },
    Feature {
        id: "N03",
        support: Support::Supported,
        detail: "Format loading, symbols and relocations",
    },
    Feature {
        id: "N04",
        support: Support::Partial,
        detail: "x86-64 and ARM64 lifting",
    },
    Feature {
        id: "N05",
        support: Support::Partial,
        detail: "Function discovery",
    },
    Feature {
        id: "N06",
        support: Support::Partial,
        detail: "Scalar IR and typed intrinsics",
    },
    Feature {
        id: "N07",
        support: Support::Partial,
        detail: "Dataflow and SSA",
    },
    Feature {
        id: "N08",
        support: Support::Partial,
        detail: "ABI recovery",
    },
    Feature {
        id: "N09",
        support: Support::Partial,
        detail: "Type constraints",
    },
    Feature {
        id: "N10",
        support: Support::Partial,
        detail: "Indirect control flow",
    },
    Feature {
        id: "N11",
        support: Support::Partial,
        detail: "Low-level C rendering",
    },
    Feature {
        id: "N12",
        support: Support::Partial,
        detail: "Persistent storage",
    },
    Feature {
        id: "N13",
        support: Support::Partial,
        detail: "Edits and undo",
    },
    Feature {
        id: "N14",
        support: Support::Partial,
        detail: "Scheduler",
    },
];
pub const EDITS: &[&str] = &[
    "rename",
    "comment",
    "function-comment",
    "signature",
    "variable",
    "bookmark",
    "define-type",
    "define-data",
    "clear-data",
    "create-function",
    "delete-function",
    "jump-table",
    "undo",
    "redo",
];
pub const LIMITATIONS: &[&str] = &[
    "SIMD/FP coverage is explicit but incomplete",
    "External libraries and relocations are not executed or applied",
    "Indirect targets require static evidence",
    "High-level reconstruction is conservative and incomplete",
];
