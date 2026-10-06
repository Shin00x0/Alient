//! N02: stable, machine-readable native scope. The catalogue has no protocol dependency.
use crate::capability_catalog::{ARCHITECTURES, EDITS, FORMATS, LIMITATIONS, MODULES};
use serde_json::json;

fn supported_ids(features: &[crate::capability_catalog::Feature]) -> Vec<&'static str> {
    features
        .iter()
        .filter(|feature| {
            !matches!(
                feature.support,
                crate::capability_catalog::Support::Unavailable
            )
        })
        .map(|feature| feature.id)
        .collect()
}
pub fn describe() -> serde_json::Value {
    json!({
        "protocol": 2,
        "engine": "rust",
        "build": env!("NATIVE_BUILD_ID"),
        "version": env!("CARGO_PKG_VERSION"),
        "architectures": supported_ids(ARCHITECTURES),
        "formats": supported_ids(FORMATS),
        "modules": MODULES.iter().map(|module| module.id).collect::<Vec<_>>(),
        "catalog": {"architectures": ARCHITECTURES, "formats": FORMATS, "modules": MODULES},
        "decompilation": "partial-low-level-c",
        "instructions": "Capstone decoding; scalar IR plus typed opaque FP/SIMD intrinsics",
        "edits": EDITS,
        "limits": {"inputBytes":crate::MAX_INPUT,"instructions":200000,"functions":20000,"milliseconds":120000},
        "limitations": LIMITATIONS,
    })
}
