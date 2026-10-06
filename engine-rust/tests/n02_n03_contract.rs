use ghidra_web_engine::{
    capabilities,
    capability_catalog::{Support, ARCHITECTURES, FORMATS},
    loaders::catalog,
};
use object::{Object, ObjectKind};

#[test]
fn n02_catalog_has_stable_ids_and_keeps_unavailable_features_out_of_active_lists() {
    let description = capabilities::describe();
    assert_eq!(description["protocol"], 2);
    assert_eq!(
        description["catalog"]["architectures"],
        serde_json::to_value(ARCHITECTURES).unwrap()
    );
    for feature in FORMATS {
        if feature.support == Support::Unavailable {
            assert!(!description["formats"]
                .as_array()
                .unwrap()
                .iter()
                .any(|id| id == feature.id));
        }
    }
    assert!(description["modules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == "N03"));
}

#[test]
fn n03_format_catalog_separates_policy_from_the_object_reader() {
    let bytes = include_bytes!("../../fixtures/sample-macho");
    let file = object::File::parse(bytes.as_slice()).unwrap();
    assert!(matches!(
        file.kind(),
        ObjectKind::Executable | ObjectKind::Dynamic
    ));
    let spec = catalog::identify(&file).unwrap();
    assert_eq!(spec.format, "Mach-O 64-bit");
    assert_eq!(spec.architecture, "AARCH64:LE:64");
}
