use ghidra_web_engine::{
    analysis::{abi, indirect},
    architectures::Decoder,
    commands::Command,
    core::*,
    ir::*,
    loaders, protocol,
    scheduler::{Budget, Job},
    storage::Store,
    types::{Field, Type, TypeRegistry},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
fn job() -> Job {
    Job::new(Budget::default())
}
fn elf(code: &[u8], arm: bool) -> Vec<u8> {
    let mut b = vec![0; 0x100 + code.len()];
    b[..7].copy_from_slice(&[127, 69, 76, 70, 2, 1, 1]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&(if arm { 183u16 } else { 62 }).to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    for (o, n) in [
        (24, 0x400100u64),
        (32, 64),
        (72, 0x100),
        (80, 0x400100),
        (96, code.len() as u64),
        (104, code.len() as u64),
    ] {
        b[o..o + 8].copy_from_slice(&n.to_le_bytes());
    }
    for (o, n) in [(52, 64u16), (54, 56), (56, 1)] {
        b[o..o + 2].copy_from_slice(&n.to_le_bytes());
    }
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[0x100..].copy_from_slice(code);
    b
}
fn arm(words: &[u32]) -> Vec<u8> {
    elf(
        &words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>(),
        true,
    )
}
fn sample() -> Vec<u8> {
    include_bytes!("../../fixtures/sample-macho").to_vec()
}
fn analyze(b: &[u8]) -> ghidra_web_engine::storage::Stored {
    protocol::analyze(b, None, None, &mut job()).unwrap()
}
fn edit(
    b: &[u8],
    old: &ghidra_web_engine::storage::Stored,
    c: Command,
) -> ghidra_web_engine::storage::Stored {
    protocol::analyze(b, Some(old), Some(&c), &mut job()).unwrap()
}
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "native-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn n01_roundtrip_addresses_and_memory_invariants() {
    let p = analyze(&sample()).program;
    let mut copy: Program = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(p, copy);
    copy.regions.push(copy.regions[0].clone());
    assert!(copy.validate().is_err());
    let a = Addr(u64::MAX);
    assert_eq!(
        serde_json::from_str::<Addr>(&serde_json::to_string(&a).unwrap()).unwrap(),
        a
    );
    assert!(p.read(&sample(), Addr(0), 4).is_err());

    let mut overlay_program = p.clone();
    let mut overlay = overlay_program.regions[0].clone();
    overlay.space = "overlay:analysis".into();
    overlay.id = stable_space_id(
        &overlay_program.id,
        "memory",
        &overlay.space,
        overlay.range.start,
    );
    overlay.priority = 1;
    overlay.id = stable_region_id(&overlay_program.id, &overlay.space, overlay.range.start, overlay.priority);
    overlay_program.regions.push(overlay.clone());
    assert!(overlay_program.validate().is_ok());
    let reference = AddressRef {
        space: overlay.space.clone(),
        address: overlay.range.start,
    };
    assert_eq!(
        overlay_program
            .read_in(&sample(), reference.clone(), 4)
            .unwrap(),
        p.read(&sample(), overlay.range.start, 4).unwrap()
    );
    assert!(overlay_program.region_in(&reference).is_some());
    assert!(overlay_program.region(overlay.range.start).is_some());

    let mut shadow = overlay.clone();
    shadow.space = "ram".into();
    shadow.name = "priority-overlay".into();
    shadow.file_offset = 0;
    shadow.priority = 3;
    shadow.id = stable_region_id(&overlay_program.id, &shadow.space, shadow.range.start, shadow.priority);
    overlay_program.regions.push(shadow);
    assert!(overlay_program.validate().is_ok());
    assert_eq!(overlay_program.region(overlay.range.start).unwrap().name, "priority-overlay");

    // A decoded item can now retain a non-ram location without colliding with ram ordering.
    let address = Addr(overlay.range.start.0 + overlay.range.size - 1);
    let mut external_instruction = p.instructions.values().next().unwrap().clone();
    external_instruction.address = address;
    external_instruction.space = overlay.space.clone();
    external_instruction.bytes = vec![0x90];
    external_instruction.id = stable_space_id(&overlay_program.id, "instructions", &external_instruction.space, address);
    overlay_program.instructions.insert(address, external_instruction);
    assert!(overlay_program.validate().is_ok());

    let mut duplicate = overlay_program.clone();
    duplicate.regions.push(duplicate.regions[0].clone());
    assert!(duplicate.validate().is_err());
}
#[test]
fn n02_scope_has_all_modules_and_partial_decompilation() {
    let c = ghidra_web_engine::capabilities::describe();
    assert_eq!(c["modules"].as_array().unwrap().len(), 14);
    assert_eq!(c["decompilation"], "partial-low-level-c");
}
#[test]
fn n03_truncated_and_invalid_binaries_are_rejected() {
    let bytes = sample();
    for n in 0..128 {
        assert!(loaders::load(&bytes[..n]).is_err(), "prefix {n}");
    }
    assert!(loaders::load(b"not a binary").is_err());
    let mut b = arm(&[0xd65f03c0]);
    b[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(loaders::load(&b).is_err());
}
#[test]
fn n03_elf_and_macho() {
    let p = analyze(&arm(&[0xd28000e0, 0x91000c00, 0xd65f03c0])).program;
    assert_eq!(p.instructions.len(), 3);
    assert_eq!(p.format, "ELF 64-bit");
    let p = analyze(&sample()).program;
    assert_eq!(p.instructions.len(), 31);
    assert_eq!(p.functions.len(), 3);
    assert!(!p.imports.is_empty());
    assert!(p
        .data
        .values()
        .any(|d| d.value.contains("Ghidra Web static analysis fixture")));
}
#[test]
fn n03_pe_x86() {
    let mut b = vec![0u8; 1024];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (o, n) in [
        (0x84, 0x8664u16),
        (0x86, 1),
        (0x94, 240),
        (0x96, 0x22),
        (0x98, 0x20b),
        (0xdc, 3),
    ] {
        b[o..o + 2].copy_from_slice(&n.to_le_bytes());
    }
    for (o, n) in [
        (0xa8, 0x1000u32),
        (0xac, 0x1000),
        (0xb8, 0x1000),
        (0xbc, 0x200),
        (0xd0, 0x2000),
        (0xd4, 0x200),
        (0x104, 16),
        (0x190, 6),
        (0x194, 0x1000),
        (0x198, 512),
        (0x19c, 512),
        (0x1ac, 0x60000020),
    ] {
        b[o..o + 4].copy_from_slice(&n.to_le_bytes());
    }
    b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
    b[0x188..0x18d].copy_from_slice(b".text");
    b[512..518].copy_from_slice(&[0xb8, 7, 0, 0, 0, 0xc3]);
    let p = analyze(&b).program;
    assert_eq!(p.format, "PE32+");
    assert_eq!(p.entry, Some(Addr(0x140001000)));
    assert_eq!(p.instructions.len(), 2);
    assert_eq!(abi::select(&p).name, "Win64");
}
#[test]
fn n04_decoders_preserve_unknown_and_real_instruction_lengths() {
    let x = Decoder::new("x86:LE:64").unwrap();
    let mov = x.decode(&[0xb8, 7, 0, 0, 0], Addr(0x400100)).unwrap();
    assert_eq!(mov.bytes.len(), 5);
    let arm = Decoder::new("AARCH64:LE:64").unwrap();
    assert_eq!(
        arm.decode(&0x17ffffffu32.to_le_bytes(), Addr(0x1000000000000000))
            .unwrap()
            .flow,
        Flow::Jump(Addr(0xffffffffffffffc))
    );
    let simd = x.decode(&[0x0f, 0x58, 0xc1], Addr(0x1000)).unwrap();
    assert!(simd.semantic_complete);
    assert!(
        matches!(simd.statements[0], Statement::Intrinsic { ref operation, ref domain, .. } if operation == "addps" && domain == "simd")
    );
}
#[test]
fn n05_recursive_discovery_does_not_decode_padding() {
    let p = analyze(&elf(&[0xc3, 0x90, 0x90, 0xcc, 0xc3], false)).program;
    assert_eq!(p.instructions.len(), 1);
    assert_eq!(p.functions.len(), 1);
}
#[test]
fn n06_widths_subregisters_and_signed_arithmetic() {
    let e = binary("+", constant(0xffffffff, 32), constant(1, 32), 32);
    assert_eq!(e.eval(&BTreeMap::new()), Some(0));
    assert_eq!(
        binary("asr", constant(0x80000000, 32), constant(1, 32), 32).eval(&BTreeMap::new()),
        Some(0xc0000000)
    );
    let d = Decoder::new("x86:LE:64").unwrap();
    let i = d.decode(&[0xb8, 7, 0, 0, 0], Addr(0)).unwrap();
    let mut regs = BTreeMap::from([("rax".into(), u64::MAX)]);
    for s in i.statements {
        if let Statement::Assign { dst, value } = s {
            let v = value.eval(&regs).unwrap();
            regs.insert(dst, v);
        }
    }
    assert_eq!(regs["rax"], 7);
}
#[test]
fn n07_ssa_diamond_has_one_version_per_use_and_edge() {
    let bytes = elf(
        &[
            0x85, 0xff, 0x74, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 5, 0xb8, 2, 0, 0, 0, 0x83, 0xc0, 3,
            0xc3,
        ],
        false,
    );
    let p = analyze(&bytes).program;
    let f = p.functions.values().next().unwrap();
    let phi = f
        .dataflow
        .phis
        .iter()
        .find(|p| p.register == "rax")
        .unwrap();
    assert_eq!(phi.incoming.len(), 2);
    assert!(phi.incoming.values().all(|v| v.len() == 1));
    assert!(f.dataflow.uses.iter().all(|u| u.definitions.len() == 1));
    assert!(f.dataflow.dominators.values().all(|d| d.contains(&f.entry)));
}
#[test]
fn n08_abi_parameters_and_stack_are_recovered() {
    let p = analyze(&sample()).program;
    let f = p
        .functions
        .values()
        .find(|f| f.name == "_calculate_score")
        .unwrap();
    assert!(f.variables.iter().any(|v| v.parameter && v.storage == "x0"));
    assert!(f
        .variables
        .iter()
        .any(|v| !v.parameter && v.storage.starts_with("entry_sp")));
    assert_eq!(abi::select(&p).name, "AAPCS64");
    let p = analyze(&elf(&[0x89, 0xf8, 0xc3], false)).program;
    assert_eq!(abi::select(&p).name, "SysV AMD64");
    assert!(p
        .functions
        .values()
        .next()
        .unwrap()
        .variables
        .iter()
        .any(|v| v.storage == "rdi"));
}
#[test]
fn n09_layout_constraints_reject_recursion_and_overlap() {
    let mut t = TypeRegistry::default();
    assert!(t
        .insert(
            "bad".into(),
            Type::Struct {
                size: 8,
                fields: vec![Field {
                    name: "x".into(),
                    ty: "bad".into(),
                    offset: 0
                }]
            }
        )
        .is_err());
    assert!(!t.0.contains_key("bad"));
    t.insert(
        "pair".into(),
        Type::Struct {
            size: 8,
            fields: vec![
                Field {
                    name: "x".into(),
                    ty: "uint32_t".into(),
                    offset: 0,
                },
                Field {
                    name: "y".into(),
                    ty: "uint32_t".into(),
                    offset: 4,
                },
            ],
        },
    )
    .unwrap();
    assert_eq!(t.size("pair").unwrap(), 8);
    assert!(t
        .insert(
            "bad".into(),
            Type::Array {
                element: "uint64_t".into(),
                count: u64::MAX
            }
        )
        .is_err());
}
#[test]
fn n10_call_summaries_propagate_between_functions() {
    let p = analyze(&elf(
        &[0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 7, 0, 0, 0, 0xc3],
        false,
    ))
    .program;
    let report = indirect::resolve(
        &p,
        &elf(&[0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 7, 0, 0, 0, 0xc3], false),
        "rax",
        &mut job(),
    )
    .unwrap();
    assert_eq!(report.return_constants.get(&Addr(0x400100)), Some(&7));
}
#[test]
fn n10_indirect_call_discovers_callee() {
    let bytes = elf(
        &[
            0x48, 0xb8, 0x0d, 0x01, 0x40, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc3, 0xb8, 7, 0, 0, 0, 0xc3,
        ],
        false,
    );
    let p = analyze(&bytes).program;
    assert!(p.functions.contains_key(&Addr(0x40010d)));
    assert!(p
        .references
        .iter()
        .any(|r| r.from == Addr(0x40010a) && r.to == Addr(0x40010d)));
}
#[test]
fn n10_n11_bounded_table_updates_cfg_and_switch() {
    let mut code = vec![0xff, 0xe0, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3];
    code.extend(0x400102u64.to_le_bytes());
    code.extend(0x400108u64.to_le_bytes());
    let bytes = elf(&code, false);
    let first = analyze(&bytes);
    let next = edit(
        &bytes,
        &first,
        Command::JumpTable {
            address: Addr(0x400100),
            base: Addr(0x40010e),
            count: 2,
            index: "rax".into(),
        },
    );
    let f = next.program.functions.values().next().unwrap();
    assert_eq!(f.blocks[0].successors.len(), 2);
    assert!(f.code.iter().any(|l| l.text.contains("switch")));
    assert!(indirect::absolute_table(&next.program, &bytes, Addr(0x40010e), 257).is_err());
}
#[test]
fn n11_symbolic_c_eliminates_private_stack_for_sample() {
    let p = analyze(&sample()).program;
    let f = p
        .functions
        .values()
        .find(|f| f.name == "_calculate_score")
        .unwrap();
    assert_eq!(f.code.len(), 3);
    assert!(f.code[1].text.contains("return"));
    assert!(!f.code[1].text.contains("load_"));
    assert!(!f.code[1].text.contains("input_"));
}
#[test]
fn n12_store_lock_publish_and_search_reopen() {
    let temp = Temp::new();
    let stored = analyze(&sample());
    {
        let store = Store::open(&temp.0).unwrap();
        assert!(Store::open(&temp.0).is_err());
        let mut result = protocol::analysis(&stored.program, "sample");
        store
            .publish(&stored, &mut result, &protocol::listing(&stored.program))
            .unwrap();
    }
    let reopened = Store::open(&temp.0).unwrap().load().unwrap().unwrap();
    assert_eq!(reopened.program, stored.program);
    assert!(reopened.index.search("_calculate_score", None, 0, 100).0 > 0);
}
#[test]
fn n13_undo_redo_and_failed_edit_are_transactional() {
    let b = sample();
    let first = analyze(&b);
    let entry = first
        .program
        .functions
        .values()
        .find(|f| f.name == "_calculate_score")
        .unwrap()
        .entry;
    let edited = edit(
        &b,
        &first,
        Command::Rename {
            address: entry,
            value: "score".into(),
        },
    );
    assert_eq!(edited.program.functions[&entry].name, "score");
    assert!(edited.program.revision > first.program.revision);
    let undo = edit(&b, &edited, Command::Undo);
    assert_eq!(undo.program.functions[&entry].name, "_calculate_score");
    let redo = edit(&b, &undo, Command::Redo);
    assert_eq!(redo.program.functions[&entry].name, "score");
    assert!(protocol::analyze(
        &b,
        Some(&redo),
        Some(&Command::Rename {
            address: entry,
            value: "bad name".into()
        }),
        &mut job()
    )
    .is_err());
    assert_eq!(redo.program.functions[&entry].name, "score");
}
#[test]
fn n14_budget_cancellation_and_unchanged_reanalysis() {
    let mut j = Job::new(Budget {
        max_work: 0,
        ..Budget::default()
    });
    assert!(j.tick().is_err());
    let temp = Temp::new();
    fs::write(temp.0.join("cancel"), b"1").unwrap();
    let mut j = job();
    j.cancel_file = Some(temp.0.join("cancel"));
    assert!(j.tick().is_err());
    let b = sample();
    let first = analyze(&b);
    let next = protocol::analyze(&b, Some(&first), None, &mut job()).unwrap();
    assert_eq!(first.program, next.program);
}

#[test]
fn n07_loop_entry_phi_includes_the_external_input() {
    let p = analyze(&elf(&[0x83, 0xef, 1, 0x75, 0xfb, 0x89, 0xf8, 0xc3], false)).program;
    let f = p.functions.values().next().unwrap();
    let phi = f
        .dataflow
        .phis
        .iter()
        .find(|phi| phi.block == f.entry && phi.register == "rdi")
        .unwrap();
    assert_eq!(phi.entry_input.as_deref(), Some("input:rdi"));
    assert!(f
        .variables
        .iter()
        .any(|v| v.parameter && v.storage == "rdi"));
}
#[test]
fn n13_type_and_data_edits_survive_undo() {
    let bytes = elf(&[0xc3, 0x90, 0x90, 0x90, 0x90], false);
    let first = analyze(&bytes);
    let typed = edit(
        &bytes,
        &first,
        Command::DefineType {
            name: "Word".into(),
            ty: Type::Int {
                bits: 32,
                signed: false,
            },
        },
    );
    let data = edit(
        &bytes,
        &typed,
        Command::DefineData {
            address: Addr(0x400101),
            ty: "Word".into(),
        },
    );
    assert_eq!(data.program.data[&Addr(0x400101)].range.size, 4);
    let undo = edit(&bytes, &data, Command::Undo);
    assert!(!undo.program.data.contains_key(&Addr(0x400101)));
    assert!(undo.program.types.0.contains_key("Word"));
}
#[test]
fn n14_unrelated_function_cache_and_ids_stay_stable() {
    let bytes = sample();
    let first = analyze(&bytes);
    let entry = first
        .program
        .functions
        .values()
        .find(|f| f.name == "_calculate_score")
        .unwrap()
        .entry;
    let next = edit(
        &bytes,
        &first,
        Command::Comment {
            address: entry,
            value: "arithmetic".into(),
        },
    );
    for (a, f) in &first.program.functions {
        if *a != entry {
            assert_eq!(&next.program.functions[a], f);
        }
    }
    assert_eq!(
        first.program.functions[&entry].id,
        next.program.functions[&entry].id
    );
    assert!(next.program.functions[&entry].revision > first.program.functions[&entry].revision);
}
#[test]
fn n12_invalid_persisted_index_is_rejected() {
    let temp = Temp::new();
    let mut stored = analyze(&sample());
    stored
        .index
        .words
        .insert("corrupt".into(), [usize::MAX].into_iter().collect());
    let store = Store::open(&temp.0).unwrap();
    let mut result = protocol::analysis(&stored.program, "sample");
    store
        .publish(&stored, &mut result, &protocol::listing(&stored.program))
        .unwrap();
    assert!(store.load().unwrap_err().contains("Índice corrupto"));
}

#[test]
fn n08_stack_alias_survives_a_branch_boundary() {
    let bytes = elf(
        &[
            0x48, 0x83, 0xec, 8, 0xeb, 0, 0x89, 0x3c, 0x24, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 8,
            0xc3,
        ],
        false,
    );
    let p = analyze(&bytes).program;
    assert!(p
        .functions
        .values()
        .next()
        .unwrap()
        .variables
        .iter()
        .any(|v| v.storage == "entry_sp-8"));
}
#[test]
fn n11_call_result_uses_the_parameter_register_alias() {
    let p = analyze(&sample()).program;
    let f = p.functions.values().find(|f| f.name == "_main").unwrap();
    assert!(f
        .code
        .iter()
        .any(|l| l.text.starts_with("arg_0__reg = _calculate_score")));
    assert!(!f
        .code
        .iter()
        .any(|l| l.text.starts_with("x0 = _calculate_score")));
}
#[test]
fn n14_cli_cancel_does_not_publish_over_a_valid_result() {
    let temp = Temp::new();
    let b = sample();
    let stored = analyze(&b);
    {
        let store = Store::open(&temp.0).unwrap();
        let mut result = protocol::analysis(&stored.program, "sample");
        store
            .publish(&stored, &mut result, &protocol::listing(&stored.program))
            .unwrap();
    }
    fs::write(temp.0.join("input.bin"), b).unwrap();
    fs::write(temp.0.join("native.cancel"), b"cancel").unwrap();
    let before = fs::read(temp.0.join("result.json")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ghidra-web-engine"))
        .arg("analyze")
        .arg(&temp.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cancelado"));
    assert_eq!(fs::read(temp.0.join("result.json")).unwrap(), before);
}
