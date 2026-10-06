use ghidra_web_engine::{
    analysis::discovery,
    core::*,
    loaders, protocol,
    scheduler::{Budget, Job},
};
fn image(code: &[u8], arm: bool) -> Vec<u8> {
    let mut b = vec![0; 0x100 + code.len()];
    b[..7].copy_from_slice(&[127, 69, 76, 70, 2, 1, 1]);
    for (o, n) in [
        (16, 2u16),
        (18, if arm { 183 } else { 62 }),
        (52, 64),
        (54, 56),
        (56, 1),
    ] {
        b[o..o + 2].copy_from_slice(&n.to_le_bytes());
    }
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
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[0x100..].copy_from_slice(code);
    b
}
fn symbol(p: &mut Program, offset: u64, size: u64) {
    p.symbols.push(Symbol {
        name: format!("fn_{offset}"),
        address: Some(Addr(0x400100 + offset)),
        size,
        function: true,
        external: false,
        exported: false,
        source: "test".into(),
    });
}
fn run(b: &[u8], symbols: &[(u64, u64)]) -> Program {
    let mut p = loaders::load(b).unwrap();
    for (a, n) in symbols {
        symbol(&mut p, *a, *n);
    }
    discovery::discover(&mut p, b, &mut Job::new(Budget::default())).unwrap();
    p.reconcile(None, "test").unwrap();
    p
}
#[test]
fn late_call_target_is_removed_from_earlier_caller_body() {
    let mut code = vec![0x90; 14];
    code[1] = 0xc3;
    code[8..13].copy_from_slice(&[0xe8, 0xf4, 0xff, 0xff, 0xff]);
    code[13] = 0xc3;
    let p = run(&image(&code, false), &[(0, 0), (8, 0)]);
    assert_eq!(p.functions[&Addr(0x400100)].members, vec![Addr(0x400100)]);
    assert_eq!(p.functions[&Addr(0x400101)].members, vec![Addr(0x400101)]);
    assert_eq!(p.functions[&Addr(0x400101)].discovery.source, "call-target");
    assert_eq!(
        p.functions[&Addr(0x400100)].discovery.transfers[0].to,
        Addr(0x400101)
    );
}
#[test]
fn direct_thunk_keeps_its_own_body_and_target() {
    let mut code = vec![0x90; 9];
    code[..5].copy_from_slice(&[0xe9, 3, 0, 0, 0]);
    code[8] = 0xc3;
    let p = run(&image(&code, false), &[(0, 0), (8, 0)]);
    let f = &p.functions[&Addr(0x400100)];
    assert_eq!(f.members.len(), 1);
    assert_eq!(f.discovery.thunk_target, Some(Addr(0x400108)));
    assert_eq!(f.blocks[0].successors.len(), 0);
    assert_eq!(
        protocol::analysis(&p, "test")["functions"][0]["kind"],
        "thunk"
    );
}
#[test]
fn shared_non_entry_tail_is_owned_by_both_functions() {
    let mut code = vec![0x90; 22];
    code[..5].copy_from_slice(&[0xe9, 11, 0, 0, 0]);
    code[8..13].copy_from_slice(&[0xe9, 3, 0, 0, 0]);
    code[16..22].copy_from_slice(&[0xb8, 7, 0, 0, 0, 0xc3]);
    let p = run(&image(&code, false), &[(0, 0), (8, 0)]);
    for entry in [0x400100, 0x400108] {
        assert_eq!(
            p.functions[&Addr(entry)].discovery.shared_code,
            vec![Addr(0x400110), Addr(0x400115)]
        );
        assert_eq!(p.functions[&Addr(entry)].discovery.thunk_target, None);
    }
    assert_eq!(
        p.references
            .iter()
            .filter(|r| r.to == Addr(0x400110))
            .count(),
        2
    );
}
#[test]
fn declared_symbol_size_stops_decoding_trailing_data() {
    let p = run(&image(&[0xb8, 7, 0, 0, 0, 0xc3], false), &[(0, 5)]);
    assert_eq!(p.instructions.len(), 1);
    assert_eq!(
        p.functions[&Addr(0x400100)].discovery.declared_end,
        Some(Addr(0x400105))
    );
    assert_eq!(
        p.functions[&Addr(0x400100)].discovery.transfers[0].kind,
        "fallthrough"
    );
}
#[test]
fn instruction_crossing_symbol_end_is_rejected_with_diagnostic() {
    let p = run(&image(&[0xb8, 7, 0, 0, 0, 0xc3], false), &[(0, 2)]);
    assert!(p.instructions.is_empty());
    assert!(p.functions.is_empty());
    assert!(p.warnings.iter().any(|w| w.contains("cruza")));
}
fn padded_frame() -> Vec<u8> {
    let mut code = vec![0x90; 27];
    code[0] = 0xc3;
    code[16..].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0xb8, 7, 0, 0, 0, 0x5d, 0xc3]);
    code
}
#[test]
fn stripped_padded_frame_is_recovered_with_inferred_provenance() {
    let p = run(&image(&padded_frame(), false), &[]);
    let f = &p.functions[&Addr(0x400110)];
    assert_eq!(f.discovery.source, "frame-prologue-inferred");
    assert!(f.warnings.iter().any(|w| w.contains("inferida")));
    assert!(!p.instructions.contains_key(&Addr(0x400102)));
}
#[test]
fn prologue_without_closed_returning_body_is_not_promoted() {
    let mut code = padded_frame();
    code[26] = 0xf4;
    let p = run(&image(&code, false), &[]);
    assert_eq!(p.functions.len(), 1);
}
#[test]
fn prologue_inside_declared_function_is_not_a_new_root() {
    let code = padded_frame();
    let p = run(&image(&code, false), &[(0, code.len() as u64)]);
    assert_eq!(p.functions.len(), 1);
}
#[test]
fn explicit_data_prevents_prologue_recovery() {
    let bytes = image(&padded_frame(), false);
    let mut p = loaders::load(bytes.as_slice()).unwrap();
    p.data.insert(
        Addr(0x400110),
        Data {
            id: String::new(),
            revision: 0,
            space: "ram".into(),
            range: Range {
                start: Addr(0x400110),
                size: 8,
            },
            ty: "uint64_t".into(),
            value: String::new(),
            provenance: "user".into(),
        },
    );
    discovery::discover(&mut p, &bytes, &mut Job::new(Budget::default())).unwrap();
    assert_eq!(p.functions.len(), 1);
}
#[test]
fn arm64_unaligned_root_is_not_decoded() {
    let bytes = image(&[0xc0, 3, 0x5f, 0xd6, 0, 0, 0, 0], true);
    let mut p = loaders::load(&bytes).unwrap();
    p.entry = Some(Addr(0x400102));
    discovery::discover(&mut p, &bytes, &mut Job::new(Budget::default())).unwrap();
    assert!(p.instructions.is_empty());
}
#[test]
fn discovery_obeys_work_budget() {
    let bytes = image(&padded_frame(), false);
    let mut p = loaders::load(&bytes).unwrap();
    let mut job = Job::new(Budget {
        max_work: 1,
        ..Default::default()
    });
    assert!(discovery::discover(&mut p, &bytes, &mut job).is_err());
}
#[test]
fn arm64_padded_frame_is_recovered() {
    let words = [
        0xd65f03c0u32,
        0xd503201f,
        0xa9bf7bfd,
        0x910003fd,
        0xa8c17bfd,
        0xd65f03c0,
    ];
    let code = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let p = run(&image(&code, true), &[]);
    assert_eq!(
        p.functions[&Addr(0x400108)].discovery.source,
        "frame-prologue-inferred"
    );
}
#[test]
fn aligned_candidate_in_unaligned_region_is_recovered() {
    let mut code = vec![0x90; 26];
    code[0] = 0xc3;
    code[15..].copy_from_slice(&padded_frame()[16..]);
    let mut bytes = image(&code, false);
    for offset in [24, 80] {
        bytes[offset..offset + 8].copy_from_slice(&0x400101u64.to_le_bytes());
    }
    let p = run(&bytes, &[]);
    assert!(p.functions.contains_key(&Addr(0x400110)));
}
#[test]
fn external_jump_and_fallthrough_do_not_emit_dangling_local_labels() {
    use ghidra_web_engine::{analysis::abi, decompiler};
    for code in [vec![0xeb, 0, 0xc3], vec![0x90, 0x90, 0xc3]] {
        let mut p = run(&image(&code, false), &[(0, 2), (2, 0)]);
        let abi = abi::select(&p);
        let f = p.functions.get_mut(&Addr(0x400100)).unwrap();
        decompiler::emit(f, &p.instructions, &abi, &p.overrides, &Default::default());
        let c = f
            .code
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(c.contains("transfer_control(0x00400102)"), "{c}");
        assert!(!c.contains("goto loc_00400102"), "{c}");
        assert!(!f.complete);
    }
}

#[test]
fn noreturn_stop_and_direct_call_prune_the_false_fallthrough() {
    // call fn_abort; ret; fn_abort: hlt
    let bytes = image(&[0xe8, 1, 0, 0, 0, 0xc3, 0xf4], false);
    let mut p = loaders::load(&bytes).unwrap();
    symbol(&mut p, 0, 0);
    p.symbols.push(Symbol {
        name: "abort".into(),
        address: Some(Addr(0x400106)),
        size: 0,
        function: true,
        external: false,
        exported: false,
        source: "test".into(),
    });
    discovery::discover(&mut p, &bytes, &mut Job::new(Budget::default())).unwrap();
    p.reconcile(None, "test").unwrap();

    let abort = &p.functions[&Addr(0x400106)];
    assert!(abort.discovery.no_return);
    assert_eq!(abort.discovery.no_return_source, "symbol-name");
    let caller = &p.functions[&Addr(0x400100)];
    assert!(caller.discovery.no_return);
    assert_eq!(caller.members, vec![Addr(0x400100)]);
    assert!(caller.blocks[0].successors.is_empty());
}
