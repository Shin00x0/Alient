use ghidra_web_engine::{
    architectures::{register, Decoder},
    core::Addr,
    ir::*,
};
use std::collections::BTreeMap;
#[test]
fn scalar_arithmetic_matches_u128_reference() {
    let mut seed = 123456789u64;
    for bits in [1, 8, 16, 32, 64] {
        for _ in 0..1000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = seed & mask(bits);
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = seed & mask(bits);
            for (op, reference) in [
                ("+", a as u128 + b as u128),
                ("*", a as u128 * b as u128),
                ("-", (a as u128).wrapping_sub(b as u128)),
            ] {
                assert_eq!(
                    binary(op, constant(a, bits), constant(b, bits), bits).eval(&BTreeMap::new()),
                    Some(reference as u64 & mask(bits))
                );
            }
        }
    }
}
#[test]
fn large_shift_counts_never_wrap_to_u32() {
    for op in ["<<", ">>", "asr"] {
        for count in [64, 1u64 << 32, u64::MAX] {
            assert_eq!(
                binary(op, constant(0x8000, 16), constant(count, 64), 16).eval(&BTreeMap::new()),
                None
            );
        }
    }
}
#[test]
fn invalid_widths_and_operators_are_rejected() {
    for bits in [0, 65, u16::MAX] {
        let e = binary("asr", constant(1, 64), constant(1, 64), bits);
        assert!(e.validate().is_err());
        assert_eq!(e.eval(&BTreeMap::new()), None);
    }
    assert!(binary("invented", constant(1, 8), constant(2, 8), 8)
        .validate()
        .is_err());
}
#[test]
fn memory_contract_requires_byte_width_and_64_bit_address() {
    for (address, bits) in [
        (constant(1, 32), 8),
        (constant(1, 64), 7),
        (constant(1, 64), 128),
    ] {
        assert!(Statement::Store {
            address,
            value: constant(1, 64),
            bits
        }
        .validate()
        .is_err());
    }
    assert!(Statement::Store {
        address: constant(1, 64),
        value: constant(1, 64),
        bits: 8
    }
    .validate()
    .is_ok());
}
#[test]
fn effects_distinguish_load_store_call_unknown_and_stop() {
    let load = Statement::Assign {
        dst: "rax".into(),
        value: Expr::Load {
            address: Box::new(var("rsp", 64)),
            bits: 64,
        },
    }
    .effects();
    assert!(load.reads_memory && load.may_trap && !load.writes_memory);
    assert!(load.reads.contains("rsp") && load.writes.contains("rax"));
    let store = Statement::Store {
        address: var("rsp", 64),
        value: var("rax", 64),
        bits: 64,
    }
    .effects();
    assert!(store.writes_memory && !store.reads_memory);
    for s in [
        Statement::Call {
            target: constant(42, 64),
        },
        Statement::Unknown {
            description: "opaque".into(),
        },
    ] {
        let e = s.effects();
        assert!(e.reads_memory && e.writes_memory && e.unknown_registers);
    }
    let stop = Statement::Stop {
        instruction: "hlt".into(),
    }
    .effects();
    assert_eq!(stop.control, "stop");
    assert!(stop.may_trap);
    assert_eq!(Statement::Return.effects().control, "return");
}
#[test]
fn nested_unknown_expression_is_a_conservative_barrier() {
    let e = Statement::Assign {
        dst: "rax".into(),
        value: binary("+", Expr::Unknown("opaque".into()), constant(1, 64), 64),
    }
    .effects();
    assert!(e.unknown_registers && e.reads_memory && e.writes_memory);
}
#[test]
fn subregister_writes_match_bit_slice_reference() {
    for name in ["al", "ah", "ax", "eax", "rax"] {
        let o = register(name);
        let Operand::Reg { bits, offset, .. } = o else {
            panic!()
        };
        for value in [0, 1, 255, 65535, u64::MAX] {
            let old = 0xdeadbeef01234567;
            let Statement::Assign { value: e, .. } = assign(&o, constant(value, 64)) else {
                panic!()
            };
            let expected = if bits >= 32 {
                value & mask(bits)
            } else {
                (old & !(mask(bits) << offset)) | ((value & mask(bits)) << offset)
            };
            assert_eq!(
                e.eval(&BTreeMap::from([("rax".into(), old)])),
                Some(expected)
            );
        }
    }
}
#[test]
fn simplification_preserves_values_and_unknown_memory() {
    for bits in [8, 16, 32, 64] {
        for op in ["+", "-", "*", "&", "|", "^", "<<", ">>", "asr"] {
            for rhs in [0, 1, 7, 63] {
                let e = binary(op, var("x", bits), constant(rhs, 64), bits);
                let simple = e.simplify(&BTreeMap::new());
                for v in [0, 1, 127, 128, 65535, u64::MAX] {
                    let env = BTreeMap::from([("x".into(), v)]);
                    assert_eq!(simple.eval(&env), e.eval(&env));
                }
            }
        }
    }
    let load = Expr::Load {
        address: Box::new(constant(1, 64)),
        bits: 8,
    };
    assert_eq!(load.simplify(&BTreeMap::new()), load);
}
#[test]
fn lifted_ir_roundtrips_with_effects_and_source_location() {
    let d = Decoder::new("x86:LE:64").unwrap();
    let i = d.decode(&[0x48, 0x8b, 0x07], Addr(0x1000)).unwrap();
    for s in &i.statements {
        s.validate().unwrap();
        let encoded = serde_json::to_string(s).unwrap();
        assert_eq!(*s, serde_json::from_str::<Statement>(&encoded).unwrap());
    }
    assert_eq!(i.address, Addr(0x1000));
    assert!(i.statements.iter().any(|s| s.effects().reads_memory));
}
#[test]
fn expression_depth_is_bounded() {
    let mut e = constant(0, 64);
    for _ in 0..130 {
        e = binary("+", e, constant(1, 64), 64);
    }
    assert!(e.validate().is_err());
}
#[test]
fn signed_and_unsigned_comparisons_match_reference() {
    for a in 0..=255u64 {
        for b in [0, 1, 127, 128, 255] {
            for (op, expected) in [("<s", (a as i8) < (b as i8)), ("<u", a < b), ("==", a == b)] {
                let e = Expr::Compare {
                    op: op.into(),
                    left: Box::new(constant(a, 8)),
                    right: Box::new(constant(b, 8)),
                    bits: 8,
                };
                assert_eq!(e.eval(&BTreeMap::new()), Some(expected as u64));
                assert_eq!(e.simplify(&BTreeMap::new()).bits(), 1);
            }
        }
    }
}
#[test]
fn program_validation_rejects_corrupted_ir_with_location() {
    use ghidra_web_engine::{
        protocol,
        scheduler::{Budget, Job},
    };
    let source = include_bytes!("../../fixtures/sample-macho");
    let mut p = protocol::analyze(source, None, None, &mut Job::new(Budget::default()))
        .unwrap()
        .program;
    let i = p.instructions.values_mut().next().unwrap();
    i.statements = vec![Statement::Assign {
        dst: "x0".into(),
        value: binary("invalid", constant(0, 64), constant(1, 64), 64),
    }];
    let error = p.validate().unwrap_err();
    assert!(error.contains("IR en") && error.contains("operación 0"));
}
#[test]
fn invalid_register_slices_become_unknown_without_panicking() {
    for (bits, offset) in [(0, 0), (65, 0), (8, 64), (64, 1), (u16::MAX, u16::MAX)] {
        let s = assign(
            &Operand::Reg {
                name: "rax".into(),
                bits,
                offset,
            },
            constant(0, 64),
        );
        assert!(matches!(s, Statement::Unknown { .. }));
    }
}

#[test]
fn conditions_read_concrete_flags_and_evaluate_x86_and_arm64_codes() {
    let flags = BTreeMap::from([
        ("__flag_zf".into(), 0),
        ("__flag_cf".into(), 0),
        ("__flag_sf".into(), 1),
        ("__flag_of".into(), 1),
        ("__flag_pf".into(), 0),
    ]);
    for (code, expected) in [
        ("ne", true),
        ("a", true),
        ("g", true),
        ("ge", true),
        ("lt", false),
        ("hi", true),
        ("al", true),
        ("nv", false),
    ] {
        let condition = Expr::Condition(code.into());
        assert!(condition.validate().is_ok(), "{code}");
        assert_eq!(condition.bits(), 1);
        assert_eq!(condition.eval(&flags), Some(expected as u64), "{code}");
    }
    let reads = Expr::Condition("hi".into()).reads();
    assert!(
        reads.contains("__flags") && reads.contains("__flag_cf") && reads.contains("__flag_zf")
    );
    assert!(Expr::Condition("invented".into()).validate().is_err());

    let writes = Statement::Flags {
        op: "-".into(),
        left: var("rax", 64),
        right: var("rbx", 64),
        bits: 64,
    }
    .writes();
    assert!(writes.contains(&"__flag_zf".into()) && writes.contains(&"__flag_of".into()));
}

#[test]
fn arithmetic_flags_produce_concrete_branch_inputs() {
    let plus = evaluate_flags("+", 0xff, 1, 8).unwrap();
    assert_eq!(plus["__flag_cf"], 1);
    assert_eq!(plus["__flag_zf"], 1);
    assert_eq!(plus["__flag_pf"], 1);
    assert_eq!(plus["__flag_of"], 0);
    assert_eq!(evaluate_condition("e", &plus), Some(true));
    let sub = evaluate_flags("-", 0x80, 1, 8).unwrap();
    assert_eq!(sub["__flag_sf"], 0);
    assert_eq!(sub["__flag_of"], 1);
    assert_eq!(evaluate_condition("l", &sub), Some(true));
}
