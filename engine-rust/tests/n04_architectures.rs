//! N04 delivery: extensions, dynamic TLS bases, stop boundaries and unsupported prefixes.
use ghidra_web_engine::{
    architectures::Decoder,
    core::{Addr, Flow},
    ir::{binary, constant, memory_address, Expr, Operand, Statement},
};
use std::collections::BTreeMap;
fn decode(bytes: &[u8]) -> ghidra_web_engine::core::Instruction {
    Decoder::new("x86:LE:64")
        .unwrap()
        .decode(bytes, Addr(0x1000))
        .unwrap()
}
fn eval(expr: &Expr, regs: &BTreeMap<String, u64>, memory: &BTreeMap<u64, u8>) -> Option<u64> {
    if let Some(v) = expr.eval(regs) {
        return Some(v);
    }
    match expr {
        Expr::Load { address, bits } => {
            let a = eval(address, regs, memory)?;
            let mut v = 0;
            for i in 0..bits / 8 {
                v |= u64::from(*memory.get(&a.wrapping_add(u64::from(i)))?) << (i * 8);
            }
            Some(v)
        }
        Expr::Binary {
            op,
            left,
            right,
            bits,
        } => binary(
            op,
            constant(eval(left, regs, memory)?, left.bits()),
            constant(eval(right, regs, memory)?, right.bits()),
            *bits,
        )
        .eval(&BTreeMap::new()),
        _ => None,
    }
}
fn execute(
    bytes: &[u8],
    mut regs: BTreeMap<String, u64>,
    memory: BTreeMap<u64, u8>,
) -> BTreeMap<String, u64> {
    let i = decode(bytes);
    assert!(i.semantic_complete, "{}", i.text);
    for s in i.statements {
        if let Statement::Assign { dst, value } = s {
            let v = eval(&value, &regs, &memory).unwrap();
            regs.insert(dst, v);
        }
    }
    regs
}
#[test]
fn movzx_zero_extends_bytes_and_words_and_clears_upper_eax() {
    for (bytes, value, expected) in [
        (vec![0x0f, 0xb6, 0xc1], 0xff, 0xff),
        (vec![0x0f, 0xb7, 0xc1], 0xffff, 0xffff),
        (vec![0x48, 0x0f, 0xb6, 0xc1], 0x80, 0x80),
    ] {
        let regs = execute(
            &bytes,
            BTreeMap::from([("rax".into(), u64::MAX), ("rcx".into(), value)]),
            BTreeMap::new(),
        );
        assert_eq!(regs["rax"], expected);
    }
}
#[test]
fn movzx_reads_high_byte_before_overwriting_same_register() {
    let regs = execute(
        &[0x0f, 0xb6, 0xc4],
        BTreeMap::from([("rax".into(), 0x1234ab00)]),
        BTreeMap::new(),
    );
    assert_eq!(regs["rax"], 0xab);
}
#[test]
fn signed_extensions_preserve_sign_and_partial_destination_bits() {
    for (bytes, input, old, expected) in [
        (vec![0x48, 0x0f, 0xbe, 0xc1], 0x80, 0, u64::MAX - 127),
        (vec![0x48, 0x63, 0xc1], 0x80000000, 0, 0xffffffff80000000),
        (
            vec![0x66, 0x0f, 0xbe, 0xc1],
            0x80,
            0xdeadbeef00000000,
            0xdeadbeef0000ff80,
        ),
    ] {
        let regs = execute(
            &bytes,
            BTreeMap::from([("rax".into(), old), ("rcx".into(), input)]),
            BTreeMap::new(),
        );
        assert_eq!(regs["rax"], expected);
    }
}
#[test]
fn byte_load_extension_uses_exact_memory_width() {
    let regs = execute(
        &[0x0f, 0xb6, 0x00],
        BTreeMap::from([("rax".into(), 0x9000)]),
        BTreeMap::from([(0x9000, 0xff)]),
    );
    assert_eq!(regs["rax"], 255);
}
#[test]
fn fs_and_gs_are_dynamic_bases_not_absolute_file_offsets() {
    for (prefix, base) in [(0x64, "fs_base"), (0x65, "gs_base")] {
        let i = decode(&[prefix, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]);
        assert!(i.semantic_complete);
        let Statement::Assign { value, .. } = &i.statements[0] else {
            panic!("expected load")
        };
        assert!(value.reads().contains(base));
        assert!(eval(value, &BTreeMap::new(), &BTreeMap::from([(0x28, 7)])).is_none());
        let regs = BTreeMap::from([(base.into(), 0x9000)]);
        let mut memory = BTreeMap::new();
        for i in 0..8 {
            memory.insert(0x9028 + i, if i == 0 { 42 } else { 0 });
        }
        assert_eq!(eval(value, &regs, &memory), Some(42));
    }
}
#[test]
fn tls_indexing_and_lea_have_different_segment_semantics() {
    let mov = decode(&[0x64, 0x48, 0x8b, 0x44, 0x88, 0x10]);
    assert!(mov.semantic_complete);
    let address = memory_address(&mov.operands[1]);
    let regs = BTreeMap::from([
        ("fs_base".into(), 0x9000),
        ("rax".into(), 0x20),
        ("rcx".into(), 3),
    ]);
    assert_eq!(address.eval(&regs), Some(0x903c));
    let lea = decode(&[0x64, 0x48, 0x8d, 0x44, 0x88, 0x10]);
    assert!(lea.semantic_complete);
    let Statement::Assign { value, .. } = &lea.statements[0] else {
        panic!()
    };
    assert!(!value.reads().contains("fs_base"));
    assert_eq!(value.eval(&regs), Some(0x3c));
}
#[test]
fn rip_relative_address_calculation_wraps_without_panicking() {
    let i = Decoder::new("x86:LE:64")
        .unwrap()
        .decode(&[0x48, 0x8d, 0x05, 0, 0, 0, 0], Addr(u64::MAX - 3))
        .unwrap();
    let Statement::Assign { value, .. } = &i.statements[0] else {
        panic!()
    };
    assert_eq!(value.eval(&BTreeMap::new()), Some(3));
}
#[test]
fn stop_instructions_are_explicit_boundaries_not_nops_or_unknown_bytes() {
    for bytes in [&[0xf4][..], &[0x0f, 0x0b][..], &[0xcc][..]] {
        let i = decode(bytes);
        assert!(i.semantic_complete);
        assert_eq!(i.flow, Flow::Stop);
        assert!(matches!(i.statements[0], Statement::Stop { .. }));
    }
    let i = Decoder::new("AARCH64:LE:64")
        .unwrap()
        .decode(&0xd4200000u32.to_le_bytes(), Addr(0x1000))
        .unwrap();
    assert!(i.semantic_complete);
    assert_eq!(i.flow, Flow::Stop);
    assert!(matches!(i.statements[0], Statement::Stop { .. }));
}
#[test]
fn unsupported_address_size_and_atomic_prefixes_remain_barriers() {
    for bytes in [&[0x67, 0x0f, 0xb6, 0x00][..], &[0xf0, 0x48, 0x01, 0x08][..]] {
        let i = decode(bytes);
        assert!(!i.semantic_complete);
        assert!(matches!(i.statements[0], Statement::Unknown { .. }));
    }
}
#[test]
fn old_snapshots_without_segment_field_still_deserialize() {
    let op: Operand = serde_json::from_str(
        r#"{"Mem":{"base":"rax","index":null,"scale":1,"displacement":4,"bits":8}}"#,
    )
    .unwrap();
    assert_eq!(
        memory_address(&op).eval(&BTreeMap::from([("rax".into(), 16)])),
        Some(20)
    );
}

#[test]
fn simd_and_scalar_fp_are_typed_intrinsics_with_real_mandatory_prefixes() {
    for (bytes, operation, domain, bits, lanes, output) in [
        (
            &[0xf3, 0x0f, 0x58, 0xc1][..],
            "addss",
            "float",
            32,
            1,
            "xmm0",
        ),
        (
            &[0xf2, 0x0f, 0x59, 0xc1][..],
            "mulsd",
            "float",
            64,
            1,
            "xmm0",
        ),
        (&[0x66, 0x0f, 0xef, 0xc1][..], "pxor", "simd", 8, 16, "xmm0"),
        (&[0x0f, 0x58, 0xc1][..], "addps", "simd", 32, 4, "xmm0"),
    ] {
        let i = decode(bytes);
        assert!(i.semantic_complete, "{}", i.text);
        let Statement::Intrinsic {
            operation: got,
            domain: got_domain,
            outputs,
            element_bits,
            lanes: got_lanes,
            ..
        } = &i.statements[0]
        else {
            panic!("expected typed intrinsic for {}", i.text)
        };
        assert_eq!(got, operation);
        assert_eq!(got_domain, domain);
        assert_eq!(*element_bits, bits);
        assert_eq!(*got_lanes, lanes);
        assert_eq!(outputs, &vec![output.to_string()]);
    }
}
#[test]
fn vector_memory_and_fp_division_keep_effects_and_traps_explicit() {
    let load = decode(&[0xf3, 0x0f, 0x10, 0x00]); // movss xmm0, dword ptr [rax]
    assert!(load.semantic_complete);
    let effects = load.statements[0].effects();
    assert!(effects.reads_memory);
    assert!(!effects.unknown_registers);
    assert!(effects.reads.contains("rax"));
    assert!(effects.writes.contains("xmm0"));

    let divide = decode(&[0xf3, 0x0f, 0x5e, 0xc1]); // divss xmm0, xmm1
    assert!(divide.semantic_complete);
    assert!(divide.statements[0].effects().may_trap);
}
#[test]
fn arm64_fp_and_special_register_reads_are_preserved_as_intrinsics() {
    let decoder = Decoder::new("AARCH64:LE:64").unwrap();
    let fadd = decoder
        .decode(&0x1e212800u32.to_le_bytes(), Addr(0x1000)) // fadd s0, s0, s1
        .unwrap();
    assert!(fadd.semantic_complete, "{}", fadd.text);
    let Statement::Intrinsic {
        operation,
        domain,
        outputs,
        inputs,
        element_bits,
        ..
    } = &fadd.statements[0]
    else {
        panic!("expected typed FP intrinsic")
    };
    assert_eq!(operation, "fadd");
    assert_eq!(domain, "float");
    assert_eq!(*element_bits, 32);
    assert_eq!(outputs, &vec!["s0".to_string()]);
    assert_eq!(inputs, &vec!["s0".to_string(), "s1".to_string()]);

    let mrs = decoder
        .decode(&0xd53bd040u32.to_le_bytes(), Addr(0x1004)) // mrs x0, tpidr_el0
        .unwrap();
    assert!(mrs.semantic_complete, "{}", mrs.text);
    assert!(
        matches!(mrs.statements[0], Statement::Intrinsic { ref operation, ref domain, .. } if operation == "mrs" && domain == "special")
    );
}
#[test]
fn special_x86_state_instructions_do_not_become_unknown_barriers() {
    for (bytes, operation, outputs) in [
        (&[0x0f, 0x31][..], "rdtsc", vec!["rax", "rdx"]),
        (&[0x0f, 0xa2][..], "cpuid", vec!["rax", "rbx", "rcx", "rdx"]),
    ] {
        let i = decode(bytes);
        assert!(i.semantic_complete, "{}", i.text);
        let Statement::Intrinsic {
            operation: got,
            domain,
            outputs: got_outputs,
            ..
        } = &i.statements[0]
        else {
            panic!("expected special intrinsic")
        };
        assert_eq!(got, operation);
        assert_eq!(domain, "special");
        assert_eq!(
            got_outputs,
            &outputs.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }
}
