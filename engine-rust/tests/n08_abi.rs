use ghidra_web_engine::{
    analysis::{
        abi,
        dataflow::{Dataflow, Phi, Use},
    },
    core::*,
    ir::*,
    protocol,
    scheduler::{Budget, Job},
};
use std::collections::BTreeMap;
fn job() -> Job {
    Job::new(Budget::default())
}
fn sample() -> Program {
    protocol::analyze(
        include_bytes!("../../fixtures/sample-macho"),
        None,
        None,
        &mut job(),
    )
    .unwrap()
    .program
}
fn synthetic(statements: Vec<Statement>, win: bool) -> (Program, Function) {
    let mut p = sample();
    if win {
        p.architecture = "x86:LE:64".into();
        p.format = "PE32+".into();
    }
    let mut f = p.functions.values().next().unwrap().clone();
    let a = f.entry;
    f.members = vec![a];
    f.blocks = vec![Block {
        address: a,
        members: vec![a],
        successors: vec![],
    }];
    p.instructions.get_mut(&a).unwrap().statements = statements;
    (p, f)
}
fn load(offset: i64, bits: u16, reg: &str) -> Expr {
    Expr::Load {
        address: Box::new(binary("+", var(reg, 64), constant(offset as u64, 64), 64)),
        bits,
    }
}
#[test]
fn profiles_distinguish_stack_layouts_and_registers() {
    let mut p = sample();
    let f = p.functions.values().next().unwrap();
    let r = abi::report(&p, f, &mut job()).unwrap();
    assert_eq!(r["firstStackArgumentOffset"], 0);
    assert!(abi::select(&p).clobbers.contains(&"x30".into()));
    p.architecture = "x86:LE:64".into();
    p.format = "PE32+".into();
    let f = p.functions.values().next().unwrap();
    let r = abi::report(&p, f, &mut job()).unwrap();
    assert_eq!(r["shadowSpaceBytes"], 32);
    assert_eq!(r["firstStackArgumentOffset"], 40);
    p.format = "ELF".into();
    let f = p.functions.values().next().unwrap();
    assert_eq!(
        abi::report(&p, f, &mut job()).unwrap()["firstStackArgumentOffset"],
        8
    );
}
#[test]
fn truncated_stack_pointers_are_not_aliases() {
    let offsets = BTreeMap::from([("sp".into(), 0)]);
    assert_eq!(abi::stack_offset(&var("sp", 32), &offsets), None);
    assert_eq!(
        abi::stack_offset(&binary("+", var("sp", 64), constant(8, 64), 32), &offsets),
        None
    );
    assert_eq!(
        abi::stack_offset(&binary("+", var("sp", 64), constant(8, 64), 64), &offsets),
        Some(8)
    );
}
#[test]
fn nested_phis_recover_parameter_and_pointer_type() {
    let (p, f) = synthetic(
        vec![Statement::Assign {
            dst: "x1".into(),
            value: Expr::Load {
                address: Box::new(var("x0", 64)),
                bits: 8,
            },
        }],
        false,
    );
    let mut df = Dataflow::default();
    df.phis = vec![
        Phi {
            id: "p1".into(),
            block: f.entry,
            register: "x0".into(),
            incoming: BTreeMap::from([(f.entry, vec!["input:x0".into()])]),
            entry_input: None,
        },
        Phi {
            id: "p2".into(),
            block: f.entry,
            register: "x0".into(),
            incoming: BTreeMap::from([(f.entry, vec!["p1".into(), "p2".into()])]),
            entry_input: None,
        },
    ];
    df.uses = vec![Use {
        address: f.entry,
        statement: 0,
        register: "x0".into(),
        definitions: vec!["p2".into()],
    }];
    let v = abi::variables(
        &f,
        &p.instructions,
        &df,
        &abi::select(&p),
        &p.overrides,
        &mut job(),
    )
    .unwrap();
    assert!(v
        .iter()
        .any(|v| v.parameter && v.storage == "x0" && v.ty == "uint8_ptr"));
}
#[test]
fn phi_cycle_without_input_does_not_invent_parameter() {
    let (p, f) = synthetic(vec![Statement::Nop], false);
    let mut df = Dataflow::default();
    df.phis = vec![Phi {
        id: "p".into(),
        block: f.entry,
        register: "x0".into(),
        incoming: BTreeMap::from([(f.entry, vec!["p".into()])]),
        entry_input: None,
    }];
    df.uses = vec![Use {
        address: f.entry,
        statement: 0,
        register: "x0".into(),
        definitions: vec!["p".into()],
    }];
    assert!(!abi::variables(
        &f,
        &p.instructions,
        &df,
        &abi::select(&p),
        &p.overrides,
        &mut job()
    )
    .unwrap()
    .iter()
    .any(|v| v.parameter));
}
#[test]
fn loads_in_flags_and_store_values_are_collected_at_max_width() {
    let (p, f) = synthetic(
        vec![
            Statement::Flags {
                op: "-".into(),
                left: load(-8, 8, "sp"),
                right: constant(0, 8),
                bits: 8,
            },
            Statement::Store {
                address: var("x1", 64),
                value: load(-8, 64, "sp"),
                bits: 64,
            },
        ],
        false,
    );
    let v = abi::variables(
        &f,
        &p.instructions,
        &Dataflow::default(),
        &abi::select(&p),
        &p.overrides,
        &mut job(),
    )
    .unwrap();
    assert!(v
        .iter()
        .any(|v| v.storage == "entry_sp-8" && v.ty == "uint64_t"));
}
#[test]
fn win64_shadow_space_is_not_a_stack_argument() {
    let (p, f) = synthetic(
        vec![
            Statement::Assign {
                dst: "rax".into(),
                value: load(8, 64, "rsp"),
            },
            Statement::Assign {
                dst: "rax".into(),
                value: load(40, 64, "rsp"),
            },
        ],
        true,
    );
    let r = abi::report(&p, &f, &mut job()).unwrap();
    assert_eq!(r["stackAccesses"][0]["region"], "shadow-space");
    assert_eq!(r["stackAccesses"][0]["parameterCandidate"], false);
    assert_eq!(r["stackAccesses"][1]["parameterCandidate"], true);
}
#[test]
fn stack_balance_reports_known_and_unknown_without_guessing() {
    let (p, f) = synthetic(
        vec![
            Statement::Assign {
                dst: "sp".into(),
                value: binary("-", var("sp", 64), constant(16, 64), 64),
            },
            Statement::Call {
                target: constant(99, 64),
            },
            Statement::Assign {
                dst: "sp".into(),
                value: binary("+", var("sp", 64), constant(16, 64), 64),
            },
            Statement::Return,
        ],
        false,
    );
    let r = abi::report(&p, &f, &mut job()).unwrap();
    assert_eq!(r["calls"][0]["stackOffset"], -16);
    assert_eq!(r["returns"][0]["balanced"], true);
    let (p, f) = synthetic(
        vec![
            Statement::Unknown {
                description: "dynamic".into(),
            },
            Statement::Return,
        ],
        false,
    );
    assert!(abi::report(&p, &f, &mut job()).unwrap()["returns"][0]["balanced"].is_null());
}
#[test]
fn report_obeys_work_budget() {
    let (p, f) = synthetic(vec![Statement::Nop], false);
    assert!(abi::report(
        &p,
        &f,
        &mut Job::new(Budget {
            max_work: 1,
            ..Default::default()
        })
    )
    .is_err());
}

#[test]
fn direct_call_reports_constant_integer_argument_evidence() {
    let (mut p, f) = synthetic(
        vec![
            Statement::Assign {
                dst: "rdi".into(),
                value: constant(7, 64),
            },
            Statement::Assign {
                dst: "rsi".into(),
                value: constant(9, 64),
            },
            Statement::Call {
                target: constant(0x1234, 64),
            },
        ],
        false,
    );
    p.architecture = "x86:LE:64".into();
    p.format = "ELF".into();
    let report = abi::report(&p, &f, &mut job()).unwrap();
    assert_eq!(report["calls"][0]["direct"], true);
    assert_eq!(report["calls"][0]["target"], "1234");
    assert_eq!(report["calls"][0]["arguments"][0]["register"], "rdi");
    assert_eq!(report["calls"][0]["arguments"][0]["value"], 7);
    assert_eq!(report["calls"][0]["arguments"][1]["register"], "rsi");
    assert_eq!(report["calls"][0]["arguments"][1]["value"], 9);
}

#[test]
fn callee_saved_stack_evidence_requires_matching_register_and_slot() {
    let (mut p, f) = synthetic(
        vec![
            Statement::Store {
                address: binary("-", var("rsp", 64), constant(8, 64), 64),
                value: var("rbx", 64),
                bits: 64,
            },
            Statement::Assign {
                dst: "rsp".into(),
                value: binary("-", var("rsp", 64), constant(8, 64), 64),
            },
            Statement::Assign {
                dst: "rbx".into(),
                value: Expr::Load {
                    address: Box::new(var("rsp", 64)),
                    bits: 64,
                },
            },
            Statement::Return,
        ],
        false,
    );
    p.architecture = "x86:LE:64".into();
    p.format = "ELF".into();
    let report = abi::report(&p, &f, &mut job()).unwrap();
    assert_eq!(report["calleeSavedEvidence"][0]["kind"], "save");
    assert_eq!(report["calleeSavedEvidence"][0]["register"], "rbx");
    assert_eq!(report["calleeSavedEvidence"][0]["stackOffset"], -8);
    assert_eq!(report["calleeSavedEvidence"][1]["kind"], "restore");
    assert_eq!(report["calleeSavedEvidence"][1]["register"], "rbx");
    assert_eq!(report["calleeSavedEvidence"][1]["stackOffset"], -8);
}

#[test]
fn fp_register_profiles_and_direct_call_evidence_are_reported() {
    let (mut p, f) = synthetic(
        vec![
            Statement::Intrinsic {
                operation: "addss".into(),
                domain: "float".into(),
                outputs: vec!["xmm0".into()],
                inputs: vec!["xmm1".into()],
                element_bits: 32,
                lanes: 1,
                reads_memory: false,
                writes_memory: false,
                may_trap: false,
            },
            Statement::Call {
                target: constant(0x1234, 64),
            },
        ],
        true,
    );
    p.architecture = "x86:LE:64".into();
    let report = abi::report(&p, &f, &mut job()).unwrap();
    assert_eq!(report["floatingArgumentRegisters"][0], "xmm0");
    assert_eq!(report["floatingReturnRegister"], "xmm0");
    assert_eq!(
        report["calls"][0]["floatingArguments"][0]["register"],
        "xmm0"
    );
    assert!(report["calls"][0]["floatingArguments"][0]["definitions"][0]
        .as_str()
        .unwrap()
        .contains("xmm0"));

    p.architecture = "AARCH64:LE:64".into();
    let arm = abi::select(&p);
    assert_eq!(arm.float_args[0], "v0");
    assert_eq!(arm.float_result, "v0");
}
