use ghidra_web_engine::{
    analysis::dataflow::{self, Dataflow},
    core::*,
    ir::*,
    protocol,
    scheduler::{Budget, Job},
};
use std::collections::{BTreeMap, BTreeSet};
fn fixture(
    edges: &[(u64, Vec<u64>)],
    statements: &[(u64, Vec<Statement>)],
) -> (Function, BTreeMap<Addr, Instruction>) {
    let p = protocol::analyze(
        include_bytes!("../../fixtures/sample-macho"),
        None,
        None,
        &mut Job::new(Budget::default()),
    )
    .unwrap()
    .program;
    let mut f = p.functions.values().next().unwrap().clone();
    f.entry = Addr(edges[0].0);
    f.members = edges.iter().map(|(a, _)| Addr(*a)).collect();
    f.blocks = edges
        .iter()
        .map(|(a, to)| Block {
            address: Addr(*a),
            members: vec![Addr(*a)],
            successors: to.iter().map(|a| Addr(*a)).collect(),
        })
        .collect();
    let mut ins = BTreeMap::new();
    for (a, _) in edges {
        let mut i = p.instructions.values().next().unwrap().clone();
        i.address = Addr(*a);
        i.statements = statements
            .iter()
            .find(|(b, _)| a == b)
            .map_or(vec![Statement::Nop], |(_, s)| s.clone());
        ins.insert(Addr(*a), i);
    }
    (f, ins)
}
fn set(v: u64) -> Statement {
    Statement::Assign {
        dst: "x".into(),
        value: constant(v, 64),
    }
}
fn read() -> Statement {
    Statement::Assign {
        dst: "y".into(),
        value: var("x", 64),
    }
}
fn run(f: &Function, i: &BTreeMap<Addr, Instruction>) -> Dataflow {
    dataflow::analyze(f, i, &[], &mut Job::new(Budget::default())).unwrap()
}
#[test]
fn diamond_has_idom_frontiers_live_phi_and_reverse_uses() {
    let (f, i) = fixture(
        &[
            (1, vec![2, 3]),
            (2, vec![4]),
            (3, vec![4]),
            (4, vec![5]),
            (5, vec![]),
        ],
        &[(2, vec![set(7)]), (3, vec![set(9)]), (5, vec![read()])],
    );
    let d = run(&f, &i);
    assert_eq!(d.immediate_dominators[&Addr(4)], Some(Addr(1)));
    assert_eq!(d.dominance_frontiers[&Addr(2)], BTreeSet::from([Addr(4)]));
    assert!(d.live_in[&Addr(4)].contains("x"));
    let phi = d.phis.iter().find(|p| p.register == "x").unwrap();
    assert_eq!(phi.block, Addr(4));
    assert_eq!(d.phis.len(), 1);
    assert!(d.def_uses[&phi.id].iter().any(|u| u.address == Addr(5)));
    for ids in phi.incoming.values() {
        assert!(d.phi_uses[&ids[0]].contains(&phi.id));
    }
}
#[test]
fn dead_merge_is_pruned() {
    let (f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[(2, vec![set(1)]), (3, vec![set(2)]), (4, vec![set(3)])],
    );
    assert!(run(&f, &i).phis.is_empty());
}
#[test]
fn loop_entry_retains_external_input() {
    let (f, i) = fixture(
        &[(1, vec![1, 2]), (2, vec![])],
        &[(1, vec![read(), set(3)]), (2, vec![read()])],
    );
    let d = run(&f, &i);
    let phi = d.phis.iter().find(|p| p.register == "x").unwrap();
    assert_eq!(phi.entry_input.as_deref(), Some("input:x"));
    assert!(d.dominance_frontiers[&Addr(1)].contains(&Addr(1)));
}
#[test]
fn constants_are_available_before_each_statement() {
    let (f, i) = fixture(&[(1, vec![])], &[(1, vec![set(7), read(), set(9)])]);
    let d = run(&f, &i);
    assert!(!d.constants_at_statement[&Addr(1)][0].contains_key("x"));
    assert_eq!(d.constants_at_statement[&Addr(1)][1]["x"], 7);
    assert_eq!(d.constants_at_statement[&Addr(1)][2]["y"], 7);
}
#[test]
fn disagreeing_paths_do_not_produce_constant() {
    let (f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[(2, vec![set(1)]), (3, vec![set(2)]), (4, vec![read()])],
    );
    assert!(!run(&f, &i).constants_before[&Addr(4)].contains_key("x"));
}
#[test]
fn equal_paths_preserve_constant() {
    let (f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[(2, vec![set(7)]), (3, vec![set(7)]), (4, vec![read()])],
    );
    assert_eq!(run(&f, &i).constants_before[&Addr(4)]["x"], 7);
}
#[test]
fn unknown_kills_versions_and_constants() {
    let (f, i) = fixture(
        &[(1, vec![])],
        &[(
            1,
            vec![
                set(7),
                Statement::Unknown {
                    description: "opaque".into(),
                },
                read(),
            ],
        )],
    );
    let d = run(&f, &i);
    assert!(!d.constants_at_statement[&Addr(1)][2].contains_key("x"));
    assert!(d
        .uses
        .iter()
        .find(|u| u.statement == 2)
        .unwrap()
        .definitions[0]
        .starts_with("unknown:"));
}
#[test]
fn call_arguments_preserve_live_merges() {
    let (f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[
            (2, vec![set(1)]),
            (3, vec![set(2)]),
            (
                4,
                vec![Statement::Call {
                    target: constant(99, 64),
                }],
            ),
        ],
    );
    assert!(run(&f, &i).phis.iter().any(|p| p.register == "x"));
}
#[test]
fn invalid_cfg_and_budget_fail_explicitly() {
    let (f, i) = fixture(&[(1, vec![99])], &[]);
    assert!(dataflow::analyze(&f, &i, &[], &mut Job::new(Budget::default())).is_err());
    let (f, i) = fixture(&[(1, vec![]), (2, vec![])], &[]);
    assert!(dataflow::analyze(&f, &i, &[], &mut Job::new(Budget::default())).is_err());
    let (f, i) = fixture(&[(1, vec![])], &[]);
    assert!(dataflow::analyze(
        &f,
        &i,
        &[],
        &mut Job::new(Budget {
            max_work: 1,
            ..Default::default()
        })
    )
    .is_err());
}
#[test]
fn old_dataflow_json_loads_with_empty_new_fields() {
    let old = r#"{"dominators":{},"phis":[],"uses":[],"constants_before":{},"reaching_in":{}}"#;
    let d: Dataflow = serde_json::from_str(old).unwrap();
    assert!(d.live_in.is_empty() && d.def_uses.is_empty());
}
#[test]
fn block_order_does_not_change_analysis() {
    let (mut f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[(2, vec![set(7)]), (3, vec![set(9)]), (4, vec![read()])],
    );
    let a = run(&f, &i);
    f.blocks.reverse();
    let b = run(&f, &i);
    assert_eq!(a.dominators, b.dominators);
    assert_eq!(a.live_in, b.live_in);
    assert_eq!(a.phis, b.phis);
    assert_eq!(a.constants_at_statement, b.constants_at_statement);
}
#[test]
fn call_kills_only_abi_clobbered_constants() {
    let (f, i) = fixture(
        &[(1, vec![])],
        &[(
            1,
            vec![
                set(7),
                Statement::Assign {
                    dst: "saved".into(),
                    value: constant(8, 64),
                },
                Statement::Call {
                    target: constant(99, 64),
                },
                read(),
            ],
        )],
    );
    let d = dataflow::analyze(&f, &i, &["x".into()], &mut Job::new(Budget::default())).unwrap();
    assert!(!d.constants_at_statement[&Addr(1)][3].contains_key("x"));
    assert_eq!(d.constants_at_statement[&Addr(1)][3]["saved"], 8);
}
#[test]
fn implicit_memory_and_flags_have_versions_without_explicit_operands() {
    let call = Statement::Call {
        target: constant(99, 64),
    };
    let (f, i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[
            (2, vec![call.clone()]),
            (3, vec![call]),
            (4, vec![Statement::Return]),
        ],
    );
    let d = run(&f, &i);
    for r in ["__memory", "__flags"] {
        assert!(d
            .phis
            .iter()
            .any(|p| p.register == r && p.incoming.len() == 2));
    }
}

#[test]
fn constant_branch_excludes_impossible_edge_and_preserves_path_constant() {
    let (f, mut i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[
            (
                1,
                vec![
                    set(7),
                    Statement::Branch {
                        condition: Expr::Compare {
                            op: "==".into(),
                            left: Box::new(var("x", 64)),
                            right: Box::new(constant(7, 64)),
                            bits: 64,
                        },
                        target: Addr(2),
                    },
                ],
            ),
            (2, vec![set(7)]),
            (3, vec![set(9)]),
            (4, vec![read()]),
        ],
    );
    i.get_mut(&Addr(1)).unwrap().flow = Flow::Branch(Addr(2));
    let dataflow = run(&f, &i);
    assert_eq!(dataflow.feasible_edges[&Addr(1)], BTreeSet::from([Addr(2)]));
    assert!(dataflow.unreachable_blocks.contains(&Addr(3)));
    assert_eq!(
        dataflow.constants_before[&Addr(4)].get("x"),
        Some(&7),
        "{:?}",
        dataflow.constants_before
    );
}

#[test]
fn sccp_reaches_stable_edges_and_exposes_ranges_and_memory_aliases() {
    let (f, mut i) = fixture(
        &[(1, vec![2, 3]), (2, vec![4]), (3, vec![4]), (4, vec![])],
        &[
            (
                1,
                vec![
                    set(7),
                    Statement::Branch {
                        condition: Expr::Compare {
                            op: "==".into(),
                            left: Box::new(var("x", 64)),
                            right: Box::new(constant(7, 64)),
                            bits: 64,
                        },
                        target: Addr(2),
                    },
                ],
            ),
            (
                2,
                vec![Statement::Store {
                    address: binary("+", var("rsp", 64), constant(8, 64), 64),
                    value: constant(1, 64),
                    bits: 64,
                }],
            ),
            (
                3,
                vec![Statement::Store {
                    address: binary("+", var("rsp", 64), constant(16, 64), 64),
                    value: constant(2, 64),
                    bits: 64,
                }],
            ),
            (4, vec![read()]),
        ],
    );
    i.get_mut(&Addr(1)).unwrap().flow = Flow::Branch(Addr(2));
    let d = run(&f, &i);
    assert_eq!(d.feasible_edges[&Addr(1)], BTreeSet::from([Addr(2)]));
    assert_eq!(d.ranges_before[&Addr(1)][1]["x"].minimum, 7);
    assert!(d.memory_alias_sets.contains_key("stack:8"));
    assert!(!d.memory_alias_sets.contains_key("stack:16"));
    assert!(
        d.memory_ssa.is_empty(),
        "no loads or memory phi exist in this fixture"
    );
}

#[test]
fn cmp_flags_make_a_following_conditional_edge_feasible() {
    let (f, mut i) = fixture(
        &[(1, vec![2, 3]), (2, vec![]), (3, vec![])],
        &[(1, vec![
            Statement::Flags { op: "-".into(), left: constant(7, 64), right: constant(7, 64), bits: 64 },
            Statement::Branch { condition: Expr::Condition("e".into()), target: Addr(2) },
        ])],
    );
    i.get_mut(&Addr(1)).unwrap().flow = Flow::Branch(Addr(2));
    assert_eq!(run(&f, &i).feasible_edges[&Addr(1)], BTreeSet::from([Addr(2)]));
}
