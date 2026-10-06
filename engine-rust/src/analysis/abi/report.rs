use super::*;
use crate::{scheduler::Job, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// ABI-relative observations, not a recovered C prototype or proof of preservation.
pub fn report(p: &Program, f: &Function, job: &mut Job) -> Result<Value> {
    let abi = select(p);
    let arm = p.architecture.starts_with("AARCH64");
    let win = !arm && p.format == "PE32+";
    let first_stack_argument = first_stack_argument_offset(&abi);
    let preserved = callee_saved(arm, win);
    let states = stack_states(f, &p.instructions, &abi, job)?;
    let return_checks = callee_saved_return_checks(p, f, &abi, &preserved, &states, job)?;
    let mut accesses = vec![];
    let mut calls = vec![];
    let mut returns = vec![];
    let mut saved_registers = vec![];

    for b in &f.blocks {
        let mut offsets = states.get(&b.address).cloned().unwrap_or_default();
        let mut values = BTreeMap::new();
        let mut definitions = f
            .dataflow
            .reaching_in
            .get(&b.address)
            .cloned()
            .unwrap_or_default();
        for a in &b.members {
            values = f
                .dataflow
                .constants_before
                .get(a)
                .cloned()
                .unwrap_or(values);
            for (index, statement) in p.instructions[a].statements.iter().enumerate() {
                job.tick()?;
                let mut loads = BTreeMap::new();
                for expression in expressions(statement) {
                    collect_loads(expression, &offsets, &mut loads);
                }
                let stores = if let Statement::Store { address, bits, .. } = statement {
                    stack_offset(address, &offsets).map(|offset| (offset, *bits))
                } else {
                    None
                };
                for (offset, bits, kind) in loads
                    .into_iter()
                    .map(|(offset, bits)| (offset, bits, "read"))
                    .chain(stores.map(|(offset, bits)| (offset, bits, "write")))
                {
                    accesses.push(json!({
                        "address":a,
                        "statementIndex":index,
                        "offset":offset,
                        "bits":bits,
                        "kind":kind,
                        "region":stack_region(offset, arm, win),
                        "parameterCandidate":kind=="read" && offset>=first_stack_argument,
                        "confidence":"inferred"
                    }));
                }

                record_saved_register(
                    statement,
                    *a,
                    index,
                    &offsets,
                    &preserved,
                    &abi.stack,
                    &mut saved_registers,
                );

                match statement {
                    Statement::Assign { dst, value } => {
                        let offset = stack_offset(value, &offsets);
                        offsets.remove(dst);
                        if let Some(offset) = offset {
                            offsets.insert(dst.clone(), offset);
                        }
                        values.remove(dst);
                        if let Some(value) = value.eval(&values) {
                            values.insert(dst.clone(), value);
                        }
                        definitions
                            .insert(dst.clone(), BTreeSet::from([format!("{a}:{index}:{dst}")]));
                    }
                    Statement::Intrinsic { outputs, .. } => {
                        for output in outputs {
                            definitions.insert(
                                output.clone(),
                                BTreeSet::from([format!("{a}:{index}:{output}")]),
                            );
                        }
                    }
                    Statement::Call { target } => {
                        let destination = target.eval(&values);
                        calls.push(json!({
                            "address":a,
                            "target":destination.map(Addr),
                            "direct":destination.is_some(),
                            "stackOffset":offsets.get(&abi.stack),
                            "arguments":call_arguments(&abi, &values, &definitions),
                            "floatingArguments":call_float_arguments(&abi, &definitions),
                            "confidence":if destination.is_some() {"constant-target"} else {"unknown-target"}
                        }));
                        offsets.retain(|register, _| !abi.clobbers.contains(register));
                        for register in &abi.clobbers {
                            values.remove(register);
                            definitions.insert(
                                register.clone(),
                                BTreeSet::from([format!("unknown:{a}:{index}:{register}")]),
                            );
                        }
                    }
                    Statement::Return => returns.push(json!({
                        "address":a,
                        "statementIndex":index,
                        "stackOffset":offsets.get(&abi.stack),
                        "balanced":offsets.get(&abi.stack).map(|offset|*offset==0)
                    })),
                    Statement::Unknown { .. } => {
                        offsets.clear();
                        values.clear();
                        definitions.clear();
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(json!({
        "name":abi.name,
        "argumentRegisters":abi.args,
        "returnRegister":abi.result,
        "floatingArgumentRegisters":abi.float_args,
        "floatingReturnRegister":abi.float_result,
        "stackRegister":abi.stack,
        "callerSaved":abi.clobbers,
        "calleeSaved":preserved,
        "stackAlignment":16,
        "firstStackArgumentOffset":first_stack_argument,
        "shadowSpaceBytes":if win {32} else {0},
        "stackAccesses":accesses,
        "calls":calls,
        "returns":returns,
        "calleeSavedEvidence":saved_registers,
        "calleeSavedReturnChecks":return_checks,
        "limits":"Integer scalar ABI approximation. Register values and reaching definitions at calls are inferred evidence, not verified prototypes. A callee-saved return check is only restored when every merged path has the same empty outstanding-save set. Platform variants, aggregate/FP/variadic signatures and dynamic frames are not recovered."
    }))
}

fn callee_saved(arm: bool, win: bool) -> Vec<String> {
    if arm {
        (19..=29)
            .map(|number| format!("x{number}"))
            .chain(["sp".into()])
            .collect()
    } else if win {
        [
            "rbx", "rbp", "rdi", "rsi", "rsp", "r12", "r13", "r14", "r15",
        ]
        .map(str::to_string)
        .to_vec()
    } else {
        ["rbx", "rbp", "rsp", "r12", "r13", "r14", "r15"]
            .map(str::to_string)
            .to_vec()
    }
}

fn stack_region(offset: i64, arm: bool, win: bool) -> &'static str {
    if offset < 0 {
        "frame-or-red-zone"
    } else if !arm && offset < 8 {
        "return-address"
    } else if win && offset < 40 {
        "shadow-space"
    } else {
        "stack-argument-area"
    }
}

fn call_arguments(
    abi: &Abi,
    values: &BTreeMap<String, u64>,
    definitions: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Value> {
    abi.args
        .iter()
        .enumerate()
        .filter_map(|(position, register)| {
            if let Some(value) = values.get(register) {
                Some(json!({
                    "position":position,
                    "register":register,
                    "value":value,
                    "confidence":"constant"
                }))
            } else {
                definitions
                    .get(register)
                    .filter(|ids| !ids.is_empty())
                    .map(|ids| {
                        json!({
                            "position":position,
                            "register":register,
                            "definitions":ids,
                            "confidence":"reaching-definition"
                        })
                    })
            }
        })
        .collect()
}

fn call_float_arguments(abi: &Abi, definitions: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    abi.float_args
        .iter()
        .enumerate()
        .filter_map(|(position, register)| {
            definitions
                .get(register)
                .filter(|definitions| !definitions.is_empty())
                .map(|definitions| {
                    json!({
                        "position": position,
                        "register": register,
                        "definitions": definitions,
                        "confidence": "reaching-definition"
                    })
                })
        })
        .collect()
}

fn record_saved_register(
    statement: &Statement,
    address: Addr,
    index: usize,
    offsets: &BTreeMap<String, i64>,
    preserved: &[String],
    stack: &str,
    result: &mut Vec<Value>,
) {
    match statement {
        Statement::Store {
            address: slot,
            value: Expr::Var { name, .. },
            ..
        } if name != stack && preserved.contains(name) => {
            if let Some(offset) = stack_offset(slot, offsets) {
                result.push(json!({
                    "address":address,
                    "statementIndex":index,
                    "kind":"save",
                    "register":name,
                    "stackOffset":offset,
                    "confidence":"inferred"
                }));
            }
        }
        Statement::Assign {
            dst,
            value: Expr::Load { address: slot, .. },
        } if dst != stack && preserved.contains(dst) => {
            if let Some(offset) = stack_offset(slot, offsets) {
                result.push(json!({
                    "address":address,
                    "statementIndex":index,
                    "kind":"restore",
                    "register":dst,
                    "stackOffset":offset,
                    "confidence":"inferred"
                }));
            }
        }
        _ => {}
    }
}

fn callee_saved_return_checks(
    p: &Program,
    f: &Function,
    abi: &Abi,
    preserved: &[String],
    states: &BTreeMap<Addr, BTreeMap<String, i64>>,
    job: &mut Job,
) -> Result<Vec<Value>> {
    type Outstanding = BTreeMap<String, i64>;
    let predecessors = f
        .blocks
        .iter()
        .map(|block| {
            (
                block.address,
                f.blocks
                    .iter()
                    .filter(|candidate| candidate.successors.contains(&block.address))
                    .map(|candidate| candidate.address)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut outputs = BTreeMap::<Addr, Option<Outstanding>>::new();
    let mut inputs = BTreeMap::<Addr, Option<Outstanding>>::new();

    loop {
        let mut changed = false;
        for block in &f.blocks {
            job.tick()?;
            let input = if block.address == f.entry {
                Some(Outstanding::new())
            } else {
                let preds = &predecessors[&block.address];
                let first = preds
                    .first()
                    .and_then(|pred| outputs.get(pred))
                    .cloned()
                    .flatten();
                match first {
                    Some(candidate)
                        if preds.iter().all(|pred| {
                            outputs
                                .get(pred)
                                .is_some_and(|output| output.as_ref() == Some(&candidate))
                        }) =>
                    {
                        Some(candidate)
                    }
                    _ => None,
                }
            };
            let output =
                transfer_callee_saved(input.clone(), block, p, abi, preserved, states, job)?;
            changed |= outputs.get(&block.address) != Some(&output)
                || inputs.get(&block.address) != Some(&input);
            outputs.insert(block.address, output);
            inputs.insert(block.address, input);
        }
        if !changed {
            break;
        }
    }

    let mut checks = vec![];
    for block in &f.blocks {
        let mut outstanding = inputs.get(&block.address).cloned().flatten();
        let mut offsets = states.get(&block.address).cloned().unwrap_or_default();
        for address in &block.members {
            for (index, statement) in p.instructions[address].statements.iter().enumerate() {
                job.tick()?;
                if matches!(statement, Statement::Return) {
                    let status = match &outstanding {
                        Some(saved) if saved.is_empty() => "restored",
                        Some(_) => "outstanding-save",
                        None => "not-proven",
                    };
                    checks.push(json!({
                        "address":address,
                        "statementIndex":index,
                        "status":status,
                        "outstanding":outstanding.as_ref()
                    }));
                }
                apply_callee_saved(&mut outstanding, statement, &mut offsets, abi, preserved);
            }
        }
    }
    Ok(checks)
}

fn transfer_callee_saved(
    mut outstanding: Option<BTreeMap<String, i64>>,
    block: &Block,
    p: &Program,
    abi: &Abi,
    preserved: &[String],
    states: &BTreeMap<Addr, BTreeMap<String, i64>>,
    job: &mut Job,
) -> Result<Option<BTreeMap<String, i64>>> {
    let mut offsets = states.get(&block.address).cloned().unwrap_or_default();
    for address in &block.members {
        for statement in &p.instructions[address].statements {
            job.tick()?;
            apply_callee_saved(&mut outstanding, statement, &mut offsets, abi, preserved);
        }
    }
    Ok(outstanding)
}

fn apply_callee_saved(
    outstanding: &mut Option<BTreeMap<String, i64>>,
    statement: &Statement,
    offsets: &mut BTreeMap<String, i64>,
    abi: &Abi,
    preserved: &[String],
) {
    if let Some(saved) = outstanding {
        match statement {
            Statement::Store {
                address: slot,
                value: Expr::Var { name, .. },
                ..
            } if name != &abi.stack && preserved.contains(name) => {
                if let Some(offset) = stack_offset(slot, offsets) {
                    saved.insert(name.clone(), offset);
                }
            }
            Statement::Assign {
                dst,
                value: Expr::Load { address: slot, .. },
            } if dst != &abi.stack && preserved.contains(dst) => {
                if let Some(offset) = stack_offset(slot, offsets) {
                    if saved.get(dst) == Some(&offset) {
                        saved.remove(dst);
                    }
                }
            }
            Statement::Unknown { .. } => *outstanding = None,
            _ => {}
        }
    }
    if let Statement::Assign { dst, value } = statement {
        let offset = stack_offset(value, offsets);
        offsets.remove(dst);
        if let Some(offset) = offset {
            offsets.insert(dst.clone(), offset);
        }
    }
    if matches!(statement, Statement::Call { .. }) {
        offsets.retain(|register, _| !abi.clobbers.contains(register));
    }
}
