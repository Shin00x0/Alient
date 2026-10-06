//! N08: ABI register sets, input parameters and abstract stack offsets.
use crate::{analysis::dataflow::Dataflow, core::*, ir::*};
use std::collections::BTreeMap;
#[derive(Debug, Clone)]
pub struct Abi {
    pub name: &'static str,
    pub args: Vec<String>,
    pub float_args: Vec<String>,
    pub result: String,
    pub float_result: String,
    pub stack: String,
    pub clobbers: Vec<String>,
}
pub fn select(p: &Program) -> Abi {
    if p.architecture.starts_with("AARCH64") {
        Abi {
            name: "AAPCS64",
            args: (0..8).map(|n| format!("x{n}")).collect(),
            float_args: (0..8).map(|n| format!("v{n}")).collect(),
            result: "x0".into(),
            float_result: "v0".into(),
            stack: "sp".into(),
            clobbers: (0..19)
                .map(|n| format!("x{n}"))
                .chain((0..32).map(|n| format!("v{n}")))
                .chain(["x30".into()])
                .collect(),
        }
    } else if p.format == "PE32+" {
        Abi {
            name: "Win64",
            args: ["rcx", "rdx", "r8", "r9"].map(str::to_string).to_vec(),
            float_args: (0..4).map(|n| format!("xmm{n}")).collect(),
            result: "rax".into(),
            float_result: "xmm0".into(),
            stack: "rsp".into(),
            clobbers: ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
                .into_iter()
                .map(str::to_string)
                .chain((0..6).map(|n| format!("xmm{n}")))
                .collect(),
        }
    } else {
        Abi {
            name: "SysV AMD64",
            args: ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                .map(str::to_string)
                .to_vec(),
            float_args: (0..8).map(|n| format!("xmm{n}")).collect(),
            result: "rax".into(),
            float_result: "xmm0".into(),
            stack: "rsp".into(),
            clobbers: ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
                .into_iter()
                .map(str::to_string)
                .chain((0..16).map(|n| format!("xmm{n}")))
                .collect(),
        }
    }
}
pub fn first_stack_argument_offset(abi: &Abi) -> i64 {
    match abi.name {
        "AAPCS64" => 0,
        "Win64" => 40,
        _ => 8,
    }
}

pub fn variables(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    df: &Dataflow,
    abi: &Abi,
    overrides: &Overrides,
    job: &mut crate::scheduler::Job,
) -> crate::Result<Vec<Variable>> {
    let mut variables = vec![];
    for (i, arg) in abi.args.iter().enumerate() {
        if df.uses.iter().any(|u| {
            u.register == *arg && u.definitions.iter().any(|d| derives_from_input(d, arg, df))
        }) {
            let id = format!("{}:param:{arg}", f.entry);
            variables.push(Variable {
                id: id.clone(),
                name: overrides
                    .variable_names
                    .get(&id)
                    .cloned()
                    .unwrap_or(format!("arg_{i}")),
                ty: overrides
                    .variable_types
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| infer_parameter(arg, f, instructions, df)),
                storage: arg.clone(),
                parameter: true,
            });
        }
    }
    for (i, arg) in abi.float_args.iter().enumerate() {
        if df.uses.iter().any(|use_| {
            use_.register == *arg
                && use_
                    .definitions
                    .iter()
                    .any(|definition| derives_from_input(definition, arg, df))
        }) {
            let id = format!("{}:float-param:{arg}", f.entry);
            variables.push(Variable {
                id: id.clone(),
                name: overrides
                    .variable_names
                    .get(&id)
                    .cloned()
                    .unwrap_or(format!("fp_arg_{i}")),
                ty: overrides
                    .variable_types
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| infer_float_parameter(arg, f, instructions)),
                storage: arg.clone(),
                parameter: true,
            });
        }
    }
    let states = stack_states(f, instructions, abi, job)?;
    let mut slots: BTreeMap<i64, u16> = BTreeMap::new();
    let mut read_slots: BTreeMap<i64, u16> = BTreeMap::new();
    for b in &f.blocks {
        let mut offsets = states.get(&b.address).cloned().unwrap_or_default();
        for a in &b.members {
            for s in &instructions[a].statements {
                for e in expressions(s) {
                    collect_loads(e, &offsets, &mut slots);
                    collect_loads(e, &offsets, &mut read_slots);
                }
                match s {
                    Statement::Assign { dst, value } => {
                        collect_loads(value, &offsets, &mut slots);
                        let o = stack_offset(value, &offsets);
                        offsets.remove(dst);
                        if let Some(o) = o {
                            offsets.insert(dst.clone(), o);
                        }
                    }
                    Statement::Store { address, bits, .. } => {
                        if let Some(o) = stack_offset(address, &offsets) {
                            slots
                                .entry(o)
                                .and_modify(|b| *b = (*b).max(*bits))
                                .or_insert(*bits);
                        }
                    }
                    Statement::Unknown { .. } => offsets.clear(),
                    Statement::Call { .. } => offsets.retain(|r, _| !abi.clobbers.contains(r)),
                    _ => {}
                }
            }
        }
    }
    let first_stack_argument = first_stack_argument_offset(abi);
    for (offset, bits) in slots {
        let parameter = read_slots.contains_key(&offset) && offset >= first_stack_argument;
        let category = if parameter { "stack-param" } else { "stack" };
        let id = format!("{}:{category}:{offset}", f.entry);
        let default_name = if parameter {
            format!("arg_stack_{}", (offset - first_stack_argument) / 8)
        } else {
            format!(
                "stack_{}{:x}",
                if offset < 0 { "minus_" } else { "plus_" },
                offset.unsigned_abs()
            )
        };
        variables.push(Variable {
            id: id.clone(),
            name: overrides
                .variable_names
                .get(&id)
                .cloned()
                .unwrap_or(default_name),
            ty: overrides
                .variable_types
                .get(&id)
                .cloned()
                .unwrap_or(format!("uint{}_t", bits.max(8))),
            storage: format!("entry_sp{offset:+}"),
            parameter,
        });
    }
    Ok(variables)
}
fn collect_loads(e: &Expr, offsets: &BTreeMap<String, i64>, slots: &mut BTreeMap<i64, u16>) {
    match e {
        Expr::Load { address, bits } => {
            if let Some(o) = stack_offset(address, offsets) {
                slots
                    .entry(o)
                    .and_modify(|b| *b = (*b).max(*bits))
                    .or_insert(*bits);
            }
            collect_loads(address, offsets, slots);
        }
        Expr::Binary { left, right, .. } | Expr::Compare { left, right, .. } => {
            collect_loads(left, offsets, slots);
            collect_loads(right, offsets, slots);
        }
        _ => {}
    }
}
pub fn stack_offset(e: &Expr, offsets: &BTreeMap<String, i64>) -> Option<i64> {
    match e {
        Expr::Var { name, bits: 64 } => offsets.get(name).copied(),
        Expr::Binary {
            op,
            left,
            right,
            bits: 64,
        } => {
            if op == "&" && right.eval(&BTreeMap::new()) == Some(u64::MAX) {
                return stack_offset(left, offsets);
            }
            let a = stack_offset(left, offsets)?;
            let b = right.eval(&BTreeMap::new())? as i64;
            match op.as_str() {
                "+" => a.checked_add(b),
                "-" => a.checked_sub(b),
                _ => None,
            }
        }
        _ => None,
    }
}

fn infer_float_parameter(
    reg: &str,
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
) -> String {
    for address in &f.members {
        for statement in &instructions[address].statements {
            if let Statement::Intrinsic {
                domain,
                element_bits,
                inputs,
                ..
            } = statement
            {
                if inputs.iter().any(|input| input == reg) {
                    return match (domain.as_str(), element_bits) {
                        ("float", 32) => "float".into(),
                        ("float", 64) => "double".into(),
                        ("simd", bits) => format!("vector_u{bits}"),
                        _ => "fp_unknown".into(),
                    };
                }
            }
        }
    }
    "fp_unknown".into()
}

fn infer_parameter(
    reg: &str,
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    df: &Dataflow,
) -> String {
    fn scan(e: &Expr, reg: &str, pointer: bool, width: &mut u16, is_pointer: &mut bool) {
        match e {
            Expr::Var { name, bits } if name == reg => {
                *width = (*width).max(*bits);
                *is_pointer |= pointer;
            }
            Expr::Binary { left, right, .. } | Expr::Compare { left, right, .. } => {
                scan(left, reg, pointer, width, is_pointer);
                scan(right, reg, pointer, width, is_pointer);
            }
            Expr::Load { address, .. } => scan(address, reg, true, width, is_pointer),
            _ => {}
        }
    }
    let mut width = 0;
    let mut pointer = false;
    for u in df.uses.iter().filter(|u| {
        u.register == reg && u.definitions.iter().any(|d| derives_from_input(d, reg, df))
    }) {
        if !f.members.contains(&u.address) {
            continue;
        }
        match &instructions[&u.address].statements[u.statement] {
            Statement::Assign { value, .. } => scan(value, reg, false, &mut width, &mut pointer),
            Statement::Store { address, value, .. } => {
                scan(address, reg, true, &mut width, &mut pointer);
                scan(value, reg, false, &mut width, &mut pointer);
            }
            Statement::Flags { left, right, .. } => {
                scan(left, reg, false, &mut width, &mut pointer);
                scan(right, reg, false, &mut width, &mut pointer);
            }
            _ => {}
        }
    }
    if pointer {
        "uint8_ptr".into()
    } else {
        format!(
            "uint{}_t",
            if [8, 16, 32, 64].contains(&width) {
                width
            } else {
                64
            }
        )
    }
}

fn stack_states(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    abi: &Abi,
    job: &mut crate::scheduler::Job,
) -> crate::Result<BTreeMap<Addr, BTreeMap<String, i64>>> {
    let mut outputs: BTreeMap<Addr, BTreeMap<String, i64>> = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    loop {
        job.tick()?;
        let mut changed = false;
        for b in &f.blocks {
            let preds = f
                .blocks
                .iter()
                .filter(|p| p.successors.contains(&b.address))
                .map(|p| p.address)
                .collect::<Vec<_>>();
            let mut offsets = if b.address == f.entry {
                BTreeMap::from([(abi.stack.clone(), 0)])
            } else {
                preds
                    .first()
                    .and_then(|p| outputs.get(p))
                    .cloned()
                    .unwrap_or_default()
            };
            for pred in preds {
                if let Some(values) = outputs.get(&pred) {
                    offsets.retain(|r, v| values.get(r) == Some(v));
                } else if b.address != f.entry {
                    offsets.clear();
                }
            }
            inputs.insert(b.address, offsets.clone());
            for a in &b.members {
                for s in &instructions[a].statements {
                    job.tick()?;
                    match s {
                        Statement::Assign { dst, value } => {
                            let offset = stack_offset(value, &offsets);
                            offsets.remove(dst);
                            if let Some(o) = offset {
                                offsets.insert(dst.clone(), o);
                            }
                        }
                        Statement::Call { .. } => offsets.retain(|r, _| !abi.clobbers.contains(r)),
                        Statement::Unknown { .. } => offsets.clear(),
                        _ => {}
                    }
                }
            }
            if outputs.get(&b.address) != Some(&offsets) {
                outputs.insert(b.address, offsets);
                changed = true;
            }
        }
        if !changed {
            return Ok(inputs);
        }
    }
}

/// Follow arbitrarily nested phi nodes; visited IDs break loop-carried cycles.
fn derives_from_input(id: &str, reg: &str, df: &Dataflow) -> bool {
    let input = format!("input:{reg}");
    let mut pending = vec![id];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = pending.pop() {
        if id == input {
            return true;
        }
        if !seen.insert(id) {
            continue;
        }
        if let Some(phi) = df.phis.iter().find(|p| p.id == id && p.register == reg) {
            pending.extend(phi.incoming.values().flatten().map(String::as_str));
            pending.extend(phi.entry_input.as_deref());
        }
    }
    false
}
fn expressions(s: &Statement) -> Vec<&Expr> {
    match s {
        Statement::Assign { value, .. } => vec![value],
        Statement::Store { address, value, .. } => vec![address, value],
        Statement::Flags { left, right, .. } => vec![left, right],
        Statement::Branch { condition, .. } => vec![condition],
        Statement::Call { target } | Statement::Jump { target } => vec![target],
        _ => vec![],
    }
}
mod report;
pub use report::report;
