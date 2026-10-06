//! N07: fixed-point reaching definitions, explicit SSA phi nodes, dominators and constants.
mod structure;
use crate::{core::*, ir::*, scheduler::Job, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueRange {
    pub minimum: u64,
    pub maximum: u64,
    pub bits: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryAccess {
    pub address: Addr,
    pub statement: usize,
    pub kind: String,
    pub location: String,
    pub bits: u16,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dataflow {
    #[serde(default)]
    pub immediate_dominators: BTreeMap<Addr, Option<Addr>>,
    #[serde(default)]
    pub dominance_frontiers: BTreeMap<Addr, BTreeSet<Addr>>,
    #[serde(default)]
    pub live_in: BTreeMap<Addr, BTreeSet<String>>,
    #[serde(default)]
    pub live_out: BTreeMap<Addr, BTreeSet<String>>,
    #[serde(default)]
    pub phi_uses: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub def_uses: BTreeMap<String, Vec<Use>>,
    #[serde(default)]
    pub constants_at_statement: BTreeMap<Addr, Vec<BTreeMap<String, u64>>>,
    pub dominators: BTreeMap<Addr, BTreeSet<Addr>>,
    pub phis: Vec<Phi>,
    pub uses: Vec<Use>,
    pub constants_before: BTreeMap<Addr, BTreeMap<String, u64>>,
    pub reaching_in: BTreeMap<Addr, BTreeMap<String, BTreeSet<String>>>,
    #[serde(default)]
    pub feasible_edges: BTreeMap<Addr, BTreeSet<Addr>>,
    #[serde(default)]
    pub unreachable_blocks: BTreeSet<Addr>,
    #[serde(default)]
    pub ranges_before: BTreeMap<Addr, Vec<BTreeMap<String, ValueRange>>>,
    #[serde(default)]
    pub memory_accesses: Vec<MemoryAccess>,
    #[serde(default)]
    pub memory_alias_sets: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub memory_ssa: BTreeMap<Addr, Vec<String>>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Phi {
    pub id: String,
    pub block: Addr,
    pub register: String,
    pub incoming: BTreeMap<Addr, Vec<String>>,
    #[serde(default)]
    pub entry_input: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Use {
    pub address: Addr,
    pub statement: usize,
    pub register: String,
    pub definitions: Vec<String>,
}
fn propagate_constants(
    blocks: &[Block],
    entry: Addr,
    instructions: &BTreeMap<Addr, Instruction>,
    clobbers: &[String],
    predecessors: &BTreeMap<Addr, Vec<Addr>>,
    result: &mut Dataflow,
    job: &mut Job,
) -> Result<()> {
    result.constants_before.clear();
    result.constants_at_statement.clear();
    let mut constants: BTreeMap<Addr, BTreeMap<String, u64>> = BTreeMap::new();
    loop {
        job.tick()?;
        let mut changed = false;
        for block in blocks {
            let preds = &predecessors[&block.address];
            let mut values = if block.address == entry {
                BTreeMap::new()
            } else {
                preds
                    .first()
                    .and_then(|pred| constants.get(pred))
                    .cloned()
                    .unwrap_or_default()
            };
            for predecessor in preds.iter().skip(1) {
                values.retain(|register, value| {
                    constants
                        .get(predecessor)
                        .and_then(|state| state.get(register))
                        == Some(value)
                });
            }
            if block.address != entry
                && (preds.is_empty() || preds.iter().any(|pred| !constants.contains_key(pred)))
            {
                values.clear();
            }
            for address in &block.members {
                result.constants_before.insert(*address, values.clone());
                let mut statement_values = vec![];
                for statement in &instructions[address].statements {
                    statement_values.push(values.clone());
                    match statement {
                        Statement::Assign { dst, value } => {
                            let value = value.eval(&values);
                            values.remove(dst);
                            if let Some(value) = value {
                                values.insert(dst.clone(), value);
                            }
                        }
                        Statement::Unknown { .. } => values.clear(),
                        Statement::Call { .. } => {
                            for register in clobbers {
                                values.remove(register);
                            }
                            values.remove("__flags");
                        }
                        Statement::Flags { op, left, right, bits } => {
                            for flag in ["__flags", "__flag_cf", "__flag_zf", "__flag_sf", "__flag_of", "__flag_pf"] {
                                values.remove(flag);
                            }
                            if let (Some(left), Some(right)) = (left.eval(&values), right.eval(&values)) {
                                if let Some(flags) = evaluate_flags(op, left, right, *bits) {
                                    values.extend(flags);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                result
                    .constants_at_statement
                    .insert(*address, statement_values);
            }
            if constants.get(&block.address) != Some(&values) {
                constants.insert(block.address, values);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}
fn refine_feasible_edges(
    blocks: &[Block],
    entry: Addr,
    instructions: &BTreeMap<Addr, Instruction>,
    constants_at_statement: &BTreeMap<Addr, Vec<BTreeMap<String, u64>>>,
) -> (BTreeMap<Addr, BTreeSet<Addr>>, BTreeSet<Addr>) {
    let mut edges = blocks
        .iter()
        .map(|block| {
            (
                block.address,
                block.successors.iter().copied().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for block in blocks {
        let Some(address) = block.members.last() else {
            continue;
        };
        let instruction = &instructions[address];
        let Flow::Branch(target) = instruction.flow else {
            continue;
        };
        let Some((index, Statement::Branch { condition, .. })) = instruction
            .statements
            .iter()
            .enumerate()
            .find(|(_, statement)| matches!(statement, Statement::Branch { .. }))
        else {
            continue;
        };
        let Some(values) = constants_at_statement
            .get(address)
            .and_then(|states| states.get(index))
        else {
            continue;
        };
        let Some(taken) = condition.eval(values) else {
            continue;
        };
        let kept = if taken != 0 {
            Some(target)
        } else {
            instruction
                .next()
                .filter(|next| block.successors.contains(next))
        };
        if let Some(kept) = kept {
            edges.insert(block.address, BTreeSet::from([kept]));
        }
    }
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(block) = pending.pop() {
        if reachable.insert(block) {
            pending.extend(edges.get(&block).into_iter().flatten().copied());
        }
    }
    let unreachable = blocks
        .iter()
        .map(|block| block.address)
        .filter(|block| !reachable.contains(block))
        .collect();
    (edges, unreachable)
}

pub fn analyze(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    clobbers: &[String],
    job: &mut Job,
) -> Result<Dataflow> {
    let mut result = Dataflow::default();
    let blocks = &f.blocks;
    let all = blocks.iter().map(|b| b.address).collect::<BTreeSet<_>>();
    if !all.contains(&f.entry) || all.len() != blocks.len() {
        return Err("CFG sin entrada válida o con bloques duplicados".into());
    }
    let mut reachable = BTreeSet::new();
    let mut pending = vec![f.entry];
    while let Some(a) = pending.pop() {
        job.tick()?;
        if !reachable.insert(a) {
            continue;
        }
        let b = blocks
            .iter()
            .find(|b| b.address == a)
            .ok_or("Sucesor CFG inexistente")?;
        if b.members.is_empty() || b.members.iter().any(|a| !instructions.contains_key(a)) {
            return Err("Bloque CFG vacío o instrucción inexistente".into());
        }
        pending.extend(b.successors.iter().copied());
    }
    if reachable != all {
        return Err("CFG contiene bloques inalcanzables".into());
    }
    let mut predecessors: BTreeMap<Addr, Vec<Addr>> = all.iter().map(|a| (*a, vec![])).collect();
    for b in blocks {
        for to in &b.successors {
            predecessors.entry(*to).or_default().push(b.address);
        }
    }
    for b in blocks {
        result.dominators.insert(
            b.address,
            if b.address == f.entry {
                BTreeSet::from([b.address])
            } else {
                all.clone()
            },
        );
    }
    loop {
        job.tick()?;
        let mut changed = false;
        for b in blocks.iter().filter(|b| b.address != f.entry) {
            let preds = &predecessors[&b.address];
            let mut next = preds
                .first()
                .map_or(BTreeSet::new(), |a| result.dominators[a].clone());
            for pred in preds.iter().skip(1) {
                next = next
                    .intersection(&result.dominators[pred])
                    .copied()
                    .collect();
            }
            next.insert(b.address);
            if next != result.dominators[&b.address] {
                result.dominators.insert(b.address, next);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    structure::enrich(f, instructions, clobbers, &mut result, job)?;
    let mut registers = BTreeSet::new();
    for a in &f.members {
        for s in &instructions[a].statements {
            registers.extend(s.reads());
            registers.extend(s.writes());
        }
    }
    registers.extend(clobbers.iter().cloned());
    registers.extend(["__memory".into(), "__flags".into()]);
    type Definitions = BTreeMap<String, BTreeSet<String>>;
    let initial: Definitions = registers
        .iter()
        .map(|r| (r.clone(), BTreeSet::from([format!("input:{r}")])))
        .collect();
    let mut outputs: BTreeMap<Addr, Definitions> = BTreeMap::new();
    loop {
        job.tick()?;
        let mut changed = false;
        for b in blocks {
            let mut defs: Definitions = BTreeMap::new();
            if b.address == f.entry {
                defs = initial.clone();
            }
            for pred in &predecessors[&b.address] {
                if let Some(d) = outputs.get(pred) {
                    for (r, ids) in d {
                        defs.entry(r.clone()).or_default().extend(ids.clone());
                    }
                }
            }
            result.reaching_in.insert(b.address, defs.clone());
            for a in &b.members {
                for (i, s) in instructions[a].statements.iter().enumerate() {
                    for r in s.writes() {
                        defs.insert(r.clone(), BTreeSet::from([format!("{a}:{i}:{r}")]));
                    }
                    let killed: Vec<String> = match s {
                        Statement::Unknown { .. } => registers.iter().cloned().collect(),
                        Statement::Call { .. } => clobbers
                            .iter()
                            .cloned()
                            .chain(["__memory".into(), "__flags".into()])
                            .collect(),
                        _ => vec![],
                    };
                    for r in killed {
                        defs.insert(r.clone(), BTreeSet::from([format!("unknown:{a}:{i}:{r}")]));
                    }
                }
            }
            if outputs.get(&b.address) != Some(&defs) {
                outputs.insert(b.address, defs);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Place merge versions, then propagate SSA versions (not raw reaching sets).
    let phi_keys = result
        .reaching_in
        .iter()
        .flat_map(|(b, regs)| {
            regs.iter()
                .filter(|(r, ids)| {
                    ids.len() > 1
                        && (predecessors[b].len() > 1 || *b == f.entry)
                        && result.live_in[b].contains(*r)
                })
                .map(move |(r, _)| (*b, r.clone()))
        })
        .collect::<BTreeSet<_>>();
    let transfer = |defs: &mut BTreeMap<String, String>, a: Addr, i: usize, s: &Statement| {
        for r in s.writes() {
            defs.insert(r.clone(), format!("{a}:{i}:{r}"));
        }
        let killed: Vec<String> = match s {
            Statement::Unknown { .. } => registers.iter().cloned().collect(),
            Statement::Call { .. } => clobbers
                .iter()
                .cloned()
                .chain(["__memory".into(), "__flags".into()])
                .collect(),
            _ => vec![],
        };
        for r in killed {
            defs.insert(r.clone(), format!("unknown:{a}:{i}:{r}"));
        }
    };
    let mut ssa_out: BTreeMap<Addr, BTreeMap<String, String>> = BTreeMap::new();
    let incoming = |b: Addr, outputs: &BTreeMap<Addr, BTreeMap<String, String>>| {
        registers
            .iter()
            .map(|r| {
                let version = if phi_keys.contains(&(b, r.clone())) {
                    format!("phi:{b}:{r}")
                } else if b == f.entry {
                    format!("input:{r}")
                } else {
                    predecessors[&b]
                        .iter()
                        .find_map(|p| outputs.get(p).and_then(|d| d.get(r)))
                        .cloned()
                        .unwrap_or(format!("input:{r}"))
                };
                (r.clone(), version)
            })
            .collect::<BTreeMap<_, _>>()
    };
    loop {
        job.tick()?;
        let mut changed = false;
        for b in blocks {
            let mut defs = incoming(b.address, &ssa_out);
            for a in &b.members {
                for (i, s) in instructions[a].statements.iter().enumerate() {
                    transfer(&mut defs, *a, i, s);
                }
            }
            if ssa_out.get(&b.address) != Some(&defs) {
                ssa_out.insert(b.address, defs);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (b, r) in &phi_keys {
        let edges = predecessors[b]
            .iter()
            .map(|pred| (*pred, vec![ssa_out[pred][r].clone()]))
            .collect();
        result.phis.push(Phi {
            id: format!("phi:{b}:{r}"),
            block: *b,
            register: r.clone(),
            incoming: edges,
            entry_input: (*b == f.entry).then(|| format!("input:{r}")),
        });
    }
    for b in blocks {
        let mut defs = incoming(b.address, &ssa_out);
        for a in &b.members {
            for (i, s) in instructions[a].statements.iter().enumerate() {
                for r in s.reads() {
                    result.uses.push(Use {
                        address: *a,
                        statement: i,
                        definitions: vec![defs.get(&r).cloned().unwrap_or(format!("input:{r}"))],
                        register: r,
                    });
                }
                transfer(&mut defs, *a, i, s);
            }
        }
    }
    // Sparse conditional constant propagation: repeatedly prune proved-impossible
    // edges and recompute until the executable-edge set is stable.
    let static_edges = blocks
        .iter()
        .map(|block| {
            (
                block.address,
                block.successors.iter().copied().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut feasible_edges = static_edges.clone();
    let mut unreachable_blocks = BTreeSet::new();
    for _ in 0..=blocks.len() {
        let mut feasible_predecessors: BTreeMap<Addr, Vec<Addr>> =
            all.iter().map(|address| (*address, vec![])).collect();
        for (from, targets) in &feasible_edges {
            for target in targets {
                feasible_predecessors
                    .entry(*target)
                    .or_default()
                    .push(*from);
            }
        }
        for predecessors in feasible_predecessors.values_mut() {
            predecessors.sort();
            predecessors.dedup();
        }
        propagate_constants(
            blocks,
            f.entry,
            instructions,
            clobbers,
            &feasible_predecessors,
            &mut result,
            job,
        )?;
        let (mut refined, unreachable) = refine_feasible_edges(
            blocks,
            f.entry,
            instructions,
            &result.constants_at_statement,
        );
        for block in &unreachable {
            refined.insert(*block, BTreeSet::new());
        }
        unreachable_blocks = unreachable;
        if refined == feasible_edges {
            break;
        }
        feasible_edges = refined;
    }
    result.feasible_edges = feasible_edges;
    result.unreachable_blocks = unreachable_blocks;
    for phi in &result.phis {
        for definition in phi
            .incoming
            .values()
            .flatten()
            .chain(phi.entry_input.iter())
        {
            let users = result.phi_uses.entry(definition.clone()).or_default();
            if !users.contains(&phi.id) {
                users.push(phi.id.clone());
            }
        }
    }
    for usage in &result.uses {
        for definition in &usage.definitions {
            result
                .def_uses
                .entry(definition.clone())
                .or_default()
                .push(usage.clone());
        }
    }
    collect_extended_facts(f, instructions, &mut result);
    Ok(result)
}
fn stack_offset(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Var { name, .. } if name == "rsp" || name == "sp" => Some(0),
        Expr::Binary {
            op, left, right, ..
        } if op == "+" || op == "-" => {
            let base = stack_offset(left)?;
            let delta = right.eval(&BTreeMap::new())? as i64;
            base.checked_add(if op == "+" { delta } else { -delta })
        }
        _ => None,
    }
}
fn memory_location(expr: &Expr) -> String {
    if let Some(offset) = stack_offset(expr) {
        return format!("stack:{offset}");
    }
    if let Some(address) = expr.eval(&BTreeMap::new()) {
        return format!("global:{address:016x}");
    }
    "unknown".into()
}
fn collect_loads(expr: &Expr, address: Addr, statement: usize, accesses: &mut Vec<MemoryAccess>) {
    match expr {
        Expr::Load {
            address: location,
            bits,
        } => {
            accesses.push(MemoryAccess {
                address,
                statement,
                kind: "read".into(),
                location: memory_location(location),
                bits: *bits,
            });
            collect_loads(location, address, statement, accesses);
        }
        Expr::Binary { left, right, .. } | Expr::Compare { left, right, .. } => {
            collect_loads(left, address, statement, accesses);
            collect_loads(right, address, statement, accesses);
        }
        _ => {}
    }
}
fn collect_extended_facts(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    result: &mut Dataflow,
) {
    result.ranges_before.clear();
    result.memory_accesses.clear();
    result.memory_alias_sets.clear();
    result.memory_ssa.clear();
    for usage in &result.uses {
        if usage.register == "__memory" {
            result
                .memory_ssa
                .entry(usage.address)
                .or_default()
                .extend(usage.definitions.clone());
        }
    }
    for phi in &result.phis {
        if phi.register == "__memory" {
            result
                .memory_ssa
                .entry(phi.block)
                .or_default()
                .push(phi.id.clone());
        }
    }
    for versions in result.memory_ssa.values_mut() {
        versions.sort();
        versions.dedup();
    }
    for address in &f.members {
        if f.blocks.iter().any(|block| {
            block.members.contains(address) && result.unreachable_blocks.contains(&block.address)
        }) {
            continue;
        }
        let mut ranges = vec![];
        for values in result
            .constants_at_statement
            .get(address)
            .cloned()
            .unwrap_or_default()
        {
            ranges.push(
                values
                    .into_iter()
                    .map(|(register, value)| {
                        (
                            register,
                            ValueRange {
                                minimum: value,
                                maximum: value,
                                bits: 64,
                            },
                        )
                    })
                    .collect(),
            );
        }
        result.ranges_before.insert(*address, ranges);
        for (statement, operation) in instructions[address].statements.iter().enumerate() {
            match operation {
                Statement::Store {
                    address: location,
                    bits,
                    value,
                } => {
                    result.memory_accesses.push(MemoryAccess {
                        address: *address,
                        statement,
                        kind: "write".into(),
                        location: memory_location(location),
                        bits: *bits,
                    });
                    collect_loads(location, *address, statement, &mut result.memory_accesses);
                    collect_loads(value, *address, statement, &mut result.memory_accesses);
                }
                Statement::Assign { value, .. } | Statement::Flags { left: value, .. } => {
                    collect_loads(value, *address, statement, &mut result.memory_accesses)
                }
                _ => {}
            }
        }
    }
    for access in &result.memory_accesses {
        let key = if access.location == "unknown" {
            "unknown-may-alias".into()
        } else {
            access.location.clone()
        };
        result
            .memory_alias_sets
            .entry(key)
            .or_default()
            .push(format!("{}:{}", access.address, access.statement));
    }
}
