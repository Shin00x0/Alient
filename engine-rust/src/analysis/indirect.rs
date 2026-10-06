//! N10: bounded pointer resolution and call summaries. Unresolved branches remain explicit.
use crate::{core::*, ir::*, scheduler::Job, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndirectReport {
    pub resolved: Vec<Reference>,
    pub unresolved: Vec<Addr>,
    pub return_constants: BTreeMap<Addr, u64>,
    pub tables: BTreeMap<Addr, Vec<Addr>>,
}
pub fn evaluate(
    e: &Expr,
    values: &BTreeMap<String, u64>,
    p: &Program,
    source: &[u8],
) -> Option<u64> {
    if let Some(v) = e.eval(values) {
        return Some(v);
    }
    if let Expr::Load { address, bits } = e {
        if ![8, 16, 32, 64].contains(bits) {
            return None;
        }
        let a = evaluate(address, values, p, source)?;
        if p.region(Addr(a))?.permissions.contains('w') {
            return None;
        }
        if p.relocations.iter().any(|r| {
            !r.applied
                && (r.address.0 as u128) < a as u128 + u128::from(*bits / 8)
                && (a as u128) < r.address.0 as u128 + u128::from(r.width.max(8) / 8)
        }) {
            return None;
        }
        let b = p.read(source, Addr(a), (*bits / 8) as usize).ok()?;
        let mut word = [0u8; 8];
        word[..b.len()].copy_from_slice(&b);
        return Some(u64::from_le_bytes(word));
    }
    if let Expr::Binary {
        op,
        left,
        right,
        bits,
    } = e
    {
        let a = evaluate(left, values, p, source)?;
        let b = evaluate(right, values, p, source)?;
        return binary(op, constant(a, *bits), constant(b, *bits), *bits).eval(&BTreeMap::new());
    }
    None
}
pub fn resolve(
    p: &Program,
    source: &[u8],
    return_register: &str,
    job: &mut Job,
) -> Result<IndirectReport> {
    let mut summaries = BTreeMap::new();
    let mut final_report = IndirectReport::default();
    for _ in 0..p.functions.len().clamp(1, 16) {
        let report = resolve_pass(p, source, return_register, &summaries, job)?;
        let stable = report.return_constants == summaries;
        summaries = report.return_constants.clone();
        final_report = report;
        if stable {
            break;
        }
    }
    Ok(final_report)
}
fn resolve_pass(
    p: &Program,
    source: &[u8],
    return_register: &str,
    summaries: &BTreeMap<Addr, u64>,
    job: &mut Job,
) -> Result<IndirectReport> {
    let mut report = IndirectReport::default();
    for f in p.functions.values() {
        job.tick()?;
        let mut outputs: BTreeMap<Addr, BTreeMap<String, u64>> = BTreeMap::new();
        loop {
            job.tick()?;
            let mut local = IndirectReport::default();
            let mut dedup = BTreeSet::new();
            let mut returns = vec![];
            let mut changed = false;
            for b in &f.blocks {
                let preds = f
                    .blocks
                    .iter()
                    .filter(|pred| pred.successors.contains(&b.address))
                    .map(|pred| pred.address)
                    .collect::<Vec<_>>();
                let mut values = if b.address == f.entry {
                    BTreeMap::new()
                } else {
                    preds
                        .first()
                        .and_then(|a| outputs.get(a))
                        .cloned()
                        .unwrap_or_default()
                };
                for pred in &preds {
                    values.retain(|r, v| outputs.get(pred).and_then(|d| d.get(r)) == Some(v));
                }
                for a in &b.members {
                    let ins = &p.instructions[a];
                    if let Flow::Switch { targets, .. } = &ins.flow {
                        local.tables.insert(*a, targets.clone());
                    }
                    for s in &ins.statements {
                        job.tick()?;
                        match s {
                            Statement::Assign { dst, value } => {
                                let v = evaluate(value, &values, p, source);
                                values.remove(dst);
                                if let Some(v) = v {
                                    values.insert(dst.clone(), v);
                                    if p.region(Addr(v)).is_some()
                                        && dedup.insert((*a, Addr(v), "DATA"))
                                    {
                                        local.resolved.push(Reference {
                                            from: *a,
                                            to: Addr(v),
                                            kind: "DATA".into(),
                                            confidence: "inferred".into(),
                                        });
                                    }
                                }
                            }
                            Statement::Call { target } | Statement::Jump { target } => {
                                if !matches!(target, Expr::Const { .. })
                                    && !matches!(ins.flow, Flow::Switch { .. })
                                {
                                    if let Some(to) = evaluate(target, &values, p, source)
                                        .map(Addr)
                                        .filter(|a| p.executable(*a))
                                    {
                                        let kind = if matches!(s, Statement::Call { .. }) {
                                            "INDIRECT_CALL"
                                        } else {
                                            "INDIRECT_JUMP"
                                        };
                                        if dedup.insert((*a, to, kind)) {
                                            local.resolved.push(Reference {
                                                from: *a,
                                                to,
                                                kind: kind.into(),
                                                confidence: "inferred".into(),
                                            });
                                        }
                                    } else {
                                        local.unresolved.push(*a);
                                    }
                                }
                                if matches!(s, Statement::Call { .. }) {
                                    let result = evaluate(target, &values, p, source)
                                        .and_then(|to| summaries.get(&Addr(to)))
                                        .copied();
                                    values.clear();
                                    if let Some(v) = result {
                                        values.insert(return_register.into(), v);
                                    }
                                }
                            }
                            Statement::Return => returns.push(values.get(return_register).copied()),
                            Statement::Unknown { .. } => values.clear(),
                            Statement::Store { .. } => {
                                values.clear();
                            }
                            _ => {}
                        }
                    }
                }
                if outputs.get(&b.address) != Some(&values) {
                    outputs.insert(b.address, values);
                    changed = true;
                }
            }
            if let Some(Some(first)) = returns.first() {
                if returns.iter().all(|v| v == &Some(*first))
                    && f.members
                        .iter()
                        .all(|a| p.instructions[a].semantic_complete)
                    && f.blocks.iter().all(|b| {
                        !b.successors.is_empty()
                            || matches!(
                                p.instructions[b.members.last().unwrap()].flow,
                                Flow::Return
                            )
                    })
                {
                    local.return_constants.insert(f.entry, *first);
                }
            }
            if !changed {
                report.resolved.extend(local.resolved);
                report.unresolved.extend(local.unresolved);
                report.tables.extend(local.tables);
                report.return_constants.extend(local.return_constants);
                break;
            }
        }
    }
    Ok(report)
}
/// Explicit bounds are required. Never scan an unbounded pointer table until a plausible value appears.
pub fn absolute_table(p: &Program, source: &[u8], base: Addr, count: usize) -> Result<Vec<Addr>> {
    if count == 0 || count > 256 {
        return Err("Tabla de salto requiere 1..256 entradas".into());
    }
    let bytes = p.read(source, base, count * 8)?;
    let mut entries = vec![];
    for b in bytes.as_chunks::<8>().0 {
        let a = Addr(u64::from_le_bytes(*b));
        if !p.executable(a) {
            return Err("Tabla contiene destino no ejecutable".into());
        }
        entries.push(a);
    }
    Ok(entries)
}
