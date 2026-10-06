//! Straight-line symbolic elimination. Only exact private stack slots may be removed.
use crate::{
    analysis::abi::{stack_offset, Abi},
    core::*,
    ir::*,
};
use std::collections::BTreeMap;
fn substitute(
    e: &Expr,
    regs: &BTreeMap<String, Expr>,
    stack: &BTreeMap<(i64, u16), Expr>,
    sp: &str,
    budget: &mut usize,
) -> Option<Expr> {
    *budget = budget.checked_sub(1)?;
    Some(match e {
        Expr::Const { .. } => e.clone(),
        Expr::Var { name, bits } => {
            let v = regs
                .get(name)
                .cloned()
                .unwrap_or_else(|| var(&format!("input_{name}"), 64));
            if *bits < 64 {
                binary("&", v, constant(mask(*bits), 64), 64).simplify(&BTreeMap::new())
            } else {
                v
            }
        }
        Expr::Binary {
            op,
            left,
            right,
            bits,
        } => binary(
            op,
            substitute(left, regs, stack, sp, budget)?,
            substitute(right, regs, stack, sp, budget)?,
            *bits,
        )
        .simplify(&BTreeMap::new()),
        Expr::Load { address, bits } => {
            let a = substitute(address, regs, stack, sp, budget)?;
            let offset = stack_offset(&a, &BTreeMap::from([(format!("input_{sp}"), 0)]))?;
            stack.get(&(offset, *bits))?.clone()
        }
        _ => return None,
    })
}
pub fn return_expression(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    abi: &Abi,
) -> Option<Expr> {
    if f.blocks.len() != 1 || f.members.len() > 256 {
        return None;
    }
    let mut regs = BTreeMap::new();
    let mut stack = BTreeMap::new();
    let mut budget = 20000;
    let mut result = None;
    for a in &f.blocks[0].members {
        if !instructions[a].semantic_complete {
            return None;
        }
        for s in &instructions[a].statements {
            match s {
                Statement::Assign { dst, value } => {
                    let v = substitute(value, &regs, &stack, &abi.stack, &mut budget)?;
                    regs.insert(dst.clone(), v);
                }
                Statement::Store {
                    address,
                    value,
                    bits,
                } => {
                    let address = substitute(address, &regs, &stack, &abi.stack, &mut budget)?;
                    let offset = stack_offset(
                        &address,
                        &BTreeMap::from([(format!("input_{}", abi.stack), 0)]),
                    )?;
                    // Above entry SP can be caller-owned. Reject rather than erase an observable write.
                    if offset >= 0 || offset.checked_add(i64::from(*bits / 8))? > 0 {
                        return None;
                    }
                    let v = substitute(value, &regs, &stack, &abi.stack, &mut budget)?;
                    stack.retain(|(o, b), _| {
                        *o + i64::from(*b / 8) <= offset || *o >= offset + i64::from(*bits / 8)
                    });
                    stack.insert((offset, *bits), v);
                }
                Statement::Return => {
                    result = Some(
                        regs.get(&abi.result)
                            .cloned()
                            .unwrap_or_else(|| var(&format!("input_{}", abi.result), 64)),
                    );
                }
                Statement::Flags { .. } | Statement::Nop => {}
                _ => return None,
            }
        }
    }
    if stack_offset(
        regs.get(&abi.stack)
            .unwrap_or(&var(&format!("input_{}", abi.stack), 64)),
        &BTreeMap::from([(format!("input_{}", abi.stack), 0)]),
    ) != Some(0)
    {
        return None;
    }
    // Do not hide changes to ABI-preserved registers.
    for (r, v) in &regs {
        if r != &abi.stack && !abi.clobbers.contains(r) && v != &var(&format!("input_{r}"), 64) {
            return None;
        }
    }
    let result = result?;
    if result
        .reads()
        .iter()
        .any(|r| !abi.args.iter().any(|arg| r == &format!("input_{arg}")))
    {
        return None;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symbolic_return_matches_fixture_integer_semantics() {
        let bytes = include_bytes!("../../../fixtures/sample-macho");
        let stored = crate::protocol::analyze(
            bytes,
            None,
            None,
            &mut crate::scheduler::Job::new(Default::default()),
        )
        .unwrap();
        let f = stored
            .program
            .functions
            .values()
            .find(|f| f.name == "_calculate_score")
            .unwrap();
        let expr = return_expression(
            f,
            &stored.program.instructions,
            &crate::analysis::abi::select(&stored.program),
        )
        .unwrap();
        let mut seed = 0xfedcba9876543210u64;
        for n in 0..1000 {
            let value = match n {
                0 => 0,
                1 => u64::MAX,
                2 => 0x80000000,
                _ => {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    seed
                }
            };
            assert_eq!(
                expr.eval(&BTreeMap::from([("input_x0".into(), value)])),
                Some(u64::from((value as u32).wrapping_mul(7).wrapping_add(3)))
            );
        }
    }
}
