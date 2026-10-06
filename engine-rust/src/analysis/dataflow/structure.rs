use super::*;
/// Backwards liveness and dominator structure on the validated reachable CFG.
pub(super) fn enrich(
    f: &Function,
    instructions: &BTreeMap<Addr, Instruction>,
    clobbers: &[String],
    result: &mut Dataflow,
    job: &mut Job,
) -> Result<()> {
    let all = f
        .members
        .iter()
        .flat_map(|a| {
            instructions[a]
                .statements
                .iter()
                .flat_map(|s| s.reads().into_iter().chain(s.writes()))
        })
        .chain(clobbers.iter().cloned())
        .chain(["__memory".into(), "__flags".into()])
        .collect::<BTreeSet<_>>();
    let mut used = BTreeMap::new();
    let mut defined = BTreeMap::new();
    for b in &f.blocks {
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        for a in &b.members {
            job.tick()?;
            for s in &instructions[a].statements {
                reads.extend(s.reads().difference(&writes).cloned());
                // ABI-independent conservative inputs: implicit arguments/return registers
                // and unknown instructions must not lose live incoming versions.
                if matches!(
                    s,
                    Statement::Call { .. } | Statement::Return | Statement::Unknown { .. }
                ) {
                    reads.extend(all.difference(&writes).cloned());
                }
                writes.extend(s.writes());
                if matches!(s, Statement::Call { .. }) {
                    writes.extend(clobbers.iter().cloned());
                    writes.extend(["__memory".into(), "__flags".into()]);
                }
                if matches!(s, Statement::Unknown { .. }) {
                    writes.extend(all.iter().cloned());
                }
            }
        }
        used.insert(b.address, reads);
        defined.insert(b.address, writes);
        result.live_in.insert(b.address, BTreeSet::new());
        result.live_out.insert(b.address, BTreeSet::new());
    }
    loop {
        let mut changed = false;
        for b in f.blocks.iter().rev() {
            job.tick()?;
            let out = b
                .successors
                .iter()
                .flat_map(|s| result.live_in[s].iter().cloned())
                .collect::<BTreeSet<_>>();
            let input = used[&b.address]
                .union(&out.difference(&defined[&b.address]).cloned().collect())
                .cloned()
                .collect();
            changed |= result.live_in[&b.address] != input || result.live_out[&b.address] != out;
            result.live_in.insert(b.address, input);
            result.live_out.insert(b.address, out);
        }
        if !changed {
            break;
        }
    }
    for b in &f.blocks {
        let immediate = result.dominators[&b.address]
            .iter()
            .filter(|d| **d != b.address)
            .max_by_key(|d| result.dominators[d].len())
            .copied();
        result.immediate_dominators.insert(b.address, immediate);
        let mut frontier = BTreeSet::new();
        for p in &f.blocks {
            job.tick()?;
            if result.dominators[&p.address].contains(&b.address) {
                for to in &p.successors {
                    if *to == b.address || !result.dominators[to].contains(&b.address) {
                        frontier.insert(*to);
                    }
                }
            }
        }
        result.dominance_frontiers.insert(b.address, frontier);
    }
    Ok(())
}
