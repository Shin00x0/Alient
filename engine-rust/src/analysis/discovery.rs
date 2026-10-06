//! N05: recursive traversal from symbols, entry points and calls; no linear padding sweep.
mod recovery;
use crate::{
    architectures::Decoder,
    core::*,
    ir::Statement,
    scheduler::{Job, WorkQueue},
    Result,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub fn strings(p: &mut Program, bytes: &[u8], job: &mut Job) -> Result<()> {
    for r in &p.regions {
        if r.executable || r.file_size == 0 {
            continue;
        }
        let start = r.file_offset as usize;
        let end = start + r.file_size as usize;
        let mut at = start;
        while at < end {
            job.tick()?;
            let from = at;
            while at < end && ((32..=126).contains(&bytes[at]) || [9, 10, 13].contains(&bytes[at]))
            {
                at += 1;
            }
            if at - from >= 4 && at < end && bytes[at] == 0 {
                let address = Addr(r.range.start.0 + (from - start) as u64);
                p.data.insert(
                    address,
                    Data {
                        id: String::new(),
                        revision: 0,
                        space: r.space.clone(),
                        range: Range {
                            start: address,
                            size: (at - from + 1) as u64,
                        },
                        ty: "ascii-z".into(),
                        value: String::from_utf8_lossy(&bytes[from..at.min(from + 4096)])
                            .into_owned(),
                        provenance: "string-scan".into(),
                    },
                );
                if p.data.len() >= 20000 {
                    return Ok(());
                }
            }
            at += 1;
        }
    }
    for (a, d) in p.overrides.data.clone() {
        p.data.retain(|_, old| {
            old.range.start.0 as u128 + old.range.size as u128 <= d.range.start.0 as u128
                || d.range.start.0 as u128 + d.range.size as u128 <= old.range.start.0 as u128
        });
        p.data.insert(a, d);
    }
    Ok(())
}
pub fn discover(p: &mut Program, source: &[u8], job: &mut Job) -> Result<()> {
    let decoder = Decoder::new(&p.architecture)?;
    let mut names: BTreeMap<Addr, String> = p
        .symbols
        .iter()
        .filter(|s| s.function && !s.external)
        .filter_map(|s| s.address.map(|a| (a, s.name.clone())))
        .filter(|(a, _)| p.executable(*a))
        .collect();
    if let Some(entry) = p.entry {
        if p.executable(entry) {
            names.entry(entry).or_insert("entry".into());
        }
    }
    for a in &p.overrides.functions {
        names.entry(*a).or_insert(format!("sub_{a}"));
    }
    for a in &p.overrides.excluded_functions {
        names.remove(a);
    }
    if names.is_empty() {
        if let Some(r) = p.regions.iter().find(|r| r.executable) {
            names.insert(r.range.start, format!("region_{}", r.range.start));
            p.warnings.push("Sin símbolos/entrada: candidato de función en el inicio de la primera región ejecutable".into());
        }
    }
    let mut origins = names
        .keys()
        .map(|a| {
            (
                *a,
                if p.overrides.functions.contains(a) {
                    "user"
                } else if p
                    .symbols
                    .iter()
                    .any(|s| s.function && s.address == Some(*a))
                {
                    "symbol"
                } else if p.entry == Some(*a) {
                    "entry"
                } else {
                    "region-fallback"
                }
                .to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let recovered = recovery::roots(p, source, &names.keys().copied().collect(), job)?;
    for a in recovered {
        names.insert(a, format!("sub_{a}"));
        origins.insert(a, "frame-prologue-inferred".into());
    }
    let limits = p
        .symbols
        .iter()
        .filter(|s| s.function && s.size > 0)
        .filter_map(|s| {
            let a = s.address?;
            let end = a.0.checked_add(s.size)?;
            let r = p.region(a)?;
            (end as u128 <= r.range.start.0 as u128 + r.range.size as u128)
                .then_some((a, Addr(end)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut queue = WorkQueue::default();
    for a in names.keys() {
        queue.push(*a, 0);
    }
    while let Some(entry) = queue.pop() {
        job.tick()?;
        if p.functions.len() >= job.budget.max_functions {
            return Err("Límite de funciones".into());
        }
        if !p.executable(entry) || p.overrides.excluded_functions.contains(&entry) {
            continue;
        }
        let limit = limits.get(&entry).copied();
        let mut pending = VecDeque::from([entry]);
        let mut members = BTreeSet::new();
        let mut warnings = vec![];
        while let Some(a) = pending.pop_front() {
            job.tick()?;
            if members.contains(&a)
                || (!p.executable(a))
                || (p.architecture.starts_with("AARCH64") && a.0 % 4 != 0)
                || limit.is_some_and(|end| a < entry || a >= end)
                || (a != entry && names.contains_key(&a))
            {
                continue;
            }
            if let Some((_, previous)) = p.instructions.range(..a).next_back() {
                if previous.next().is_some_and(|end| end > a) {
                    warnings.push(format!("Destino {a} cae dentro de otra instrucción"));
                    continue;
                }
            }
            let ins = if let Some(ins) = p.instructions.get(&a) {
                ins.clone()
            } else {
                if p.instructions.len() >= job.budget.max_instructions {
                    return Err("Límite de instrucciones".into());
                }
                let bytes = match p.bytes_at(source, a, 16) {
                    Ok(b) => b,
                    Err(e) => {
                        warnings.push(format!("{a}: {e}"));
                        continue;
                    }
                };
                let mut ins = match decoder.decode(bytes, a) {
                    Ok(i) => i,
                    Err(e) => {
                        warnings.push(format!("{a}: {e}"));
                        if p.architecture.starts_with("AARCH64") && bytes.len() >= 4 {
                            Instruction {
                                id: String::new(),
                                revision: 0,
                                space: "ram".into(),
                                address: a,
                                bytes: bytes[..4].to_vec(),
                                text: format!(
                                    ".inst 0x{:08x}",
                                    u32::from_le_bytes(bytes[..4].try_into().unwrap())
                                ),
                                mnemonic: ".inst".into(),
                                operands: vec![],
                                statements: vec![Statement::Unknown { description: e }],
                                flow: Flow::Stop,
                                semantic_complete: false,
                            }
                        } else {
                            continue;
                        }
                    }
                };
                if limit.is_some_and(|end| a.0 as u128 + ins.bytes.len() as u128 > end.0 as u128) {
                    warnings.push(format!(
                        "Instrucción {a} cruza el tamaño declarado del símbolo"
                    ));
                    continue;
                }
                if let Some(table) = p.overrides.jump_tables.get(&a) {
                    let targets =
                        super::indirect::absolute_table(p, source, table.base, table.count)?;
                    ins.flow = Flow::Switch {
                        targets,
                        index: table.index.clone(),
                    };
                }
                if let Some((next, _)) = p
                    .instructions
                    .range((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded))
                    .next()
                {
                    if ins.next().is_some_and(|end| end > *next) {
                        warnings.push(format!("Decodificación superpuesta en {a}"));
                        continue;
                    }
                }
                if p.data.values().any(|d| {
                    (d.range.start.0 as u128) < a.0 as u128 + ins.bytes.len() as u128
                        && (a.0 as u128) < d.range.start.0 as u128 + d.range.size as u128
                }) {
                    continue;
                }
                p.instructions.insert(a, ins.clone());
                ins
            };
            members.insert(a);
            match ins.flow {
                Flow::Next => {
                    if let Some(next) = ins.next() {
                        pending.push_back(next)
                    }
                }
                Flow::Call(target) => {
                    if let Some(to) = target {
                        p.references.push(Reference {
                            from: a,
                            to,
                            kind: "UNCONDITIONAL_CALL".into(),
                            confidence: "confirmed".into(),
                        });
                        if p.executable(to) && !p.overrides.excluded_functions.contains(&to) {
                            names.entry(to).or_insert(format!("sub_{to}"));
                            origins.entry(to).or_insert("call-target".into());
                            queue.push(to, 1);
                        }
                    }
                    if let Some(next) = ins.next() {
                        pending.push_back(next);
                    }
                }
                Flow::Jump(to) => {
                    p.references.push(Reference {
                        from: a,
                        to,
                        kind: "UNCONDITIONAL_JUMP".into(),
                        confidence: "confirmed".into(),
                    });
                    pending.push_back(to)
                }
                Flow::Branch(to) => {
                    p.references.push(Reference {
                        from: a,
                        to,
                        kind: "CONDITIONAL_JUMP".into(),
                        confidence: "confirmed".into(),
                    });
                    pending.push_back(to);
                    if let Some(next) = ins.next() {
                        pending.push_back(next);
                    }
                }
                Flow::Switch { ref targets, .. } => {
                    for to in targets {
                        p.references.push(Reference {
                            from: a,
                            to: *to,
                            kind: "COMPUTED_JUMP".into(),
                            confidence: "user-bounded".into(),
                        });
                        pending.push_back(*to);
                    }
                }
                Flow::Indirect => warnings.push(format!("Salto indirecto sin resolver en {a}")),
                _ => {}
            }
        }
        if !members.contains(&entry) {
            p.warnings.push(format!(
                "Entrada {entry} sin instrucciones válidas: {}",
                warnings.join("; ")
            ));
            continue;
        }
        let members = members.into_iter().collect::<Vec<_>>();
        let blocks = blocks(&members, &p.instructions, entry);
        p.functions.insert(
            entry,
            Function {
                discovery: FunctionDiscovery {
                    source: origins.get(&entry).cloned().unwrap_or("call-target".into()),
                    declared_end: limit,
                    ..Default::default()
                },
                id: String::new(),
                revision: 0,
                entry,
                name: p
                    .overrides
                    .names
                    .get(&entry)
                    .cloned()
                    .unwrap_or_else(|| names[&entry].clone()),
                members,
                blocks,
                variables: vec![],
                signature: String::new(),
                code: vec![],
                warnings,
                complete: false,
                dataflow: Default::default(),
                cache_key: String::new(),
            },
        );
        job.progress("discovery", p.functions.len(), names.len());
    }
    repartition(p, job, false)?;
    loop {
        let changed = classify_no_return(p);
        if !changed {
            break;
        }
        repartition(p, job, true)?;
    }
    Ok(())
}
pub fn blocks(
    members: &[Addr],
    instructions: &BTreeMap<Addr, Instruction>,
    entry: Addr,
) -> Vec<Block> {
    if members.is_empty() {
        return vec![];
    }
    let set = members.iter().copied().collect::<BTreeSet<_>>();
    let mut leaders = BTreeSet::from([members[0], entry]);
    for a in members {
        let ins = &instructions[a];
        match &ins.flow {
            Flow::Switch { targets, .. } => {
                for to in targets {
                    if set.contains(to) {
                        leaders.insert(*to);
                    }
                }
            }
            Flow::Jump(to) | Flow::Branch(to) if set.contains(to) => {
                leaders.insert(*to);
            }
            _ => {}
        }
        if !matches!(ins.flow, Flow::Next) {
            if let Some(next) = ins.next() {
                if set.contains(&next) {
                    leaders.insert(next);
                }
            }
        }
    }
    for pair in members.windows(2) {
        if instructions[&pair[0]].next() != Some(pair[1]) {
            leaders.insert(pair[1]);
        }
    }
    let mut result: Vec<Block> = vec![];
    for a in members {
        if leaders.contains(a) {
            result.push(Block {
                address: *a,
                members: vec![],
                successors: vec![],
            });
        }
        result.last_mut().unwrap().members.push(*a);
    }
    for b in &mut result {
        let ins = &instructions[b.members.last().unwrap()];
        let mut edges = vec![];
        match ins.flow {
            Flow::Switch { ref targets, .. } => edges.extend(targets),
            Flow::Jump(a) => edges.push(a),
            Flow::Branch(a) => {
                edges.push(a);
                if let Some(n) = ins.next() {
                    edges.push(n)
                }
            }
            Flow::Next | Flow::Call(_) => {
                if let Some(n) = ins.next() {
                    edges.push(n)
                }
            }
            _ => {}
        }
        b.successors = edges.into_iter().filter(|a| set.contains(a)).collect();
        b.successors.sort();
        b.successors.dedup();
    }
    result
}

fn known_no_return_name(name: &str) -> bool {
    let name = name.trim_start_matches('_').to_ascii_lowercase();
    matches!(
        name.as_str(),
        "abort"
            | "exit"
            | "quick_exit"
            | "stack_chk_fail"
            | "assert_fail"
            | "cxa_throw"
            | "terminate"
    ) || name.contains("panic")
        || name.contains("fatal")
}
/// Marks only functions whose every reachable terminal path is a verified stop or
/// a direct call to a function already known not to return.
fn classify_no_return(p: &mut Program) -> bool {
    let existing = p
        .functions
        .iter()
        .filter_map(|(entry, function)| function.discovery.no_return.then_some(*entry))
        .collect::<BTreeSet<_>>();
    let named = p
        .functions
        .iter()
        .filter_map(|(entry, function)| known_no_return_name(&function.name).then_some(*entry))
        .collect::<BTreeSet<_>>();
    let known = existing.union(&named).copied().collect::<BTreeSet<_>>();
    let mut updates = vec![];
    for (entry, function) in &p.functions {
        if known.contains(entry) {
            if !function.discovery.no_return {
                updates.push((*entry, "symbol-name".to_string()));
            }
            continue;
        }
        let members = function.members.iter().copied().collect::<BTreeSet<_>>();
        let mut pending = VecDeque::from([*entry]);
        let mut visited = BTreeSet::new();
        let mut terminal = false;
        let mut escapes = false;
        while let Some(address) = pending.pop_front() {
            if !visited.insert(address) {
                continue;
            }
            let Some(instruction) = p.instructions.get(&address) else {
                escapes = true;
                continue;
            };
            let follow = |target: Addr, pending: &mut VecDeque<Addr>, escapes: &mut bool| {
                if members.contains(&target) {
                    pending.push_back(target)
                } else {
                    *escapes = true
                }
            };
            match instruction.flow {
                Flow::Stop => terminal = true,
                Flow::Return | Flow::Indirect => escapes = true,
                Flow::Next => {
                    if let Some(next) = instruction.next() {
                        follow(next, &mut pending, &mut escapes)
                    } else {
                        escapes = true
                    }
                }
                Flow::Call(target) => {
                    if target.is_some_and(|callee| known.contains(&callee)) {
                        terminal = true;
                    } else if let Some(next) = instruction.next() {
                        follow(next, &mut pending, &mut escapes)
                    } else {
                        escapes = true
                    }
                }
                Flow::Jump(target) => follow(target, &mut pending, &mut escapes),
                Flow::Branch(target) => {
                    follow(target, &mut pending, &mut escapes);
                    if let Some(next) = instruction.next() {
                        follow(next, &mut pending, &mut escapes)
                    } else {
                        escapes = true
                    }
                }
                Flow::Switch { ref targets, .. } => {
                    if targets.is_empty() {
                        escapes = true
                    }
                    for target in targets {
                        follow(*target, &mut pending, &mut escapes)
                    }
                }
            }
        }
        if terminal && !escapes {
            updates.push((*entry, "stop-or-noreturn-call".into()));
        }
    }
    let changed = !updates.is_empty();
    for (entry, source) in updates {
        let function = p.functions.get_mut(&entry).unwrap();
        function.discovery.no_return = true;
        function.discovery.no_return_source = source;
    }
    changed
}

/// Rebuild ownership using all discovered roots, so a late call cannot leave a
/// callee embedded in an earlier caller. Shared non-entry blocks remain explicit.
fn repartition(p: &mut Program, job: &mut Job, honor_no_return: bool) -> Result<()> {
    let entries = p.functions.keys().copied().collect::<BTreeSet<_>>();
    let no_return_entries = p
        .functions
        .iter()
        .filter_map(|(entry, function)| function.discovery.no_return.then_some(*entry))
        .collect::<BTreeSet<_>>();
    for f in p.functions.values_mut() {
        let mut pending = VecDeque::from([f.entry]);
        let mut members = BTreeSet::new();
        let mut transfers = vec![];
        while let Some(a) = pending.pop_front() {
            job.tick()?;
            if members.contains(&a)
                || (a != f.entry && entries.contains(&a))
                || f.discovery
                    .declared_end
                    .is_some_and(|end| a < f.entry || a >= end)
            {
                continue;
            }
            let Some(ins) = p.instructions.get(&a) else {
                continue;
            };
            if f.discovery
                .declared_end
                .is_some_and(|end| a.0 as u128 + ins.bytes.len() as u128 > end.0 as u128)
            {
                continue;
            }
            members.insert(a);
            let mut follow = vec![];
            match &ins.flow {
                Flow::Next => {
                    if let Some(n) = ins.next() {
                        follow.push((n, "fallthrough"));
                    }
                }
                Flow::Call(target) => {
                    let non_returning_call = honor_no_return
                        && target.is_some_and(|target| no_return_entries.contains(&target));
                    if !non_returning_call {
                        if let Some(n) = ins.next() {
                            follow.push((n, "fallthrough"));
                        }
                    }
                }
                Flow::Jump(to) => follow.push((*to, "jump")),
                Flow::Branch(to) => {
                    follow.push((*to, "branch"));
                    if let Some(n) = ins.next() {
                        follow.push((n, "fallthrough"));
                    }
                }
                Flow::Switch { targets, .. } => {
                    follow.extend(targets.iter().map(|a| (*a, "switch")))
                }
                _ => {}
            }
            for (to, kind) in follow {
                if (to != f.entry && entries.contains(&to))
                    || f.discovery
                        .declared_end
                        .is_some_and(|end| to < f.entry || to >= end)
                {
                    transfers.push(FunctionTransfer {
                        from: a,
                        to,
                        kind: kind.into(),
                    });
                } else {
                    pending.push_back(to);
                }
            }
        }
        f.members = members.into_iter().collect();
        f.blocks = blocks(&f.members, &p.instructions, f.entry);
        f.discovery.transfers = transfers;
        let meaningful = f
            .members
            .iter()
            .map(|a| &p.instructions[a])
            .filter(|i| !matches!(i.mnemonic.as_str(), "nop" | "endbr64" | "endbr32"))
            .collect::<Vec<_>>();
        if let [ins] = meaningful.as_slice() {
            if let Flow::Jump(to) = ins.flow {
                if to != f.entry && entries.contains(&to) {
                    f.discovery.thunk_target = Some(to);
                }
            }
        }
        if f.discovery.source == "frame-prologue-inferred" {
            f.warnings.push("Entrada inferida por prólogo de marco y frontera con padding; requiere revisión del analista".into());
        }
    }
    let mut owners: BTreeMap<Addr, Vec<Addr>> = BTreeMap::new();
    for (entry, f) in &p.functions {
        for a in &f.members {
            job.tick()?;
            owners.entry(*a).or_default().push(*entry);
        }
    }
    for (a, owners) in owners.into_iter().filter(|(_, v)| v.len() > 1) {
        for entry in owners {
            p.functions
                .get_mut(&entry)
                .unwrap()
                .discovery
                .shared_code
                .push(a);
        }
    }
    for f in p.functions.values_mut() {
        if !f.discovery.shared_code.is_empty() {
            f.warnings.push(format!(
                "{} instrucciones compartidas con otras funciones",
                f.discovery.shared_code.len()
            ));
        }
    }
    let mut seen = BTreeSet::new();
    p.references
        .retain(|r| seen.insert((r.from, r.to, r.kind.clone())));
    Ok(())
}
