//! Native analysis pipeline and compatibility DTOs for the existing web UI.
use crate::{
    analysis::{abi, dataflow, discovery, indirect},
    commands::{Command, History},
    core::*,
    decompiler, loaders,
    scheduler::Job,
    storage::{SearchIndex, Stored},
    Result,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub fn analyze(
    source: &[u8],
    old: Option<&Stored>,
    command: Option<&Command>,
    job: &mut Job,
) -> Result<Stored> {
    job.progress("load", 0, 1);
    let mut p = loaders::load(source)?;
    if let Some(s) = old {
        if s.program.id != p.id {
            return Err("El archivo no coincide con el proyecto persistente".into());
        }
        p.overrides = s.program.overrides.clone();
        p.types = s.program.types.clone();
    }
    let mut history = old.map_or_else(|| History::new(&p), |s| s.history.clone());
    if let Some(c) = command {
        let old = old.ok_or("Analiza el programa antes de editar")?;
        let (state, _) = history.apply(&old.program, c)?;
        p.overrides = state.overrides;
        p.types = state.types;
    }
    for (address, name) in &p.overrides.names {
        let mut found = false;
        for symbol in &mut p.symbols {
            if symbol.address == Some(*address) {
                symbol.name = name.clone();
                symbol.source = "user".into();
                found = true;
            }
        }
        if !found {
            p.symbols.push(Symbol {
                name: name.clone(),
                address: Some(*address),
                size: 0,
                function: false,
                external: false,
                exported: false,
                source: "user".into(),
            });
        }
    }
    job.progress("discovery", 0, 1);
    discovery::strings(&mut p, source, job)?;
    discovery::discover(&mut p, source, job)?;
    let abi = abi::select(&p);
    let abi_key = abi.name;
    // Resolve, rediscover and recompute until stable, with a bounded number of rounds.
    for round in 0..4 {
        let names = p
            .functions
            .iter()
            .map(|(a, f)| (*a, f.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let entries = p.functions.keys().copied().collect::<Vec<_>>();
        let total = entries.len();
        for (index, entry) in entries.iter().enumerate() {
            job.tick()?;
            let mut f = p.functions.remove(entry).unwrap();
            let key_data = serde_json::to_vec(&(
                env!("CARGO_PKG_VERSION"),
                env!("NATIVE_BUILD_ID"),
                abi_key,
                &f.members
                    .iter()
                    .map(|a| &p.instructions[a])
                    .collect::<Vec<_>>(),
                (&f.name, &f.discovery),
                &p.overrides.function_comments.get(entry),
                &p.overrides.signatures.get(entry),
                &f.members
                    .iter()
                    .filter_map(|a| p.overrides.comments.get(a).map(|v| (a, v)))
                    .collect::<Vec<_>>(),
                &p.overrides
                    .variable_names
                    .iter()
                    .filter(|(id, _)| id.starts_with(&format!("{entry}:")))
                    .collect::<Vec<_>>(),
                &p.overrides
                    .variable_types
                    .iter()
                    .filter(|(id, _)| id.starts_with(&format!("{entry}:")))
                    .collect::<Vec<_>>(),
                &p.types,
                &f.members
                    .iter()
                    .filter_map(|a| match p.instructions[a].flow {
                        Flow::Call(Some(to)) => names.get(&to).map(|n| (to, n)),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ))
            .map_err(|e| e.to_string())?;
            let key = hash(&key_data);
            if let Some(cached) = old
                .and_then(|s| s.program.functions.get(entry))
                .filter(|f| f.cache_key == key)
            {
                f = cached.clone();
                job.progress("cache", index + 1, total);
            } else {
                f.dataflow = dataflow::analyze(&f, &p.instructions, &abi.clobbers, job)?;
                f.variables =
                    abi::variables(&f, &p.instructions, &f.dataflow, &abi, &p.overrides, job)?;
                decompiler::emit(&mut f, &p.instructions, &abi, &p.overrides, &names);
                f.cache_key = key;
                job.progress("decompile", index + 1, total);
            }
            p.functions.insert(*entry, f);
        }
        job.progress("indirect", 0, 1);
        let report = indirect::resolve(&p, source, &abi.result, job)?;
        let mut changed = false;
        if round < 3 {
            for reference in &report.resolved {
                if let Some(ins) = p.instructions.get_mut(&reference.from) {
                    if reference.kind == "INDIRECT_CALL" && matches!(ins.flow, Flow::Call(None)) {
                        ins.flow = Flow::Call(Some(reference.to));
                        changed = true;
                    }
                    if reference.kind == "INDIRECT_JUMP" && matches!(ins.flow, Flow::Indirect) {
                        ins.flow = Flow::Jump(reference.to);
                        changed = true;
                    }
                }
            }
        }
        p.references.extend(report.resolved);
        if !changed {
            if !report.unresolved.is_empty() {
                p.warnings.push(format!(
                    "{} destinos indirectos pendientes",
                    report.unresolved.len()
                ));
            }
            break;
        }
        p.functions.clear();
        p.references.clear();
        discovery::discover(&mut p, source, job)?;
    }
    let mut seen = BTreeSet::new();
    p.references
        .retain(|r| seen.insert((r.from, r.to, r.kind.clone())));
    p.reconcile(
        old.map(|s| &s.program),
        if command.is_some() {
            "edit"
        } else {
            "analysis"
        },
    )?;
    let index = SearchIndex::build(&p);
    job.progress("complete", 1, 1);
    Ok(Stored {
        version: 1,
        program: p,
        history,
        index,
    })
}
pub fn listing(p: &Program) -> Vec<Value> {
    p.instructions.values().map(|i|{
 let f=p.functions.values().find(|f|f.members.binary_search(&i.address).is_ok());
 json!({"id":i.id,"revision":i.revision,"address":i.address.to_string(),"offset":i.address.to_string(),"endOffset":Addr(i.address.0+i.bytes.len()as u64-1).to_string(),"space":i.space,"bytes":i.bytes.iter().map(|b|format!("{b:02x}")).collect::<Vec<_>>().join(" "),"text":i.text,"comment":p.overrides.comments.get(&i.address),"function":f.map(|f|&f.name),"functionAddress":f.map(|f|f.entry.to_string()),"label":f.filter(|f|f.entry==i.address).map(|f|&f.name),"references":p.references.iter().filter(|r|r.from==i.address).map(|r|json!({"to":r.to.to_string(),"type":r.kind})).collect::<Vec<_>>()})
 }).collect()
}
pub fn analysis(p: &Program, name: &str) -> Value {
    let rows = listing(p);
    let indexed = rows
        .iter()
        .map(|r| (r["address"].as_str().unwrap().to_string(), r))
        .collect::<BTreeMap<_, _>>();
    let functions=p.functions.values().map(|f|{let lines=f.code.iter().map(|l|json!({"indent":"","tokens":[{"text":l.text,"syntax":8,"address":l.address.map(|a|a.to_string())}]})).collect::<Vec<_>>();json!({"id":f.id,"revision":f.revision,"address":f.entry.to_string(),"name":f.name,"signature":f.signature,"decompiledSignature":f.signature,"end":f.members.last().and_then(|a|p.instructions.get(a)).map(|i|Addr(i.address.0+i.bytes.len()as u64-1).to_string()),"comment":p.overrides.function_comments.get(&f.entry),"kind":if f.discovery.thunk_target.is_some(){"thunk"}else{"function"},"discovery":f.discovery,"decompileStatus":"partial","warning":if f.complete{format!("C de bajo nivel con operaciones abstractas; no equivale a recuperar el código fuente. {}", f.warnings.join("; "))}else{f.warnings.join("; ")},"error":"","code":f.code.iter().map(|l|format!("{}\n",l.text)).collect::<String>(),"codeLines":lines,"instructionsTruncated":false,"instructions":f.members.iter().filter_map(|a|indexed.get(&a.to_string())).collect::<Vec<_>>(),"references":p.references.iter().filter(|r|r.to==f.entry).map(|r|json!({"from":r.from.to_string(),"type":r.kind})).collect::<Vec<_>>(),"flowBlocks":f.blocks.iter().map(|b|json!({"address":b.address.to_string(),"end":b.members.last().map(|a|a.to_string()),"edges":b.successors.iter().map(|a|json!({"to":a.to_string(),"type":"FLOW"})).collect::<Vec<_>>()})).collect::<Vec<_>>(),"variables":f.variables.iter().map(|v|json!({"id":v.id,"name":v.name,"type":v.ty,"storage":v.storage,"parameter":v.parameter})).collect::<Vec<_>>()})}).collect::<Vec<_>>();
    json!({"engine":"internal","nativeEngine":"rust","engineBuild":env!("NATIVE_BUILD_ID"),"schemaVersion":4,"engineVersion":format!("Rust {}",env!("CARGO_PKG_VERSION")),"program":{"id":p.id,"revision":p.revision,"schemaVersion":2},"name":name,"format":p.format,"language":p.architecture,"imageBase":p.image_base.to_string(),"totalFunctions":p.functions.len(),"listingFunctions":p.functions.len(),"externalSymbols":p.imports.len(),"totalInstructions":p.instructions.len(),"limits":"Motor Rust: C de bajo nivel parcial, semántica entera acotada; sin equivalencia con Ghidra/IDA. 200000 instrucciones, 20000 funciones, 32 MiB, 2 min.","blocks":p.regions.iter().map(|r|json!({"name":r.name,"start":r.range.start.to_string(),"size":r.range.size.to_string(),"permissions":r.permissions})).collect::<Vec<_>>(),"functions":functions,"strings":p.data.values().filter(|d|d.ty=="ascii-z").map(|d|json!({"address":d.range.start.to_string(),"end":Addr(d.range.start.0+d.range.size-1).to_string(),"value":d.value})).collect::<Vec<_>>(),"allReferences":p.references.iter().map(|r|{let f=p.functions.values().find(|f|f.members.binary_search(&r.from).is_ok());json!({"from":r.from.to_string(),"to":r.to.to_string(),"type":r.kind,"call":r.kind.contains("CALL"),"function":f.map(|f|&f.name),"functionAddress":f.map(|f|f.entry.to_string()),"confidence":r.confidence})}).collect::<Vec<_>>(),"symbols":p.symbols.iter().map(|s|json!({"name":s.name,"address":s.address.map_or(String::new(),|a|a.to_string()),"type":if s.function{"Function"}else{"Label"},"external":s.external,"entry":s.exported})).collect::<Vec<_>>(),"types":p.types.0.keys().map(|n|json!({"name":n,"path":n,"size":p.types.size(n).unwrap_or(0)})).collect::<Vec<_>>(),"bookmarks":p.overrides.bookmarks.iter().map(|(a,v)|json!({"address":a.to_string(),"type":"Note","category":"user","comment":v})).collect::<Vec<_>>(),"loader":{"imports":p.imports,"relocations":p.relocations,"warnings":p.warnings}})
}
