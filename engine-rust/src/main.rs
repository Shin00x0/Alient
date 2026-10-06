use ghidra_web_engine::{
    capabilities,
    commands::Command,
    core::Addr,
    loaders, protocol,
    scheduler::{Budget, Job},
    storage::Store,
    Result,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
fn read_input(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = vec![];
    file.take((ghidra_web_engine::MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > ghidra_web_engine::MAX_INPUT {
        return Err("Máximo 32 MiB".into());
    }
    Ok(bytes)
}
fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let action = args.first().map(String::as_str).unwrap_or("capabilities");
    if action == "capabilities" {
        println!("{}", capabilities::describe());
        return Ok(());
    }
    if action == "inspect" {
        let path = args.get(1).ok_or("Falta archivo")?;
        let bytes = read_input(path)?;
        let p = loaders::load(&bytes)?;
        println!("{}", serde_json::to_string(&p).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let root = PathBuf::from(args.get(1).ok_or("Falta directorio de proyecto")?);
    let store = Store::open(&root)?;
    if action == "indirect" || action == "jump-table" {
        let stored = store.load()?.ok_or("No hay programa nativo")?;
        let source = read_input(root.join("input.bin"))?;
        let p = &stored.program;
        let value = if action == "indirect" {
            let abi = ghidra_web_engine::analysis::abi::select(p);
            serde_json::to_value(ghidra_web_engine::analysis::indirect::resolve(
                p,
                &source,
                &abi.result,
                &mut Job::new(Budget::default()),
            )?)
            .map_err(|e| e.to_string())?
        } else {
            let base = Addr(
                u64::from_str_radix(
                    args.get(2)
                        .ok_or("Falta dirección")?
                        .trim_start_matches("0x"),
                    16,
                )
                .map_err(|_| "Dirección inválida")?,
            );
            let count = args
                .get(3)
                .ok_or("Falta cantidad explícita")?
                .parse()
                .map_err(|_| "Cantidad inválida")?;
            serde_json::to_value(ghidra_web_engine::analysis::indirect::absolute_table(
                p, &source, base, count,
            )?)
            .map_err(|e| e.to_string())?
        };
        println!("{value}");
        return Ok(());
    }
    if action == "search" {
        let stored = store.load()?.ok_or("No hay programa nativo")?;
        let query = args.get(2).ok_or("Falta consulta")?;
        let offset = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
        let (total, hits) = stored.index.search(
            query,
            args.get(3).filter(|s| !s.is_empty()).map(String::as_str),
            offset,
            100,
        );
        println!(
            "{}",
            serde_json::json!({"total":total,"results":hits,"offset":offset})
        );
        return Ok(());
    }
    if action == "function" {
        let stored = store.load()?.ok_or("No hay programa nativo")?;
        let address = Addr(
            u64::from_str_radix(
                args.get(2)
                    .ok_or("Falta dirección")?
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|_| "Dirección inválida")?,
        );
        let f = stored
            .program
            .functions
            .get(&address)
            .ok_or("Función inexistente")?;
        let mut result = serde_json::to_value(f).map_err(|e| e.to_string())?;
        result["abi"] = ghidra_web_engine::analysis::abi::report(
            &stored.program,
            f,
            &mut Job::new(Budget::default()),
        )?;
        result["ir"] = serde_json::json!(f.members.iter().flat_map(|a| {
            stored.program.instructions[a].statements.iter().enumerate().map(move |(index, statement)| {
                serde_json::json!({"address": a, "statementIndex": index, "statement": statement, "effects": statement.effects()})
            })
        }).collect::<Vec<_>>());
        println!("{result}");
        return Ok(());
    }
    if !["analyze", "edit"].contains(&action) {
        return Err("Operación desconocida".into());
    }
    let bytes = read_input(root.join("input.bin"))?;
    let old = store.load()?;
    let command: Option<Command> = if action == "edit" {
        Some(
            serde_json::from_slice(&fs::read(root.join("edit.json")).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Comando inválido: {e}"))?,
        )
    } else {
        None
    };
    let mut job = Job::new(Budget::default());
    job.emit = true;
    job.cancel_file = Some(root.join("native.cancel"));
    let stored = protocol::analyze(&bytes, old.as_ref(), command.as_ref(), &mut job)?;
    let name = args.get(2).map_or("binary", String::as_str);
    let mut result = protocol::analysis(&stored.program, name);
    let listing = protocol::listing(&stored.program);
    let generation = store.publish(&stored, &mut result, &listing)?;
    println!(
        "{}",
        serde_json::json!({"ok":true,"generation":generation,"revision":stored.program.revision,"functions":stored.program.functions.len(),"instructions":stored.program.instructions.len()})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", serde_json::json!({"event":"error","error":e}));
        std::process::exit(1)
    }
}
