//! N03: format adapters through object-rs, with explicit imported-name and relocation provenance.
use crate::{core::*, loaders::catalog::identify, types::TypeRegistry, Result};
pub mod catalog;
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, RelocationTarget,
    SectionFlags, SectionKind, SegmentFlags,
};
use std::collections::{BTreeMap, BTreeSet};
pub fn load(bytes: &[u8]) -> Result<Program> {
    if bytes.len() > crate::MAX_INPUT {
        return Err("Máximo 32 MiB".into());
    }
    let file = object::File::parse(bytes).map_err(|e| format!("Formato inválido: {e}"))?;
    let spec = identify(&file)?;
    let arch = spec.architecture;
    let format = spec.format;
    let source_hash = hash(bytes);
    let id = format!(
        "program-{}",
        hash(format!("{source_hash}:{format}:{arch}").as_bytes())
    );
    let mut p = Program {
        schema_version: 2,
        id: id.clone(),
        source_hash,
        source_size: bytes.len() as u64,
        revision: 0,
        format: format.into(),
        architecture: arch.into(),
        image_base: Addr(file.relative_address_base()),
        entry: (file.entry() != 0).then_some(Addr(file.entry())),
        regions: vec![],
        symbols: vec![],
        imports: vec![],
        relocations: vec![],
        relocated_bytes: BTreeMap::new(),
        instructions: BTreeMap::new(),
        functions: BTreeMap::new(),
        data: BTreeMap::new(),
        references: vec![],
        types: TypeRegistry::default(),
        overrides: Overrides::default(),
        changes: vec![],
        warnings: vec![],
    };
    let segment_base = file
        .segments()
        .filter(|s| s.size() > 0 && s.file_range().1 > 0)
        .map(|s| s.address())
        .min();
    if let Some(base) = segment_base {
        p.image_base = Addr(base)
    }
    for s in file.sections() {
        let allocated = match s.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & 2 != 0,
            _ => !matches!(
                s.kind(),
                SectionKind::Debug
                    | SectionKind::Metadata
                    | SectionKind::Other
                    | SectionKind::Linker
            ),
        };
        if !allocated || s.size() == 0 {
            continue;
        }
        let (off, size) = s.file_range().unwrap_or((0, 0));
        if off.checked_add(size).is_none_or(|n| n > bytes.len() as u64) {
            return Err("Sección truncada".into());
        }
        let code = s.kind() == SectionKind::Text
            || matches!(s.flags(), SectionFlags::MachO { flags } if flags & 0x80000400 != 0);
        let permissions = match s.flags() {
            SectionFlags::Elf { sh_flags } => format!(
                "r{}{}",
                if sh_flags & 1 != 0 { 'w' } else { '-' },
                if sh_flags & 4 != 0 { 'x' } else { '-' }
            ),
            SectionFlags::Coff { characteristics } => format!(
                "{}{}{}",
                if characteristics & 0x40000000 != 0 {
                    'r'
                } else {
                    '-'
                },
                if characteristics & 0x80000000 != 0 {
                    'w'
                } else {
                    '-'
                },
                if characteristics & 0x20000000 != 0 {
                    'x'
                } else {
                    '-'
                }
            ),
            _ => format!(
                "r{}{}",
                if matches!(s.kind(), SectionKind::Data | SectionKind::UninitializedData) {
                    'w'
                } else {
                    '-'
                },
                if code { 'x' } else { '-' }
            ),
        };
        p.regions.push(Region {
            id: stable_space_id(&id, "memory", "ram", Addr(s.address())),
            revision: 1,
            name: s.name().unwrap_or("section").into(),
            space: "ram".into(),
            priority: 0,
            range: Range {
                start: Addr(s.address()),
                size: s.size(),
            },
            file_offset: off,
            file_size: size.min(s.size()),
            permissions,
            executable: code,
            zero_tail: true,
        });
    }
    if p.regions.is_empty() {
        for s in file.segments() {
            if s.size() == 0 {
                continue;
            }
            let (off, size) = s.file_range();
            let code = match s.flags() {
                SegmentFlags::Elf { p_flags } => p_flags & 1 != 0,
                SegmentFlags::MachO { initprot, .. } => initprot & 4 != 0,
                _ => false,
            };
            p.regions.push(Region {
                id: stable_space_id(&id, "memory", "ram", Addr(s.address())),
                revision: 1,
                name: s.name().ok().flatten().unwrap_or("segment").into(),
                space: "ram".into(),
                priority: 0,
                range: Range {
                    start: Addr(s.address()),
                    size: s.size(),
                },
                file_offset: off,
                file_size: size,
                permissions: if code { "r-x" } else { "rw-" }.into(),
                executable: code,
                zero_tail: true,
            });
        }
    }
    let mut seen = BTreeSet::new();
    for s in file.symbols().chain(file.dynamic_symbols()) {
        let name = s.name().unwrap_or("");
        if name.is_empty() || !seen.insert((name.to_string(), s.address(), s.is_undefined())) {
            continue;
        }
        p.symbols.push(Symbol {
            name: name.into(),
            address: (!s.is_undefined()).then_some(Addr(s.address())),
            size: s.size(),
            function: s.kind() == object::SymbolKind::Text && !s.is_undefined(),
            external: s.is_undefined(),
            exported: s.is_global() && !s.is_undefined(),
            source: "symbol-table".into(),
        });
    }
    match file.imports() {
        Ok(imports) => {
            for i in imports {
                p.imports.push(Import {
                    name: String::from_utf8_lossy(i.name()).into_owned(),
                    library: String::from_utf8_lossy(i.library()).into_owned(),
                    slot: None,
                })
            }
        }
        Err(e) => p.warnings.push(format!("Importaciones incompletas: {e}")),
    }
    for import in &p.imports {
        if !p
            .symbols
            .iter()
            .any(|s| s.external && s.name == import.name)
        {
            p.symbols.push(Symbol {
                name: import.name.clone(),
                address: None,
                size: 0,
                function: false,
                external: true,
                exported: false,
                source: "import-table".into(),
            });
        }
    }
    match file.exports() {
        Ok(exports) => {
            for e in exports {
                let name = String::from_utf8_lossy(e.name()).into_owned();
                if !p
                    .symbols
                    .iter()
                    .any(|s| s.name == name && s.address == Some(Addr(e.address())))
                {
                    p.symbols.push(Symbol {
                        name,
                        address: Some(Addr(e.address())),
                        size: 0,
                        function: p.executable(Addr(e.address())),
                        external: false,
                        exported: true,
                        source: "export-table".into(),
                    });
                }
            }
        }
        Err(e) => p.warnings.push(format!("Exportaciones incompletas: {e}")),
    }
    let relocation = |a: u64, r: object::Relocation, dynamic: bool| -> Relocation {
        let mut name = None;
        let target = match r.target() {
            RelocationTarget::Symbol(idx) => {
                let sym = if dynamic {
                    file.dynamic_symbol_table()
                        .and_then(|t| t.symbol_by_index(idx).ok())
                } else {
                    file.symbol_by_index(idx).ok()
                };
                sym.and_then(|s| {
                    name = s.name().ok().map(str::to_string);
                    (!s.is_undefined()).then_some(Addr(s.address()))
                })
            }
            RelocationTarget::Section(idx) => {
                file.section_by_index(idx).ok().map(|s| Addr(s.address()))
            }
            RelocationTarget::Absolute => Some(Addr(0)),
            _ => None,
        };
        Relocation {
            address: Addr(a),
            kind: format!("{:?}/{:?}", r.kind(), r.flags()),
            target,
            symbol: name,
            addend: r.addend(),
            width: r.size(),
            applied: false,
        }
    };
    for s in file.sections() {
        for (off, r) in s.relocations() {
            let a = s
                .address()
                .checked_add(off)
                .ok_or("Relocación desbordada")?;
            p.relocations.push(relocation(a, r, false));
        }
    }
    if let Some(rs) = file.dynamic_relocations() {
        for (a, r) in rs {
            p.relocations.push(relocation(a, r, true));
        }
    }
    apply_absolute_relocations(&mut p);
    for r in &p.relocations {
        if r.target.is_none() {
            if let Some(name) = &r.symbol {
                if let Some(import) = p
                    .imports
                    .iter_mut()
                    .find(|i| i.name == *name && i.slot.is_none())
                {
                    import.slot = Some(r.address);
                }
            }
        }
    }
    if p.symbols.len() > 100_000 || p.relocations.len() > 100_000 {
        return Err("Demasiados símbolos/relocaciones".into());
    }
    if p.regions.is_empty() {
        return Err("No hay regiones de memoria; cabeceras incompletas o archivo vacío".into());
    }
    p.regions.sort_by_key(|r| r.range.start);
    p.warnings.push("Relocaciones conservadas sin aplicar; bibliotecas externas no ejecutadas ni enlazadas dinámicamente. DWARF/PDB y fixups avanzados no interpretados.".into());
    p.validate()?;
    Ok(p)
}


/// Apply only relocations whose semantics are unambiguous without a dynamic linker.
/// The adjusted bytes form a virtual overlay; the input file is never modified.
fn apply_absolute_relocations(program: &mut Program) {
    for index in 0..program.relocations.len() {
        let relocation = &program.relocations[index];
        if relocation.kind.split('/').next() != Some("Absolute") || !matches!(relocation.width, 8 | 16 | 32 | 64) { continue; }
        let Some(target) = relocation.target else { continue; };
        let value = target.0 as i128 + relocation.addend as i128;
        let bits = relocation.width;
        if value < 0 || (bits < 64 && value > ((1i128 << bits) - 1)) { continue; }
        let bytes = (value as u64).to_le_bytes();
        let size = (bits / 8) as usize;
        if (0..size).any(|offset| program.region(Addr(relocation.address.0.saturating_add(offset as u64))).is_none()) { continue; }
        for (offset, byte) in bytes[..size].iter().enumerate() {
            program.relocated_bytes.insert(Addr(relocation.address.0 + offset as u64), *byte);
        }
        program.relocations[index].applied = true;
    }
}
