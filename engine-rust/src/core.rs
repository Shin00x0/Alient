use crate::{
    ir::{Operand, Statement},
    types::TypeRegistry,
    Result,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(pub u64);
impl Serialize for Addr {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:x}", self.0))
    }
}
impl<'de> Deserialize<'de> for Addr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = String::deserialize(d)?;
        u64::from_str_radix(v.strip_prefix("0x").unwrap_or(&v), 16)
            .map(Addr)
            .map_err(serde::de::Error::custom)
    }
}
impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}
/// A location in an explicitly named address space. Legacy APIs use ram.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressRef {
    pub space: String,
    pub address: Addr,
}
fn ram_space() -> String { "ram".into() }
impl AddressRef {
    pub fn ram(address: Addr) -> Self {
        Self {
            space: "ram".into(),
            address,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Range {
    pub start: Addr,
    pub size: u64,
}
impl Range {
    pub fn contains(&self, a: Addr) -> bool {
        a >= self.start && (a.0 as u128) < self.start.0 as u128 + self.size as u128
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Region {
    pub id: String,
    pub revision: u64,
    pub name: String,
    pub space: String,
    /// Higher-priority overlays shadow lower-priority regions in the same space.
    #[serde(default)]
    pub priority: u16,
    pub range: Range,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: String,
    pub executable: bool,
    pub zero_tail: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Flow {
    Next,
    Jump(Addr),
    Branch(Addr),
    Call(Option<Addr>),
    Return,
    Indirect,
    Switch { targets: Vec<Addr>, index: String },
    Stop,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Instruction {
    pub id: String,
    pub revision: u64,
    #[serde(default = "ram_space")]
    pub space: String,
    pub address: Addr,
    pub bytes: Vec<u8>,
    pub text: String,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub statements: Vec<Statement>,
    pub flow: Flow,
    pub semantic_complete: bool,
}
impl Instruction {
    pub fn next(&self) -> Option<Addr> {
        self.address
            .0
            .checked_add(self.bytes.len() as u64)
            .map(Addr)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reference {
    pub from: Addr,
    pub to: Addr,
    pub kind: String,
    pub confidence: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub address: Addr,
    pub members: Vec<Addr>,
    pub successors: Vec<Addr>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Variable {
    pub id: String,
    pub name: String,
    pub ty: String,
    pub storage: String,
    pub parameter: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeLine {
    pub address: Option<Addr>,
    pub text: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionDiscovery {
    pub source: String,
    pub declared_end: Option<Addr>,
    pub thunk_target: Option<Addr>,
    #[serde(default)]
    pub no_return: bool,
    #[serde(default)]
    pub no_return_source: String,
    pub shared_code: Vec<Addr>,
    pub transfers: Vec<FunctionTransfer>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionTransfer {
    pub from: Addr,
    pub to: Addr,
    pub kind: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Function {
    #[serde(default)]
    pub discovery: FunctionDiscovery,
    pub id: String,
    pub revision: u64,
    pub entry: Addr,
    pub name: String,
    pub members: Vec<Addr>,
    pub blocks: Vec<Block>,
    pub variables: Vec<Variable>,
    pub signature: String,
    pub code: Vec<CodeLine>,
    pub warnings: Vec<String>,
    pub complete: bool,
    pub dataflow: crate::analysis::dataflow::Dataflow,
    pub cache_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    pub id: String,
    pub revision: u64,
    #[serde(default = "ram_space")]
    pub space: String,
    pub range: Range,
    pub ty: String,
    pub value: String,
    pub provenance: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub address: Option<Addr>,
    pub size: u64,
    pub function: bool,
    pub external: bool,
    pub exported: bool,
    pub source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Import {
    pub name: String,
    pub library: String,
    pub slot: Option<Addr>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relocation {
    pub address: Addr,
    pub kind: String,
    pub target: Option<Addr>,
    pub symbol: Option<String>,
    pub addend: i64,
    pub width: u8,
    pub applied: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JumpTable {
    pub base: Addr,
    pub count: usize,
    pub index: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Overrides {
    #[serde(default)]
    pub jump_tables: BTreeMap<Addr, JumpTable>,
    pub names: BTreeMap<Addr, String>,
    pub comments: BTreeMap<Addr, String>,
    pub function_comments: BTreeMap<Addr, String>,
    pub signatures: BTreeMap<Addr, String>,
    pub variable_names: BTreeMap<String, String>,
    pub variable_types: BTreeMap<String, String>,
    pub bookmarks: BTreeMap<Addr, String>,
    pub functions: BTreeSet<Addr>,
    pub excluded_functions: BTreeSet<Addr>,
    pub data: BTreeMap<Addr, Data>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub revision: u64,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub deleted: Vec<String>,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Program {
    pub schema_version: u32,
    pub id: String,
    pub source_hash: String,
    pub source_size: u64,
    pub revision: u64,
    pub format: String,
    pub architecture: String,
    pub image_base: Addr,
    pub entry: Option<Addr>,
    pub regions: Vec<Region>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub relocations: Vec<Relocation>,
    /// Relocation-adjusted bytes overlaying the immutable input file in ram.
    #[serde(default)]
    pub relocated_bytes: BTreeMap<Addr, u8>,
    pub instructions: BTreeMap<Addr, Instruction>,
    pub functions: BTreeMap<Addr, Function>,
    pub data: BTreeMap<Addr, Data>,
    pub references: Vec<Reference>,
    pub types: TypeRegistry,
    pub overrides: Overrides,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn stable_id(program: &str, kind: &str, address: Addr) -> String {
    format!("{program}:{kind}:{address}")
}
pub fn stable_space_id(program: &str, kind: &str, space: &str, address: Addr) -> String {
    format!("{program}:{kind}:{space}:{address}")
}
pub fn stable_region_id(program: &str, space: &str, address: Addr, priority: u16) -> String {
    let base = stable_space_id(program, "memory", space, address);
    if priority == 0 { base } else { format!("{base}:overlay:{priority}") }
}
trait ProgramEntitySpace { fn entity_id(&self, program: &str, kind: &str, address: Addr) -> String; }
impl ProgramEntitySpace for Instruction { fn entity_id(&self, program: &str, kind: &str, address: Addr) -> String { stable_space_id(program, kind, &self.space, address) } }
impl ProgramEntitySpace for Data { fn entity_id(&self, program: &str, kind: &str, address: Addr) -> String { stable_space_id(program, kind, &self.space, address) } }
impl ProgramEntitySpace for Function { fn entity_id(&self, program: &str, kind: &str, address: Addr) -> String { stable_id(program, kind, address) } }

impl Program {
    pub fn region_in(&self, reference: &AddressRef) -> Option<&Region> {
        self.regions
            .iter()
            .filter(|region| region.space == reference.space && region.range.contains(reference.address))
            .max_by_key(|region| region.priority)
    }
    pub fn region(&self, a: Addr) -> Option<&Region> {
        self.region_in(&AddressRef::ram(a))
    }
    pub fn executable_in(&self, reference: &AddressRef) -> bool {
        self.region_in(reference).is_some_and(|r| r.executable)
            && !self.data.values().any(|d| d.space == reference.space && d.range.contains(reference.address))
    }
    pub fn executable(&self, a: Addr) -> bool { self.executable_in(&AddressRef::ram(a)) }
    pub fn file_offset_in(&self, reference: &AddressRef) -> Option<usize> {
        let region = self.region_in(reference)?;
        let delta = reference.address.0 - region.range.start.0;
        if delta >= region.file_size {
            return None;
        }
        usize::try_from(region.file_offset + delta).ok()
    }
    pub fn file_offset(&self, a: Addr) -> Option<usize> {
        self.file_offset_in(&AddressRef::ram(a))
    }
    pub fn bytes_at_in<'a>(
        &self,
        source: &'a [u8],
        reference: &AddressRef,
        max: usize,
    ) -> Result<&'a [u8]> {
        let region = self.region_in(reference).ok_or("Dirección no mapeada")?;
        let delta = reference.address.0 - region.range.start.0;
        if delta >= region.file_size {
            return Err("Memoria sin bytes de archivo".into());
        }
        let start = usize::try_from(region.file_offset + delta).map_err(|_| "Offset inválido")?;
        let len = ((region.file_size - delta) as usize).min(max);
        source
            .get(start..start + len)
            .ok_or_else(|| "Rango truncado".into())
    }
    pub fn bytes_at<'a>(&self, source: &'a [u8], a: Addr, max: usize) -> Result<&'a [u8]> {
        self.bytes_at_in(source, &AddressRef::ram(a), max)
    }
    pub fn read_in(&self, source: &[u8], start: AddressRef, len: usize) -> Result<Vec<u8>> {
        if len > 1024 * 1024 {
            return Err("Lectura > 1 MiB".into());
        }
        let mut out = vec![];
        for index in 0..len {
            let reference = AddressRef {
                space: start.space.clone(),
                address: Addr(
                    start
                        .address
                        .0
                        .checked_add(index as u64)
                        .ok_or("Desbordamiento")?,
                ),
            };
            let region = self.region_in(&reference).ok_or("Hueco de memoria")?;
            if reference.space == "ram" {
                if let Some(byte) = self.relocated_bytes.get(&reference.address) {
                    out.push(*byte);
                    continue;
                }
            }
            if let Some(offset) = self.file_offset_in(&reference) {
                out.push(*source.get(offset).ok_or("Archivo truncado")?)
            } else if region.zero_tail {
                out.push(0)
            } else {
                return Err("Memoria desconocida".into());
            }
        }
        Ok(out)
    }
    pub fn read(&self, source: &[u8], start: Addr, len: usize) -> Result<Vec<u8>> {
        self.read_in(source, AddressRef::ram(start), len)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 || self.source_hash.len() != 64 {
            return Err("Modelo incompatible".into());
        }
        if !self.source_hash.bytes().all(|b| b.is_ascii_hexdigit())
            || self.id
                != format!(
                    "program-{}",
                    hash(
                        format!("{}:{}:{}", self.source_hash, self.format, self.architecture)
                            .as_bytes()
                    )
                )
        {
            return Err("Identidad de programa inválida".into());
        }
        if self
            .changes
            .iter()
            .enumerate()
            .any(|(i, c)| c.revision != i as u64 + 1)
            || self.changes.last().map_or(0, |c| c.revision) != self.revision
        {
            return Err("Historial de revisiones inválido".into());
        }
        if self
            .regions
            .iter()
            .map(|r| &r.id)
            .collect::<BTreeSet<_>>()
            .len()
            != self.regions.len()
        {
            return Err("Identidades de región duplicadas".into());
        }
        let mut sorted = self.regions.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|r| (&r.space, r.range.start));
        for (i, r) in sorted.iter().enumerate() {
            if r.space.is_empty()
                || r.id != stable_region_id(&self.id, &r.space, r.range.start, r.priority)
                || r.revision == 0
                || r.revision > self.revision.max(1)
                || r.range.size == 0
                || r.file_size > r.range.size
                || r.file_offset
                    .checked_add(r.file_size)
                    .is_none_or(|n| n > self.source_size)
                || r.range.start.0 as u128 + r.range.size as u128 > 1u128 << 64
            {
                return Err("Mapa de memoria inválido".into());
            }
            if i > 0
                && sorted[i - 1].space == r.space
                && sorted[i - 1].priority == r.priority
                && sorted[i - 1].range.start.0 as u128 + sorted[i - 1].range.size as u128
                    > r.range.start.0 as u128
            {
                return Err("Memoria superpuesta".into());
            }
        }
        let mut ends = BTreeMap::<String, u128>::new();
        for (a, i) in &self.instructions {
            let end = *ends.get(&i.space).unwrap_or(&0);
            if i.id != stable_space_id(&self.id, "instructions", &i.space, *a)
                || i.revision == 0
                || i.revision > self.revision
                || *a != i.address
                || i.bytes.is_empty()
                || (a.0 as u128) < end
                || self.region_in(&AddressRef { space: i.space.clone(), address: *a }).is_none_or(|r| {
                    !r.executable
                        || a.0 as u128 + i.bytes.len() as u128
                            > r.range.start.0 as u128 + r.range.size as u128
                })
            {
                return Err("Instrucciones inválidas o superpuestas".into());
            }
            for (index, statement) in i.statements.iter().enumerate() {
                statement
                    .validate()
                    .map_err(|e| format!("IR en {a}, operación {index}: {e}"))?;
            }
            ends.insert(i.space.clone(), a.0 as u128 + i.bytes.len() as u128);
        }
        for (a, f) in &self.functions {
            if f.id != stable_id(&self.id, "functions", *a)
                || f.revision == 0
                || f.revision > self.revision
                || *a != f.entry
                || f.members.windows(2).any(|w| w[0] >= w[1])
                || !f.members.contains(a)
                || f.members.iter().any(|m| !self.instructions.contains_key(m))
            {
                return Err("Cuerpo de función inválido".into());
            }
            let block_entries = f.blocks.iter().map(|b| b.address).collect::<BTreeSet<_>>();
            if !block_entries.contains(a)
                || f.blocks.iter().any(|b| {
                    b.members.first() != Some(&b.address)
                        || b.successors.iter().any(|s| !block_entries.contains(s))
                })
            {
                return Err("Bloques de función inválidos".into());
            }
            let mut covered = f
                .blocks
                .iter()
                .flat_map(|b| b.members.iter().copied())
                .collect::<Vec<_>>();
            covered.sort();
            if covered != f.members {
                return Err("Cobertura de bloques inválida".into());
            }
        }
        let mut data_ends = BTreeMap::<String, u128>::new();
        for (a, d) in &self.data {
            let data_end = *data_ends.get(&d.space).unwrap_or(&0);
            if d.id != stable_space_id(&self.id, "data", &d.space, *a)
                || d.revision == 0
                || d.revision > self.revision
                || *a != d.range.start
                || (a.0 as u128) < data_end
                || d.range.size == 0
                || self.region_in(&AddressRef { space: d.space.clone(), address: d.range.start }).is_none_or(|r| {
                    d.range.start.0 as u128 + d.range.size as u128
                        > r.range.start.0 as u128 + r.range.size as u128
                })
                || self.instructions.values().any(|i| {
                    i.space == d.space && (i.address.0 as u128) < d.range.start.0 as u128 + d.range.size as u128
                        && (d.range.start.0 as u128) < i.address.0 as u128 + i.bytes.len() as u128
                })
            {
                return Err("Dato inválido o sobre código".into());
            }
            data_ends.insert(d.space.clone(), d.range.start.0 as u128 + d.range.size as u128);
        }
        if self.relocated_bytes.keys().any(|address| self.region(*address).is_none()) {
            return Err("Relocación aplicada fuera de memoria ram".into());
        }
        self.types.validate()?;
        Ok(())
    }
    pub fn reconcile(&mut self, old: Option<&Program>, reason: &str) -> Result<()> {
        let rev = old.map_or(1, |p| p.revision + 1);
        let mut change = Change {
            revision: rev,
            created: vec![],
            updated: vec![],
            deleted: vec![],
            reason: reason.into(),
        };
        macro_rules! merge {
            ($field:ident) => {{
                for (a, e) in &mut self.$field {
                    e.id = e.entity_id(&self.id, stringify!($field), *a);
                    e.revision = 0;
                    let prev = old.and_then(|p| p.$field.get(a));
                    if let Some(o) = prev {
                        let mut normalized = o.clone();
                        normalized.revision = 0;
                        if *e == normalized {
                            e.revision = o.revision
                        } else {
                            change.updated.push(e.id.clone());
                            e.revision = rev
                        }
                    } else {
                        change.created.push(e.id.clone());
                        e.revision = rev
                    }
                }
                if let Some(p) = old {
                    for (a, e) in &p.$field {
                        if !self.$field.contains_key(a) {
                            change.deleted.push(e.id.clone());
                        }
                    }
                }
            }};
        }
        merge!(instructions);
        merge!(functions);
        merge!(data);
        self.changes = old.map_or(vec![], |p| p.changes.clone());
        let meta_changed =
            old.is_none_or(|p| p.overrides != self.overrides || p.types != self.types);
        if change.created.is_empty()
            && change.updated.is_empty()
            && change.deleted.is_empty()
            && !meta_changed
        {
            self.revision = old.map_or(0, |p| p.revision)
        } else {
            self.revision = rev;
            self.changes.push(change)
        }
        self.validate()
    }
}
