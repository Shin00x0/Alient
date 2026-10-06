//! N12: revision snapshots and indexes published through a single atomic result pointer.
use crate::{commands::History, core::*, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    pub version: u32,
    pub program: Program,
    pub history: History,
    pub index: SearchIndex,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchIndex {
    pub documents: Vec<SearchDocument>,
    pub words: BTreeMap<String, BTreeSet<usize>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchDocument {
    pub kind: String,
    pub address: Addr,
    pub text: String,
}
fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}
impl SearchIndex {
    pub fn build(p: &Program) -> Self {
        let mut s = Self::default();
        for i in p.instructions.values() {
            s.add(
                "instruction",
                i.address,
                format!(
                    "{} {}",
                    i.text,
                    p.overrides
                        .comments
                        .get(&i.address)
                        .map_or("", String::as_str)
                ),
            );
        }
        for f in p.functions.values() {
            s.add("function", f.entry, f.name.clone());
            for line in &f.code {
                s.add("code", line.address.unwrap_or(f.entry), line.text.clone());
            }
        }
        for d in p.data.values() {
            s.add("data", d.range.start, d.value.clone());
        }
        s
    }
    fn add(&mut self, kind: &str, address: Addr, text: String) {
        let i = self.documents.len();
        for w in words(&text) {
            self.words.entry(w).or_default().insert(i);
        }
        self.documents.push(SearchDocument {
            kind: kind.into(),
            address,
            text,
        });
    }
    pub fn search(
        &self,
        query: &str,
        kind: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<SearchDocument>) {
        let tokens = words(query);
        if tokens.is_empty() {
            return (0, vec![]);
        }
        let mut hits: Option<BTreeSet<usize>> = None;
        for token in tokens {
            let found = self.words.get(&token).cloned().unwrap_or_default();
            hits = Some(hits.map_or(found.clone(), |v| v.intersection(&found).copied().collect()));
        }
        let docs = hits
            .unwrap_or_default()
            .into_iter()
            .map(|i| &self.documents[i])
            .filter(|d| kind.is_none_or(|k| d.kind == k))
            .collect::<Vec<_>>();
        (
            docs.len(),
            docs.into_iter()
                .skip(offset)
                .take(limit.min(300))
                .cloned()
                .collect(),
        )
    }
}
pub struct Store {
    pub root: PathBuf,
    _lock: File,
}
impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("native.lock"))
            .map_err(|e| e.to_string())?;
        lock.try_lock_exclusive()
            .map_err(|_| "El proyecto ya está ocupado")?;
        Ok(Self {
            root: root.into(),
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<Option<Stored>> {
        for name in ["result.json", "previous-result.json"] {
            let text = match fs::read_to_string(self.root.join(name)) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let generation = match v.get("listingGeneration").and_then(|s| s.as_str()) {
                Some(s) if valid_generation(s) => s,
                _ => return Ok(None),
            };
            let path = self.root.join(generation).join("native.json");
            if !path.exists() {
                return Ok(None);
            }
            let data = fs::read(path).map_err(|e| e.to_string())?;
            let stored: Stored = serde_json::from_slice(&data)
                .map_err(|e| format!("Estado nativo inválido: {e}"))?;
            if stored.version != 1 || stored.history.cursor >= stored.history.states.len() {
                return Err("Versión/historial de almacenamiento inválido".into());
            }
            stored.program.validate()?;
            if stored.history.states[stored.history.cursor]
                != crate::commands::EditState::from_program(&stored.program)
            {
                return Err("Historial no coincide con el programa".into());
            }
            if stored
                .index
                .words
                .values()
                .flatten()
                .any(|i| *i >= stored.index.documents.len())
            {
                return Err("Índice corrupto".into());
            }
            return Ok(Some(stored));
        }
        Ok(None)
    }
    pub fn publish(
        &self,
        stored: &Stored,
        result: &mut serde_json::Value,
        listing: &[serde_json::Value],
    ) -> Result<String> {
        let nonce = format!(
            "{}:{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos(),
            stored.program.revision
        );
        let h = hash(nonce.as_bytes());
        let generation = format!(
            "listing-{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        );
        let folder = self.root.join(&generation);
        fs::create_dir(&folder).map_err(|e| e.to_string())?;
        let mut pages = vec![];
        for (page, rows) in listing.chunks(256).enumerate() {
            write_json(&folder.join(format!("{page}.json")), rows)?;
            pages.push(serde_json::json!({"page":page,"space":"ram","start":rows.first().unwrap()["offset"],"end":rows.last().unwrap()["endOffset"],"count":rows.len()}));
        }
        write_json(
            &folder.join("index.json"),
            &serde_json::json!({"generation":generation,"totalInstructions":listing.len(),"pageSize":256,"defaultSpace":"ram","pages":pages}),
        )?;
        let directory=stored.program.functions.values().map(|f|serde_json::json!({"address":f.entry.to_string(),"name":f.name,"qualifiedName":f.name,"signature":f.signature,"id":f.id,"revision":f.revision})).collect::<Vec<_>>();
        write_json(&folder.join("functions.json"), &directory)?;
        write_json(&folder.join("program.json"), &stored.program)?;
        write_json(&folder.join("native.json"), stored)?;
        File::open(&folder)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        result["listingGeneration"] = serde_json::json!(generation);
        atomic_json(&self.root.join("result.json"), result)?;
        Ok(generation)
    }
}
pub fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let mut file = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, value).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
pub fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    write_json(&temporary, value)?;
    fs::rename(temporary, path).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn valid_generation(s: &str) -> bool {
    s.len() == 44
        && s.starts_with("listing-")
        && s[8..].bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}
