//! N13: validated edit commands, persistent undo/redo state and explicit analysis invalidation.
use crate::{
    core::*,
    decompiler::valid_signature,
    types::{identifier, Type, TypeRegistry},
    Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum Command {
    Rename {
        address: Addr,
        value: String,
    },
    Comment {
        address: Addr,
        value: String,
    },
    FunctionComment {
        address: Addr,
        value: String,
    },
    Signature {
        address: Addr,
        value: String,
    },
    Bookmark {
        address: Addr,
        value: String,
    },
    Variable {
        address: Addr,
        #[serde(rename = "variableId")]
        variable_id: String,
        value: String,
        #[serde(default, rename = "dataType")]
        data_type: String,
    },
    DefineType {
        name: String,
        ty: Type,
    },
    DefineData {
        address: Addr,
        ty: String,
    },
    ClearData {
        address: Addr,
    },
    CreateFunction {
        address: Addr,
    },
    DeleteFunction {
        address: Addr,
    },
    JumpTable {
        address: Addr,
        base: Addr,
        count: usize,
        index: String,
    },
    Undo,
    Redo,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditState {
    pub overrides: Overrides,
    pub types: TypeRegistry,
}
impl EditState {
    pub fn from_program(p: &Program) -> Self {
        Self {
            overrides: p.overrides.clone(),
            types: p.types.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub states: Vec<EditState>,
    pub cursor: usize,
}
impl History {
    pub fn new(p: &Program) -> Self {
        Self {
            states: vec![EditState::from_program(p)],
            cursor: 0,
        }
    }
    pub fn apply(&mut self, p: &Program, command: &Command) -> Result<(EditState, BTreeSet<Addr>)> {
        if matches!(command, Command::Undo) {
            if self.cursor == 0 {
                return Err("No hay cambios para deshacer".into());
            }
            self.cursor -= 1;
            return Ok((
                self.states[self.cursor].clone(),
                p.functions.keys().copied().collect(),
            ));
        }
        if matches!(command, Command::Redo) {
            if self.cursor + 1 >= self.states.len() {
                return Err("No hay cambios para rehacer".into());
            }
            self.cursor += 1;
            return Ok((
                self.states[self.cursor].clone(),
                p.functions.keys().copied().collect(),
            ));
        }
        let mut next = self.states[self.cursor].clone();
        let mut touched = BTreeSet::new();
        let mut require_function = |a: Addr| -> Result<()> {
            if !p.functions.contains_key(&a) {
                return Err("Función inexistente".into());
            }
            touched.insert(a);
            Ok(())
        };
        match command {
            Command::Rename { address, value } => {
                require_function(*address)?;
                if !identifier(value) {
                    return Err("Nombre de función inválido".into());
                }
                next.overrides.names.insert(*address, value.clone());
            }
            Command::Comment { address, value } => {
                if !p.instructions.contains_key(address) {
                    return Err("Instrucción inexistente".into());
                }
                if value.len() > 8000 {
                    return Err("Comentario muy largo".into());
                }
                next.overrides.comments.insert(*address, value.clone());
                for f in p.functions.values().filter(|f| f.members.contains(address)) {
                    touched.insert(f.entry);
                }
            }
            Command::FunctionComment { address, value } => {
                require_function(*address)?;
                if value.len() > 8000 {
                    return Err("Comentario muy largo".into());
                }
                next.overrides
                    .function_comments
                    .insert(*address, value.clone());
            }
            Command::Signature { address, value } => {
                require_function(*address)?;
                if !valid_signature(value) {
                    return Err("Firma C fuera del subconjunto soportado".into());
                }
                next.overrides.signatures.insert(*address, value.clone());
            }
            Command::Bookmark { address, value } => {
                if p.region(*address).is_none() {
                    return Err("Dirección no mapeada".into());
                }
                if value.len() > 8000 {
                    return Err("Marcador muy largo".into());
                }
                next.overrides.bookmarks.insert(*address, value.clone());
            }
            Command::Variable {
                address,
                variable_id,
                value,
                data_type,
            } => {
                require_function(*address)?;
                if !p.functions[address]
                    .variables
                    .iter()
                    .any(|v| &v.id == variable_id)
                {
                    return Err("Variable inexistente".into());
                }
                if !value.is_empty() {
                    if !identifier(value) {
                        return Err("Nombre de variable inválido".into());
                    }
                    next.overrides
                        .variable_names
                        .insert(variable_id.clone(), value.clone());
                }
                if !data_type.is_empty() {
                    let t = data_type.trim_start_matches('/');
                    if !next.types.0.contains_key(t) {
                        return Err("Tipo desconocido".into());
                    }
                    next.overrides
                        .variable_types
                        .insert(variable_id.clone(), t.into());
                }
            }
            Command::JumpTable {
                address,
                base,
                count,
                index,
            } => {
                if !p
                    .instructions
                    .get(address)
                    .is_some_and(|i| matches!(i.flow, Flow::Indirect | Flow::Switch { .. }))
                    || !(1..=256).contains(count)
                    || !identifier(index)
                {
                    return Err(
                        "Tabla requiere salto indirecto, índice de registro y 1..256 destinos"
                            .into(),
                    );
                }
                next.overrides.jump_tables.insert(
                    *address,
                    crate::core::JumpTable {
                        base: *base,
                        count: *count,
                        index: index.clone(),
                    },
                );
                touched.extend(p.functions.keys());
            }
            Command::DefineType { name, ty } => {
                next.types.insert(name.clone(), ty.clone())?;
                touched.extend(p.functions.keys());
            }
            Command::DefineData { address, ty } => {
                let size = next.types.size(ty)?;
                if size == 0 {
                    return Err("Dato vacío".into());
                }
                let end = address.0.checked_add(size).ok_or("Dato desbordado")?;
                let r = p.region(*address).ok_or("Memoria no mapeada")?;
                if end as u128 > r.range.start.0 as u128 + r.range.size as u128 {
                    return Err("Dato cruza memoria no mapeada".into());
                }
                if next.overrides.data.values().any(|d| {
                    d.range.start != *address
                        && d.range.start.0 < end
                        && (d.range.start.0 as u128 + d.range.size as u128) > address.0 as u128
                }) {
                    return Err("Datos superpuestos".into());
                }
                next.overrides.data.insert(
                    *address,
                    Data {
                        id: String::new(),
                        revision: 0,
                        space: r.space.clone(),
                        range: Range {
                            start: *address,
                            size,
                        },
                        ty: ty.clone(),
                        value: String::new(),
                        provenance: "user".into(),
                    },
                );
                touched.extend(p.functions.keys());
            }
            Command::ClearData { address } => {
                if next.overrides.data.remove(address).is_none() {
                    return Err("No existe dato definido por el usuario".into());
                }
                touched.extend(p.functions.keys());
            }
            Command::CreateFunction { address } => {
                if !p.executable(*address) {
                    return Err("Entrada no ejecutable".into());
                }
                if let Some((_, i)) = p.instructions.range(..*address).next_back() {
                    if i.next().is_some_and(|end| end > *address) {
                        return Err("Entrada interior a una instrucción".into());
                    }
                }
                next.overrides.excluded_functions.remove(address);
                next.overrides.functions.insert(*address);
                touched.extend(p.functions.keys());
                touched.insert(*address);
            }
            Command::DeleteFunction { address } => {
                require_function(*address)?;
                next.overrides.functions.remove(address);
                next.overrides.excluded_functions.insert(*address);
                touched.extend(p.functions.keys());
            }
            _ => {}
        }
        next.types.validate()?;
        if next != self.states[self.cursor] {
            self.states.truncate(self.cursor + 1);
            self.states.push(next.clone());
            self.cursor += 1;
        }
        Ok((next, touched))
    }
}
