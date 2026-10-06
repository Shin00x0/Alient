//! N09: validated type registry, aggregate layout and user constraints.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: String,
    pub offset: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Type {
    Int {
        bits: u16,
        signed: bool,
    },
    Pointer {
        to: String,
    },
    Array {
        element: String,
        count: u64,
    },
    Struct {
        fields: Vec<Field>,
        size: u64,
    },
    Union {
        fields: Vec<Field>,
        size: u64,
    },
    Enum {
        bits: u16,
        values: BTreeMap<String, i64>,
    },
    Void,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeRegistry(pub BTreeMap<String, Type>);
impl Default for TypeRegistry {
    fn default() -> Self {
        let mut m = BTreeMap::new();
        m.insert("void".into(), Type::Void);
        for bits in [8, 16, 32, 64] {
            for signed in [false, true] {
                m.insert(
                    format!("{}int{bits}_t", if signed { "" } else { "u" }),
                    Type::Int { bits, signed },
                );
            }
        }
        m.insert(
            "uint8_ptr".into(),
            Type::Pointer {
                to: "uint8_t".into(),
            },
        );
        Self(m)
    }
}
impl TypeRegistry {
    pub fn size(&self, name: &str) -> Result<u64> {
        self.size_inner(name, &mut vec![])
    }
    fn size_inner(&self, name: &str, seen: &mut Vec<String>) -> Result<u64> {
        if seen.iter().any(|s| s == name) {
            return Err("Tipo recursivo por valor".into());
        }
        seen.push(name.into());
        let size = match self.0.get(name).ok_or("Tipo desconocido")? {
            Type::Int { bits, .. } | Type::Enum { bits, .. } => {
                if ![8, 16, 32, 64].contains(bits) {
                    return Err("Ancho de tipo inválido".into());
                }
                u64::from(*bits) / 8
            }
            Type::Pointer { to } => {
                if !self.0.contains_key(to) {
                    return Err("Puntero a tipo inexistente".into());
                }
                8
            }
            Type::Void => 0,
            Type::Array { element, count } => self
                .size_inner(element, seen)?
                .checked_mul(*count)
                .ok_or("Array desbordado")?,
            Type::Struct { size, fields } | Type::Union { size, fields } => {
                for f in fields {
                    self.size_inner(&f.ty, seen)?;
                }
                *size
            }
        };
        seen.pop();
        Ok(size)
    }
    pub fn validate(&self) -> Result<()> {
        for (name, ty) in &self.0 {
            if !identifier(name) {
                return Err("Nombre de tipo inválido".into());
            }
            self.size(name)?;
            if let Type::Enum { bits, values } = ty {
                if values.iter().any(|(n, v)| {
                    !identifier(n)
                        || (*bits < 64
                            && ((*v as i128) < -(1i128 << (*bits - 1))
                                || (*v as i128) > ((1i128 << *bits) - 1)))
                }) {
                    return Err("Enumerador fuera de rango o nombre inválido".into());
                }
            }
            if let Type::Struct { fields, size } | Type::Union { fields, size } = ty {
                let mut spans = vec![];
                let mut names = std::collections::BTreeSet::new();
                for f in fields {
                    if !identifier(&f.name) || !names.insert(&f.name) {
                        return Err("Campo inválido".into());
                    }
                    let n = self.size_inner(&f.ty, &mut vec![name.clone()])?;
                    let end = f.offset.checked_add(n).ok_or("Campo desbordado")?;
                    if n == 0 || (matches!(ty, Type::Union { .. }) && f.offset != 0) || end > *size
                    {
                        return Err("Campo fuera del tipo".into());
                    }
                    if matches!(ty, Type::Struct { .. })
                        && spans.iter().any(|(a, b)| f.offset < *b && end > *a)
                    {
                        return Err("Campos superpuestos".into());
                    }
                    spans.push((f.offset, end));
                }
            }
        }
        Ok(())
    }
    pub fn insert(&mut self, name: String, ty: Type) -> Result<()> {
        let mut draft = self.clone();
        draft.0.insert(name, ty);
        draft.validate()?;
        *self = draft;
        Ok(())
    }
}
pub fn identifier(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|v| v.is_ascii_alphabetic() || v == '_')
        && c.all(|v| v.is_ascii_alphanumeric() || v == '_')
}
