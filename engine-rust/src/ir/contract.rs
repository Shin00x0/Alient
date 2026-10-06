//! Checked scalar IR contract and conservative effects, independent of an ABI.
use super::*;
use crate::Result;
fn width(bits: u16) -> Result<()> {
    if (1..=64).contains(&bits) {
        Ok(())
    } else {
        Err(format!("Ancho IR inválido: {bits}"))
    }
}
impl Expr {
    pub fn validate(&self) -> Result<()> {
        self.validate_depth(0)
    }
    fn validate_depth(&self, depth: usize) -> Result<()> {
        if depth > 128 {
            return Err("Expresión IR demasiado profunda".into());
        }
        width(self.bits())?;
        match self {
            Self::Binary {
                op, left, right, ..
            }
            | Self::Compare {
                op, left, right, ..
            } => {
                let allowed = if matches!(self, Self::Compare { .. }) {
                    [
                        "==", "!=", "<u", ">=u", ">u", "<=u", "<s", ">=s", ">s", "<=s",
                    ]
                    .as_slice()
                } else {
                    ["+", "-", "*", "&", "|", "^", "<<", ">>", "asr"].as_slice()
                };
                if !allowed.contains(&op.as_str()) {
                    return Err(format!("Operación IR no soportada: {op}"));
                }
                left.validate_depth(depth + 1)?;
                right.validate_depth(depth + 1)?;
            }
            Self::Load { address, bits } => {
                memory(address, *bits, depth)?;
            }
            Self::Condition(code) if condition_flags(code).is_none() => {
                return Err(format!("Condición de flags desconocida: {code}"))
            }
            Self::Var { name, .. } if name.is_empty() => return Err("Registro IR vacío".into()),
            _ => {}
        }
        Ok(())
    }
    fn memory_read(&self) -> bool {
        match self {
            Self::Load { .. } => true,
            Self::Binary { left, right, .. } | Self::Compare { left, right, .. } => {
                left.memory_read() || right.memory_read()
            }
            Self::Unknown(_) => true,
            _ => false,
        }
    }
    pub fn contains_unknown(&self) -> bool {
        match self {
            Self::Unknown(_) => true,
            Self::Binary { left, right, .. } | Self::Compare { left, right, .. } => {
                left.contains_unknown() || right.contains_unknown()
            }
            Self::Load { address, .. } => address.contains_unknown(),
            _ => false,
        }
    }
}
fn memory(address: &Expr, bits: u16, depth: usize) -> Result<()> {
    width(bits)?;
    if !bits.is_multiple_of(8) || address.bits() != 64 {
        return Err("Acceso de memoria IR inválido".into());
    }
    address.validate_depth(depth + 1)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Effects {
    pub reads: BTreeSet<String>,
    pub writes: BTreeSet<String>,
    pub reads_memory: bool,
    pub writes_memory: bool,
    pub unknown_registers: bool,
    pub control: String,
    pub may_trap: bool,
}
impl Statement {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Assign { dst, value } => {
                if dst.is_empty() {
                    return Err("Destino IR vacío".into());
                }
                value.validate()
            }
            Self::Store {
                address,
                value,
                bits,
            } => {
                memory(address, *bits, 0)?;
                value.validate()
            }
            Self::Flags {
                op,
                left,
                right,
                bits,
            } => binary(op, left.clone(), right.clone(), *bits).validate(),
            Self::Call { target } | Self::Jump { target } => {
                target.validate()?;
                if target.bits() != 64 {
                    return Err("Destino de control IR no es de 64 bits".into());
                }
                Ok(())
            }
            Self::Branch { condition, .. } => condition.validate(),
            Self::Intrinsic {
                operation,
                domain,
                outputs,
                inputs,
                element_bits,
                lanes,
                ..
            } => {
                if operation.is_empty() || !["float", "simd", "special"].contains(&domain.as_str())
                {
                    return Err("Intrínseca IR inválida".into());
                }
                if outputs.iter().any(|r| r.is_empty())
                    || inputs.iter().any(|r| r.is_empty())
                    || !(1..=64).contains(element_bits)
                    || !(1..=256).contains(lanes)
                {
                    return Err("Metadatos de intrínseca IR inválidos".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    pub fn effects(&self) -> Effects {
        let expressions: Vec<&Expr> = match self {
            Self::Assign { value, .. } => vec![value],
            Self::Store { address, value, .. } => vec![address, value],
            Self::Flags { left, right, .. } => vec![left, right],
            Self::Call { target } | Self::Jump { target } => vec![target],
            Self::Branch { condition, .. } => vec![condition],
            _ => vec![],
        };
        let unknown = matches!(self, Self::Unknown { .. } | Self::Call { .. })
            || expressions.iter().any(|e| e.contains_unknown());
        let reads_memory = unknown
            || expressions.iter().any(|e| e.memory_read())
            || matches!(
                self,
                Self::Intrinsic {
                    reads_memory: true,
                    ..
                }
            );
        let writes_memory = unknown
            || matches!(
                self,
                Self::Store { .. }
                    | Self::Intrinsic {
                        writes_memory: true,
                        ..
                    }
            );
        Effects {
            reads: self.reads(),
            writes: self.writes().into_iter().collect(),
            reads_memory,
            writes_memory,
            unknown_registers: unknown,
            control: match self {
                Self::Call { .. } => "call",
                Self::Jump { .. } => "jump",
                Self::Branch { .. } => "branch",
                Self::Return => "return",
                Self::Stop { .. } => "stop",
                Self::Unknown { .. } => "unknown",
                _ => "next",
            }
            .into(),
            may_trap: reads_memory
                || writes_memory
                || matches!(
                    self,
                    Self::Stop { .. } | Self::Intrinsic { may_trap: true, .. }
                ),
        }
    }
}
