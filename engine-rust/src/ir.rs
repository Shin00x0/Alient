//! N06: width-aware, serializable IR. Unknown effects are barriers, never no-ops.
mod contract;
use crate::core::Addr;
pub use contract::Effects;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operand {
    Reg {
        name: String,
        bits: u16,
        offset: u16,
    },
    Imm {
        value: u64,
        bits: u16,
    },
    Mem {
        #[serde(default)]
        segment: Option<String>,
        base: Option<String>,
        index: Option<String>,
        scale: i32,
        displacement: i64,
        bits: u16,
    },
    Other(String),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Expr {
    Const {
        value: u64,
        bits: u16,
    },
    Var {
        name: String,
        bits: u16,
    },
    Binary {
        op: String,
        left: Box<Expr>,
        right: Box<Expr>,
        bits: u16,
    },
    Load {
        address: Box<Expr>,
        bits: u16,
    },
    Compare {
        op: String,
        left: Box<Expr>,
        right: Box<Expr>,
        bits: u16,
    },
    Condition(String),
    Unknown(String),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Statement {
    Assign {
        dst: String,
        value: Expr,
    },
    Store {
        address: Expr,
        value: Expr,
        bits: u16,
    },
    Flags {
        op: String,
        left: Expr,
        right: Expr,
        bits: u16,
    },
    Call {
        target: Expr,
    },
    Branch {
        condition: Expr,
        target: Addr,
    },
    Jump {
        target: Expr,
    },
    /// Typed opaque operation for FP, SIMD, and architectural special instructions.
    /// Values wider than the scalar IR are never coerced into integers.
    Intrinsic {
        operation: String,
        domain: String,
        outputs: Vec<String>,
        inputs: Vec<String>,
        element_bits: u16,
        lanes: u16,
        reads_memory: bool,
        writes_memory: bool,
        may_trap: bool,
    },
    Return,
    /// Architectural stop/exception boundary. Handler/resume behavior is outside this IR.
    Stop {
        instruction: String,
    },
    Nop,
    Unknown {
        description: String,
    },
}
pub fn mask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
pub fn constant(v: u64, bits: u16) -> Expr {
    Expr::Const {
        value: v & mask(bits),
        bits,
    }
}
pub fn var(name: &str, bits: u16) -> Expr {
    Expr::Var {
        name: name.into(),
        bits,
    }
}
pub fn binary(op: &str, left: Expr, right: Expr, bits: u16) -> Expr {
    Expr::Binary {
        op: op.into(),
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}
pub fn condition_flags(code: &str) -> Option<&'static [&'static str]> {
    match code.to_ascii_lowercase().as_str() {
        "e" | "z" | "eq" | "ne" | "nz" => Some(&["zf"]),
        "a" | "nbe" | "hi" => Some(&["cf", "zf"]),
        "ae" | "nb" | "nc" | "cs" | "hs" | "cc" | "lo" => Some(&["cf"]),
        "b" | "c" | "nae" | "be" | "na" | "ls" => Some(&["cf", "zf"]),
        "g" | "nle" | "gt" | "ge" | "nl" | "l" | "nge" | "lt" | "le" | "ng" => {
            Some(&["zf", "sf", "of"])
        }
        "o" | "no" => Some(&["of"]),
        "s" | "ns" | "mi" | "pl" => Some(&["sf"]),
        "p" | "pe" | "np" | "po" => Some(&["pf"]),
        "vs" | "vc" => Some(&["of"]),
        "al" | "nv" => Some(&[]),
        _ => None,
    }
}
fn flag(values: &BTreeMap<String, u64>, name: &str) -> Option<bool> {
    values
        .get(&format!("__flag_{name}"))
        .map(|value| value & 1 != 0)
}
/// Computes the architectural integer flags for an operation whose operands are known.
/// The result is deliberately limited to operations lifted by the scalar IR.
pub fn evaluate_flags(op: &str, left: u64, right: u64, bits: u16) -> Option<BTreeMap<String, u64>> {
    if !(1..=64).contains(&bits) { return None; }
    let mask = mask(bits);
    let a = left & mask;
    let b = right & mask;
    let result = binary(op, constant(a, bits), constant(b, bits), bits).eval(&BTreeMap::new())?;
    let sign = 1u64 << (bits - 1);
    let (cf, of) = match op {
        "+" => (((a as u128 + b as u128) > mask as u128) as u64, (((!(a ^ b) & (a ^ result)) & sign) != 0) as u64),
        "-" => ((a < b) as u64, ((((a ^ b) & (a ^ result)) & sign) != 0) as u64),
        "&" | "|" | "^" => (0, 0),
        "<<" | ">>" | "asr" => {
            if b >= bits as u64 { return None; }
            (0, 0)
        }
        _ => return None,
    };
    let mut flags = BTreeMap::new();
    flags.insert("__flags".into(), result);
    flags.insert("__flag_cf".into(), cf);
    flags.insert("__flag_zf".into(), (result == 0) as u64);
    flags.insert("__flag_sf".into(), ((result & sign) != 0) as u64);
    flags.insert("__flag_of".into(), of);
    flags.insert("__flag_pf".into(), ((result as u8).count_ones() % 2 == 0) as u64);
    Some(flags)
}
pub fn evaluate_condition(code: &str, values: &BTreeMap<String, u64>) -> Option<bool> {
    let c = code.to_ascii_lowercase();
    let zf = || flag(values, "zf");
    let cf = || flag(values, "cf");
    let sf = || flag(values, "sf");
    let of = || flag(values, "of");
    let pf = || flag(values, "pf");
    Some(match c.as_str() {
        "e" | "z" | "eq" => zf()?,
        "ne" | "nz" => !zf()?,
        "a" | "nbe" | "hi" => !cf()? && !zf()?,
        "ae" | "nb" | "nc" | "cs" | "hs" => !cf()?,
        "cc" | "lo" => !cf()?,
        "b" | "c" | "nae" => cf()?,
        "be" | "na" | "ls" => cf()? || zf()?,
        "g" | "nle" | "gt" => !zf()? && sf()? == of()?,
        "ge" | "nl" => sf()? == of()?,
        "l" | "nge" | "lt" => sf()? != of()?,
        "le" | "ng" => zf()? || sf()? != of()?,
        "o" | "vs" => of()?,
        "no" | "vc" => !of()?,
        "s" | "mi" => sf()?,
        "ns" | "pl" => !sf()?,
        "p" | "pe" => pf()?,
        "np" | "po" => !pf()?,
        "al" => true,
        "nv" => false,
        _ => return None,
    })
}
impl Expr {
    pub fn bits(&self) -> u16 {
        match self {
            Self::Const { bits, .. }
            | Self::Var { bits, .. }
            | Self::Binary { bits, .. }
            | Self::Load { bits, .. }
            | Self::Compare { bits, .. } => *bits,
            Self::Condition(_) => 1,
            Self::Unknown(_) => 64,
        }
    }
    pub fn reads(&self) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        match self {
            Self::Var { name, .. } => {
                s.insert(name.clone());
            }
            Self::Binary { left, right, .. } | Self::Compare { left, right, .. } => {
                s.extend(left.reads());
                s.extend(right.reads());
            }
            Self::Load { address, .. } => {
                s.extend(address.reads());
                s.insert("__memory".into());
            }
            Self::Condition(code) => {
                s.insert("__flags".into());
                if let Some(flags) = condition_flags(code) {
                    s.extend(flags.iter().map(|flag| format!("__flag_{flag}")));
                }
            }
            _ => {}
        }
        s
    }
    pub fn eval(&self, values: &BTreeMap<String, u64>) -> Option<u64> {
        if !(1..=64).contains(&self.bits()) {
            return None;
        }
        match self {
            Self::Const { value, bits } => Some(value & mask(*bits)),
            Self::Var { name, bits } => values.get(name).map(|n| n & mask(*bits)),
            Self::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let a = left.eval(values)?;
                let b = right.eval(values)?;
                Some(
                    match op.as_str() {
                        "+" => a.wrapping_add(b),
                        "-" => a.wrapping_sub(b),
                        "*" => a.wrapping_mul(b),
                        "&" => a & b,
                        "|" => a | b,
                        "^" => a ^ b,
                        "<<" => a.checked_shl(u32::try_from(b).ok()?)?,
                        ">>" => a.checked_shr(u32::try_from(b).ok()?)?,
                        "asr" => {
                            let shift = 64 - *bits;
                            ((a << shift) as i64 >> shift).checked_shr(u32::try_from(b).ok()?)?
                                as u64
                        }
                        _ => return None,
                    } & mask(*bits),
                )
            }
            Self::Compare {
                op,
                left,
                right,
                bits,
            } => {
                let a = left.eval(values)? & mask(*bits);
                let b = right.eval(values)? & mask(*bits);
                let signed = |v: u64| ((v << (64 - *bits)) as i64) >> (64 - *bits);
                Some(match op.as_str() {
                    "==" => a == b,
                    "!=" => a != b,
                    "<u" => a < b,
                    ">=u" => a >= b,
                    ">u" => a > b,
                    "<=u" => a <= b,
                    "<s" => signed(a) < signed(b),
                    ">=s" => signed(a) >= signed(b),
                    ">s" => signed(a) > signed(b),
                    "<=s" => signed(a) <= signed(b),
                    _ => return None,
                } as u64)
            }
            Self::Condition(code) => evaluate_condition(code, values).map(u64::from),
            _ => None,
        }
    }
    pub fn simplify(&self, values: &BTreeMap<String, u64>) -> Self {
        if let Some(v) = self.eval(values) {
            return constant(
                v,
                if matches!(self, Self::Compare { .. }) {
                    1
                } else {
                    self.bits()
                },
            );
        }
        match self {
            Self::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let l = left.simplify(values);
                let r = right.simplify(values);
                let rv = r.eval(&BTreeMap::new());
                if op == "&" {
                    if let Some(mask_value) = rv {
                        for narrow in [8, 16, 32] {
                            if mask_value == mask(narrow) && *bits >= narrow {
                                if l.bits() <= narrow {
                                    return l;
                                }
                                if let Self::Var { name, .. } = &l {
                                    return var(name, narrow);
                                }
                                return binary(op, l, r, narrow);
                            }
                        }
                    }
                }
                if l.bits() <= *bits
                    && ((["+", "-", "|", "^", "<<", ">>"].contains(&op.as_str()) && rv == Some(0))
                        || (op == "*" && rv == Some(1))
                        || (op == "&" && rv == Some(mask(*bits))))
                {
                    return l;
                }
                if op == "&" && rv == Some(mask(*bits)) && l.bits() <= *bits {
                    return l;
                }
                binary(op, l, r, *bits)
            }
            _ => self.clone(),
        }
    }
}
impl Statement {
    pub fn reads(&self) -> BTreeSet<String> {
        match self {
            Self::Assign { value, .. } => value.reads(),
            Self::Store { address, value, .. } => {
                address.reads().union(&value.reads()).cloned().collect()
            }
            Self::Flags { left, right, .. } => {
                left.reads().union(&right.reads()).cloned().collect()
            }
            Self::Call { target } | Self::Jump { target } => target.reads(),
            Self::Branch { condition, .. } => condition.reads(),
            Self::Intrinsic {
                inputs,
                reads_memory,
                ..
            } => {
                let mut reads = inputs.iter().cloned().collect::<BTreeSet<_>>();
                if *reads_memory {
                    reads.insert("__memory".into());
                }
                reads
            }
            _ => BTreeSet::new(),
        }
    }
    pub fn writes(&self) -> Vec<String> {
        match self {
            Self::Assign { dst, .. } => vec![dst.clone()],
            Self::Store { .. } => vec!["__memory".into()],
            Self::Flags { .. } => [
                "__flags",
                "__flag_cf",
                "__flag_zf",
                "__flag_sf",
                "__flag_of",
                "__flag_pf",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            Self::Intrinsic {
                outputs,
                writes_memory,
                ..
            } => {
                let mut writes = outputs.clone();
                if *writes_memory {
                    writes.push("__memory".into());
                }
                writes
            }
            _ => vec![],
        }
    }
}
pub fn operand_expr(o: &Operand) -> Expr {
    match o {
        Operand::Reg { name, .. } if name == "zero" => constant(0, 64),
        Operand::Reg { name, bits, offset } => {
            if *offset == 0 {
                var(name, *bits)
            } else {
                binary(">>", var(name, 64), constant(*offset as u64, 64), *bits)
            }
        }
        Operand::Imm { value, bits } => constant(*value, *bits),
        Operand::Mem { bits, .. } => Expr::Load {
            address: Box::new(memory_address(o)),
            bits: *bits,
        },
        Operand::Other(v) => Expr::Unknown(v.clone()),
    }
}
pub fn memory_address(o: &Operand) -> Expr {
    if let Operand::Mem {
        segment,
        base,
        index,
        scale,
        displacement,
        ..
    } = o
    {
        let mut e = base.as_ref().map_or(constant(0, 64), |v| var(v, 64));
        if let Some(i) = index {
            e = binary(
                "+",
                e,
                binary("*", var(i, 64), constant(*scale as u64, 64), 64),
                64,
            );
        }
        let offset = binary("+", e, constant(*displacement as u64, 64), 64);
        if let Some(segment) = segment {
            binary("+", var(&format!("{segment}_base"), 64), offset, 64)
        } else {
            offset
        }
    } else {
        Expr::Unknown("not-memory".into())
    }
}
pub fn assign(o: &Operand, value: Expr) -> Statement {
    match o {
        Operand::Reg { name, bits, offset } => {
            if !(1..=64).contains(bits) || *offset as u32 + *bits as u32 > 64 {
                return Statement::Unknown {
                    description: "Subregistro fuera del contenedor de 64 bits".into(),
                };
            }
            if name == "zero" {
                return Statement::Nop;
            }
            let value = if *bits < 32 || *offset != 0 {
                let clear = !(mask(*bits) << *offset);
                binary(
                    "|",
                    binary("&", var(name, 64), constant(clear, 64), 64),
                    binary(
                        "<<",
                        binary("&", value, constant(mask(*bits), 64), 64),
                        constant(*offset as u64, 64),
                        64,
                    ),
                    64,
                )
            } else {
                binary("&", value, constant(mask(*bits), 64), 64)
            };
            Statement::Assign {
                dst: name.clone(),
                value,
            }
        }
        Operand::Mem { bits, .. } => Statement::Store {
            address: memory_address(o),
            value,
            bits: *bits,
        },
        _ => Statement::Unknown {
            description: "Destino no soportado".into(),
        },
    }
}
