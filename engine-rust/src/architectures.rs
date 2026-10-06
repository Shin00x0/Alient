//! N04: real ARM64/x86-64 decoding with Capstone; independent explicit IR lifting.
use crate::{core::*, ir::*, Result};
mod opcodes;
use capstone::{
    arch::{
        arm64::{Arm64Extender, Arm64OperandType, Arm64Shift},
        x86::X86OperandType,
    },
    prelude::*,
};
use opcodes::{is_fp_compare, is_fp_simd, is_special, may_trap};
pub struct Decoder {
    cs: Capstone,
    arm: bool,
}
pub fn register(name: &str) -> Operand {
    if name == "xzr" || name == "wzr" {
        return Operand::Reg {
            name: "zero".into(),
            bits: if name == "wzr" { 32 } else { 64 },
            offset: 0,
        };
    }
    let mut bits = 64;
    let mut offset = 0;
    let mut canonical = match name {
        "fp" => "x29".into(),
        "lr" => "x30".into(),
        _ => name.to_string(),
    };
    if name == "wsp" {
        canonical = "sp".into();
        bits = 32;
    } else if name.starts_with('w') && name[1..].parse::<u8>().is_ok() {
        canonical = format!("x{}", &name[1..]);
        bits = 32;
    }
    for (full, dword, word, low, high) in [
        ("rax", "eax", "ax", "al", "ah"),
        ("rbx", "ebx", "bx", "bl", "bh"),
        ("rcx", "ecx", "cx", "cl", "ch"),
        ("rdx", "edx", "dx", "dl", "dh"),
        ("rsp", "esp", "sp", "spl", ""),
        ("rbp", "ebp", "bp", "bpl", ""),
        ("rsi", "esi", "si", "sil", ""),
        ("rdi", "edi", "di", "dil", ""),
    ] {
        if [full, dword, word, low, high].contains(&name) && !name.is_empty() {
            canonical = full.into();
            bits = if name == full {
                64
            } else if name == dword {
                32
            } else if name == word {
                16
            } else {
                8
            };
            offset = if name == high { 8 } else { 0 };
        }
    }
    if name.starts_with('r') && name.len() > 2 {
        let last = name.chars().last().unwrap();
        if ['d', 'w', 'b'].contains(&last) && name[1..name.len() - 1].parse::<u8>().is_ok() {
            canonical = name[..name.len() - 1].into();
            bits = match last {
                'd' => 32,
                'w' => 16,
                _ => 8,
            };
        }
    }
    if name.starts_with('v')
        || name.starts_with('q')
        || name.starts_with("xmm")
        || name.starts_with("ymm")
    {
        return Operand::Other(name.into());
    }
    Operand::Reg {
        name: canonical,
        bits,
        offset,
    }
}
impl Decoder {
    pub fn new(architecture: &str) -> Result<Self> {
        let arm = architecture.starts_with("AARCH64");
        let cs = if arm {
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
        } else {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
        }
        .map_err(|e| e.to_string())?;
        Ok(Self { cs, arm })
    }
    pub fn decode(&self, bytes: &[u8], address: Addr) -> Result<Instruction> {
        let insns = self
            .cs
            .disasm_count(bytes, address.0, 1)
            .map_err(|e| e.to_string())?;
        let insn = insns.iter().next().ok_or("Bytes no decodificables")?;
        let detail = self.cs.insn_detail(insn).map_err(|e| e.to_string())?;
        let arch = detail.arch_detail();
        let mnemonic = insn.mnemonic().unwrap_or("unknown").to_string();
        let text = format!("{} {}", mnemonic, insn.op_str().unwrap_or(""))
            .trim()
            .to_string();
        let mut operands = vec![];
        let mut shifts = vec![];
        let mut writeback = false;
        let mut flags = false;
        let mut invalid = false;
        if self.arm {
            let d = arch.arm64().ok_or("Detalle ARM64 ausente")?;
            writeback = d.writeback();
            flags = d.update_flags();
            for o in d.operands() {
                if o.ext != Arm64Extender::ARM64_EXT_INVALID {
                    invalid = true;
                }
                shifts.push(o.shift);
                operands.push(match o.op_type {
                    Arm64OperandType::Reg(r) => {
                        let name = self.cs.reg_name(r).unwrap_or_default();
                        if name == "sp" {
                            Operand::Reg {
                                name: "sp".into(),
                                bits: 64,
                                offset: 0,
                            }
                        } else {
                            register(&name)
                        }
                    }
                    Arm64OperandType::Imm(v) => Operand::Imm {
                        value: v as u64,
                        bits: 64,
                    },
                    Arm64OperandType::Mem(m) => Operand::Mem {
                        segment: None,
                        base: self.cs.reg_name(m.base()),
                        index: self.cs.reg_name(m.index()),
                        scale: 1,
                        displacement: m.disp() as i64,
                        bits: 64,
                    },
                    _ => {
                        if !is_special(true, &mnemonic) {
                            invalid = true;
                        }
                        Operand::Other("ARM64 special operand".into())
                    }
                });
            }
        } else {
            let d = arch.x86().ok_or("Detalle x86 ausente")?;
            if d.prefix().iter().any(|b| [0xf0, 0x67].contains(b)) {
                invalid = true;
            }
            for o in d.operands() {
                operands.push(match o.op_type {
                    X86OperandType::Reg(r) => register(&self.cs.reg_name(r).unwrap_or_default()),
                    X86OperandType::Imm(v) => Operand::Imm {
                        value: v as u64,
                        bits: (o.size as u16 * 8).max(8),
                    },
                    X86OperandType::Mem(m) => {
                        // FS/GS bases are dynamic architectural inputs, never guessed from file bytes.
                        let segment = self
                            .cs
                            .reg_name(m.segment())
                            .filter(|s| s == "fs" || s == "gs");
                        let base = self.cs.reg_name(m.base());
                        let displacement = if base.as_deref() == Some("rip") {
                            address
                                .0
                                .wrapping_add(insn.bytes().len() as u64)
                                .wrapping_add(m.disp() as u64) as i64
                        } else {
                            m.disp()
                        };
                        Operand::Mem {
                            segment,
                            base: if base.as_deref() == Some("rip") {
                                None
                            } else {
                                base
                            },
                            index: self.cs.reg_name(m.index()),
                            scale: m.scale(),
                            displacement,
                            bits: o.size as u16 * 8,
                        }
                    }
                    _ => Operand::Other("invalid".into()),
                });
            }
        }
        let intrinsic_name = |o: &Operand| match o {
            Operand::Reg { name, .. } => name.clone(),
            Operand::Other(name) => name.clone(),
            Operand::Mem { .. } => "__memory".into(),
            Operand::Imm { value, .. } => format!("0x{value:x}"),
        };
        let intrinsic_lanes = |m: &str| -> (String, u16, u16) {
            let scalar = m.ends_with("ss") || m.ends_with("sd");
            let bits = if m.ends_with("sd") || m.contains("pd") {
                64
            } else if m.contains("ps") || m.ends_with("ss") {
                32
            } else {
                8
            };
            if scalar {
                ("float".into(), bits, 1)
            } else if m.contains("pd") {
                ("simd".into(), 64, 2)
            } else if m.contains("ps") {
                ("simd".into(), 32, 4)
            } else {
                ("simd".into(), bits, 16 / (bits / 8).max(1))
            }
        };
        let mut statements = vec![];
        let mut flow = Flow::Next;
        let mut supported = true;
        let value = |i: usize| -> Expr {
            let mut e = operands
                .get(i)
                .map_or(Expr::Unknown("missing operand".into()), operand_expr);
            if self.arm {
                let bits = e.bits();
                match shifts.get(i) {
                    Some(Arm64Shift::Lsl(n)) => e = binary("<<", e, constant(*n as u64, 64), bits),
                    Some(Arm64Shift::Lsr(n)) => e = binary(">>", e, constant(*n as u64, 64), bits),
                    Some(Arm64Shift::Asr(n)) => e = binary("asr", e, constant(*n as u64, 64), bits),
                    Some(Arm64Shift::Invalid) | None => {}
                    _ => e = Expr::Unknown("shift no soportado".into()),
                }
            }
            e
        };
        let dst = operands.first();
        let width = dst.map_or(64, |o| operand_expr(o).bits());
        let immediate_target = |i: usize| match operands.get(i) {
            Some(Operand::Imm { value, .. }) => Some(Addr(*value)),
            _ => None,
        };
        if ["ret", "retab", "retaa"].contains(&mnemonic.as_str()) {
            flow = Flow::Return;
            statements.push(Statement::Return);
            if mnemonic != "ret" {
                supported = false;
            }
        } else if ["call", "bl", "blr"].contains(&mnemonic.as_str()) {
            flow = Flow::Call(immediate_target(0));
            statements.push(Statement::Call { target: value(0) });
        } else if ["jmp", "b", "br"].contains(&mnemonic.as_str()) {
            flow = immediate_target(0).map_or(Flow::Indirect, Flow::Jump);
            statements.push(Statement::Jump { target: value(0) });
        } else if mnemonic.starts_with("b.")
            || (!self.arm && mnemonic.starts_with('j') && mnemonic != "jmp")
            || ["cbz", "cbnz", "tbz", "tbnz"].contains(&mnemonic.as_str())
        {
            let index = operands.len().saturating_sub(1);
            if let Some(target) = immediate_target(index) {
                flow = Flow::Branch(target);
                let condition = if mnemonic == "cbz" || mnemonic == "cbnz" {
                    Expr::Compare {
                        op: if mnemonic == "cbz" { "==" } else { "!=" }.into(),
                        left: Box::new(value(0)),
                        right: Box::new(constant(0, width)),
                        bits: width,
                    }
                } else if mnemonic == "tbz" || mnemonic == "tbnz" {
                    Expr::Compare {
                        op: if mnemonic == "tbz" { "==" } else { "!=" }.into(),
                        left: Box::new(binary(
                            "&",
                            value(0),
                            binary("<<", constant(1, 64), value(1), 64),
                            64,
                        )),
                        right: Box::new(constant(0, 64)),
                        bits: 64,
                    }
                } else {
                    Expr::Condition(
                        mnemonic
                            .trim_start_matches("b.")
                            .trim_start_matches('j')
                            .into(),
                    )
                };
                statements.push(Statement::Branch { condition, target });
            } else {
                supported = false;
                flow = Flow::Stop;
            }
        } else if ["nop", "endbr64", "endbr32"].contains(&mnemonic.as_str()) {
            statements.push(Statement::Nop);
        } else if ["ud2", "hlt", "int3", "brk"].contains(&mnemonic.as_str()) {
            statements.push(Statement::Stop {
                instruction: mnemonic.clone(),
            });
            flow = Flow::Stop;
        } else if is_fp_simd(self.arm, &mnemonic) {
            let compare = is_fp_compare(&mnemonic);
            let (domain, element_bits, lanes) = if self.arm {
                let name = operands.first().map(intrinsic_name).unwrap_or_default();
                let bits = if name.starts_with('d') { 64 } else { 32 };
                (
                    if name.starts_with('v') || name.starts_with('q') {
                        "simd".into()
                    } else {
                        "float".into()
                    },
                    bits,
                    1,
                )
            } else {
                intrinsic_lanes(&mnemonic)
            };
            let mut outputs = if compare {
                vec![]
            } else {
                operands.first().map(intrinsic_name).into_iter().collect()
            };
            let start = if compare { 0 } else { 1 };
            let mut inputs = operands
                .iter()
                .skip(start)
                .flat_map(|operand| {
                    let mut reads = vec![intrinsic_name(operand)];
                    if let Operand::Mem {
                        base,
                        index,
                        segment,
                        ..
                    } = operand
                    {
                        reads.extend(base.iter().cloned());
                        reads.extend(index.iter().cloned());
                        reads.extend(segment.iter().map(|segment| format!("{segment}_base")));
                    }
                    reads
                })
                .collect::<Vec<_>>();
            let destructive_x86 = !self.arm
                && !mnemonic.starts_with('v')
                && ![
                    "movss",
                    "movsd",
                    "movaps",
                    "movups",
                    "movdqa",
                    "movdqu",
                    "sqrtss",
                    "sqrtsd",
                    "sqrtps",
                    "sqrtpd",
                    "cvtsi2ss",
                    "cvtsi2sd",
                    "cvttss2si",
                    "cvttsd2si",
                    "cvtss2sd",
                    "cvtsd2ss",
                ]
                .contains(&mnemonic.as_str());
            if destructive_x86 {
                if let Some(dst) = operands.first() {
                    inputs.insert(0, intrinsic_name(dst));
                }
            }
            if compare {
                outputs.push("__flags".into());
            }
            statements.push(Statement::Intrinsic {
                operation: mnemonic.clone(),
                domain,
                outputs,
                inputs,
                element_bits,
                lanes,
                reads_memory: operands
                    .iter()
                    .skip(start)
                    .any(|o| matches!(o, Operand::Mem { .. })),
                writes_memory: false,
                may_trap: may_trap(&mnemonic),
            });
        } else if !self.arm && is_special(false, &mnemonic) {
            let outputs = match mnemonic.as_str() {
                "cpuid" => vec!["rax".into(), "rbx".into(), "rcx".into(), "rdx".into()],
                "rdtsc" | "rdtscp" => vec!["rax".into(), "rdx".into()],
                "xgetbv" => vec!["rax".into(), "rdx".into()],
                _ => operands.first().map(intrinsic_name).into_iter().collect(),
            };
            statements.push(Statement::Intrinsic {
                operation: mnemonic.clone(),
                domain: "special".into(),
                outputs,
                inputs: operands.iter().map(intrinsic_name).collect(),
                element_bits: 64,
                lanes: 1,
                reads_memory: false,
                writes_memory: false,
                may_trap: false,
            });
        } else if self.arm && is_special(true, &mnemonic) {
            statements.push(Statement::Intrinsic {
                operation: mnemonic.clone(),
                domain: "special".into(),
                outputs: if mnemonic == "mrs" {
                    operands.first().map(intrinsic_name).into_iter().collect()
                } else {
                    vec![]
                },
                inputs: operands
                    .iter()
                    .skip(if mnemonic == "mrs" { 1 } else { 0 })
                    .map(intrinsic_name)
                    .collect(),
                element_bits: 64,
                lanes: 1,
                reads_memory: false,
                writes_memory: false,
                may_trap: false,
            });
        } else if !self.arm
            && ["movzx", "movsx", "movsxd"].contains(&mnemonic.as_str())
            && operands.len() == 2
        {
            let source = value(1);
            let source_bits = source.bits();
            if source_bits >= width || ![8, 16, 32].contains(&source_bits) {
                supported = false;
            } else {
                let extended = if mnemonic == "movzx" {
                    source
                } else {
                    let shift = 64 - source_bits;
                    binary(
                        "asr",
                        binary("<<", source, constant(shift as u64, 64), 64),
                        constant(shift as u64, 64),
                        64,
                    )
                };
                statements.push(assign(dst.unwrap(), extended));
            }
        } else if ["mov", "movabs", "movz", "movn", "movk", "adr", "adrp"]
            .contains(&mnemonic.as_str())
            && operands.len() >= 2
        {
            let e = if mnemonic == "movn" {
                binary("^", value(1), constant(mask(width), width), width)
            } else if mnemonic == "movk" {
                let shift = match shifts.get(1) {
                    Some(Arm64Shift::Lsl(n)) => *n,
                    _ => 0,
                };
                binary(
                    "|",
                    binary("&", value(0), constant(!(0xffffu64 << shift), width), width),
                    value(1),
                    width,
                )
            } else {
                value(1)
            };
            statements.push(assign(dst.unwrap(), e));
        } else if mnemonic == "lea" && operands.len() == 2 {
            // LEA computes an offset; segment overrides do not participate in its result.
            let mut source = operands[1].clone();
            if let Operand::Mem { segment, .. } = &mut source {
                *segment = None;
            }
            statements.push(assign(dst.unwrap(), memory_address(&source)));
        } else if [
            "add", "adds", "sub", "subs", "and", "ands", "orr", "or", "eor", "xor", "mul", "imul",
            "lsl", "lsr", "asr", "shl", "shr", "sar",
        ]
        .contains(&mnemonic.as_str())
            && operands.len() >= 2
        {
            let op = match mnemonic.as_str() {
                "add" | "adds" => "+",
                "sub" | "subs" => "-",
                "and" | "ands" => "&",
                "orr" | "or" => "|",
                "eor" | "xor" => "^",
                "mul" | "imul" => "*",
                "lsl" | "shl" => "<<",
                "lsr" | "shr" => ">>",
                _ => "asr",
            };
            let (a, b) = if self.arm || operands.len() == 3 {
                (value(1), value(2))
            } else {
                (value(0), value(1))
            };
            if flags || !self.arm {
                statements.push(Statement::Flags {
                    op: op.into(),
                    left: a.clone(),
                    right: b.clone(),
                    bits: width,
                });
            }
            statements.push(assign(dst.unwrap(), binary(op, a, b, width)));
        } else if ["cmp", "cmn", "tst", "test"].contains(&mnemonic.as_str()) && operands.len() == 2
        {
            statements.push(Statement::Flags {
                op: match mnemonic.as_str() {
                    "cmp" => "-",
                    "cmn" => "+",
                    _ => "&",
                }
                .into(),
                left: value(0),
                right: value(1),
                bits: width,
            });
        } else if ["madd", "msub"].contains(&mnemonic.as_str()) && operands.len() == 4 {
            statements.push(assign(
                dst.unwrap(),
                binary(
                    if mnemonic == "madd" { "+" } else { "-" },
                    value(3),
                    binary("*", value(1), value(2), width),
                    width,
                ),
            ));
        } else if [
            "ldr", "ldur", "ldrb", "ldurb", "ldrh", "ldurh", "str", "stur", "strb", "sturb",
            "strh", "sturh", "ldp", "stp",
        ]
        .contains(&mnemonic.as_str())
            && self.arm
        {
            let pair = mnemonic == "ldp" || mnemonic == "stp";
            let mi = if pair { 2 } else { 1 };
            if let Some(mem @ Operand::Mem { base, index, .. }) = operands.get(mi) {
                if index.is_some() {
                    invalid = true;
                }
                let bits = if mnemonic.ends_with('b') {
                    8
                } else if mnemonic.ends_with('h') {
                    16
                } else {
                    width
                };
                let addr = memory_address(mem);
                let load = mnemonic.starts_with('l');
                for (k, operand) in operands.iter().enumerate().take(if pair { 2 } else { 1 }) {
                    let a = if k == 0 {
                        addr.clone()
                    } else {
                        binary("+", addr.clone(), constant((bits / 8) as u64, 64), 64)
                    };
                    if load {
                        statements.push(assign(
                            operand,
                            Expr::Load {
                                address: Box::new(a),
                                bits,
                            },
                        ));
                    } else {
                        statements.push(Statement::Store {
                            address: a,
                            value: value(k),
                            bits,
                        });
                    }
                }
                if writeback {
                    if let Some(base) = base {
                        let updated = if let Some(post) = operands.get(mi + 1) {
                            binary("+", var(base, 64), operand_expr(post), 64)
                        } else {
                            addr
                        };
                        statements.push(Statement::Assign {
                            dst: base.clone(),
                            value: updated,
                        });
                    } else {
                        invalid = true;
                    }
                }
            } else {
                supported = false;
            }
        } else if !self.arm && ["push", "pop"].contains(&mnemonic.as_str()) && operands.len() == 1 {
            if width == 16
                || (mnemonic == "pop" && matches!(dst,Some(Operand::Reg {name,..}) if name=="rsp"))
            {
                invalid = true;
            }
            if mnemonic == "push" {
                statements.push(Statement::Store {
                    address: binary("-", var("rsp", 64), constant(8, 64), 64),
                    value: value(0),
                    bits: 64,
                });
                statements.push(Statement::Assign {
                    dst: "rsp".into(),
                    value: binary("-", var("rsp", 64), constant(8, 64), 64),
                });
            } else {
                statements.push(assign(
                    dst.unwrap(),
                    Expr::Load {
                        address: Box::new(var("rsp", 64)),
                        bits: 64,
                    },
                ));
                statements.push(Statement::Assign {
                    dst: "rsp".into(),
                    value: binary("+", var("rsp", 64), constant(8, 64), 64),
                });
            }
        } else if !self.arm && mnemonic == "leave" {
            statements.push(Statement::Assign {
                dst: "rsp".into(),
                value: binary("+", var("rbp", 64), constant(8, 64), 64),
            });
            statements.push(Statement::Assign {
                dst: "rbp".into(),
                value: Expr::Load {
                    address: Box::new(var("rbp", 64)),
                    bits: 64,
                },
            });
        } else {
            supported = false;
        }
        if operands.iter().any(|o| matches!(o, Operand::Other(_)))
            && !statements
                .iter()
                .all(|s| matches!(s, Statement::Intrinsic { .. }))
        {
            invalid = true;
        }
        fn unknown(e: &Expr) -> bool {
            match e {
                Expr::Unknown(_) => true,
                Expr::Binary { left, right, .. } | Expr::Compare { left, right, .. } => {
                    unknown(left) || unknown(right)
                }
                Expr::Load { address, .. } => unknown(address),
                _ => false,
            }
        }
        invalid |= statements.iter().any(|s| match s {
            Statement::Assign { value, .. } => unknown(value),
            Statement::Store { address, value, .. } => unknown(address) || unknown(value),
            Statement::Flags { left, right, .. } => unknown(left) || unknown(right),
            Statement::Branch { condition, .. } => unknown(condition),
            Statement::Call { target } | Statement::Jump { target } => unknown(target),
            _ => false,
        });
        invalid |= statements.iter().any(|s| s.validate().is_err());
        if !supported || invalid {
            statements = vec![Statement::Unknown {
                description: text.clone(),
            }];
        }
        Ok(Instruction {
            id: String::new(),
            revision: 0,
            space: "ram".into(),
            address,
            bytes: insn.bytes().to_vec(),
            text,
            mnemonic,
            operands,
            statements,
            flow,
            semantic_complete: supported && !invalid,
        })
    }
}
