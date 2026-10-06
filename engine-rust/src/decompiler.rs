//! N11: AST-backed C-like output, structured branches and loops when the CFG proves the pattern.
mod symbolic;
use crate::{analysis::abi::Abi, core::*, ir::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ast {
    Line {
        address: Option<Addr>,
        text: String,
    },
    If {
        address: Addr,
        condition: String,
        yes: Vec<Ast>,
        no: Vec<Ast>,
    },
    While {
        address: Addr,
        condition: String,
        body: Vec<Ast>,
    },
    Switch {
        address: Addr,
        value: String,
        cases: BTreeMap<u64, Addr>,
    },
}
pub fn c_name(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if i == 0 && c.is_ascii_digit() {
                out.push('_')
            }
            out.push(c)
        } else {
            out.push('_')
        }
    }
    if out.is_empty() {
        "unnamed".into()
    } else {
        out
    }
}
fn expr(e: &Expr, names: &BTreeMap<String, String>) -> String {
    match e {
        Expr::Const { value, .. } => format!("0x{value:x}"),
        Expr::Var { name, bits } => {
            let n = names.get(name).cloned().unwrap_or_else(|| c_name(name));
            if *bits < 64 {
                format!("((uint{bits}_t){n})")
            } else {
                n
            }
        }
        Expr::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let a = expr(left, names);
            let b = expr(right, names);
            if op == "asr" {
                format!("((int{bits}_t)({a}) >> ({b}))")
            } else {
                format!("((uint{bits}_t)({a} {op} {b}))")
            }
        }
        Expr::Load { address, bits } => format!("load_u{bits}({})", expr(address, names)),
        Expr::Compare {
            op,
            left,
            right,
            bits,
        } => {
            let sign = if op.ends_with('s') { "int" } else { "uint" };
            let op = op.trim_end_matches(['s', 'u']);
            format!(
                "(({sign}{bits}_t){} {op} ({sign}{bits}_t){})",
                expr(left, names),
                expr(right, names)
            )
        }
        Expr::Condition(c) => format!("condition_{}(__flags)", c_name(c)),
        Expr::Unknown(v) => format!("unknown_value(/* {} */)", v.replace("*/", "* /")),
    }
}
fn condition(
    e: &Expr,
    last: &Option<(String, Expr, Expr, u16)>,
    names: &BTreeMap<String, String>,
) -> String {
    if let Expr::Condition(c) = e {
        if let Some((op, l, r, bits)) = last {
            let compare = match c.as_str() {
                "eq" | "e" | "z" => Some("=="),
                "ne" | "nz" => Some("!="),
                "lt" | "l" => Some("<s"),
                "ge" => Some(">=s"),
                "gt" | "g" => Some(">s"),
                "le" => Some("<=s"),
                "lo" | "cc" | "b" | "c" => Some("<u"),
                "hs" | "cs" | "ae" | "nc" => Some(">=u"),
                "hi" | "a" => Some(">u"),
                "ls" | "be" => Some("<=u"),
                _ => None,
            };
            if op == "-" {
                if let Some(cmp) = compare {
                    return expr(
                        &Expr::Compare {
                            op: cmp.into(),
                            left: Box::new(l.clone()),
                            right: Box::new(r.clone()),
                            bits: *bits,
                        },
                        names,
                    );
                }
            }
            if op == "&" && matches!(c.as_str(), "e" | "eq" | "z" | "ne" | "nz") {
                return format!(
                    "({} {} 0)",
                    expr(&binary("&", l.clone(), r.clone(), *bits), names),
                    if ["ne", "nz"].contains(&c.as_str()) {
                        "!="
                    } else {
                        "=="
                    }
                );
            }
        }
    }
    expr(e, names)
}
pub fn emit(
    f: &mut Function,
    instructions: &BTreeMap<Addr, Instruction>,
    abi: &Abi,
    overrides: &Overrides,
    symbol_names: &BTreeMap<Addr, String>,
) -> Vec<Ast> {
    let names = f
        .variables
        .iter()
        .filter(|v| v.parameter)
        .map(|v| (v.storage.clone(), c_name(&v.name)))
        .collect::<BTreeMap<_, _>>();
    let mut regs = BTreeSet::new();
    for a in &f.members {
        for s in &instructions[a].statements {
            regs.extend(s.reads());
            regs.extend(s.writes());
        }
    }
    regs.insert(abi.result.clone());
    let args = f
        .variables
        .iter()
        .filter(|v| v.parameter)
        .map(|v| format!("{} {}", v.ty, c_name(&v.name)))
        .collect::<Vec<_>>()
        .join(", ");
    f.signature = overrides
        .signatures
        .get(&f.entry)
        .cloned()
        .unwrap_or(format!(
            "uint64_t {}({})",
            c_name(&f.name),
            if args.is_empty() { "void" } else { &args }
        ));
    if f.discovery.transfers.is_empty()
        && !overrides.signatures.contains_key(&f.entry)
        && !f.members.iter().any(|a| overrides.comments.contains_key(a))
        && !overrides.function_comments.contains_key(&f.entry)
    {
        if let Some(value) = symbolic::return_expression(f, instructions, abi) {
            let symbolic_names = names
                .iter()
                .map(|(r, n)| (format!("input_{r}"), n.clone()))
                .collect();
            f.code = vec![
                CodeLine {
                    address: Some(f.entry),
                    text: format!("{} {{", f.signature),
                },
                CodeLine {
                    address: f.members.last().copied(),
                    text: format!("  return {};", expr(&value, &symbolic_names)),
                },
                CodeLine {
                    address: None,
                    text: "}".into(),
                },
            ];
            f.complete = true;
            return f
                .code
                .iter()
                .map(|l| Ast::Line {
                    address: l.address,
                    text: l.text.clone(),
                })
                .collect();
        }
    }
    let mut ast = vec![
        Ast::Line {
            address: None,
            text: format!("{} {{", f.signature),
        },
        Ast::Line {
            address: None,
            text: format!(
                "  /* ABI {} · C de bajo nivel; load/store y flags son operaciones abstractas */",
                abi.name
            ),
        },
    ];
    if let Some(comment) = overrides.function_comments.get(&f.entry) {
        ast.push(Ast::Line {
            address: Some(f.entry),
            text: format!("  /* {} */", comment.replace("*/", "* /")),
        });
    }
    for reg in regs
        .iter()
        .filter(|r| !names.contains_key(*r) && r.as_str() != "__memory" && r.as_str() != "zero")
    {
        ast.push(Ast::Line {
            address: None,
            text: format!(
                "  uint64_t {} = input_register(\"{}\");",
                c_name(reg),
                c_name(reg)
            ),
        });
    }
    // Parameters describe incoming values; machine registers remain full width after writes.
    let mut names = names;
    let occupied = names
        .values()
        .cloned()
        .chain(regs.iter().cloned())
        .collect::<BTreeSet<_>>();
    for name in names.values_mut() {
        let input = name.clone();
        let mut wide = format!("{input}__reg");
        while occupied.contains(&wide) {
            wide.push('_');
        }
        ast.push(Ast::Line {
            address: None,
            text: format!("  uint64_t {wide} = (uint64_t){input};"),
        });
        *name = wide;
    }
    let mut block_lines: BTreeMap<Addr, Vec<Ast>> = BTreeMap::new();
    let mut branch_conditions = BTreeMap::new();
    f.complete = true;
    for block in &f.blocks {
        let mut lines = vec![];
        let mut flags = None;
        for a in &block.members {
            if let Some(comment) = overrides.comments.get(a) {
                lines.push(Ast::Line {
                    address: Some(*a),
                    text: format!("/* {} */", comment.replace("*/", "* /")),
                });
            }
            let ins = &instructions[a];
            if !ins.semantic_complete {
                f.complete = false;
            }
            for s in &ins.statements {
                let text = match s {
                    Statement::Assign { dst, value } => {
                        if flags
                            .as_ref()
                            .is_some_and(|(_, l, r, _): &(String, Expr, Expr, u16)| {
                                l.reads().contains(dst) || r.reads().contains(dst)
                            })
                        {
                            flags = None;
                        }
                        format!(
                            "{} = {};",
                            names.get(dst).cloned().unwrap_or_else(|| c_name(dst)),
                            expr(value, &names)
                        )
                    }
                    Statement::Store {
                        address,
                        value,
                        bits,
                    } => format!(
                        "store_u{bits}({}, {});",
                        expr(address, &names),
                        expr(value, &names)
                    ),
                    Statement::Flags {
                        op,
                        left,
                        right,
                        bits,
                    } => {
                        flags = Some((op.clone(), left.clone(), right.clone(), *bits));
                        format!(
                            "__flags = flags_{}_{bits}({}, {});",
                            match op.as_str() {
                                "-" => "sub",
                                "+" => "add",
                                "&" => "and",
                                _ => "operation",
                            },
                            expr(left, &names),
                            expr(right, &names)
                        )
                    }
                    Statement::Call { target } => {
                        flags = None;
                        let callee = target
                            .eval(&BTreeMap::new())
                            .map(Addr)
                            .and_then(|a| symbol_names.get(&a))
                            .map(|n| c_name(n))
                            .unwrap_or_else(|| format!("function_at({})", expr(target, &names)));
                        let arguments = abi
                            .args
                            .iter()
                            .map(|r| {
                                names.get(r).cloned().unwrap_or_else(|| {
                                    if regs.contains(r) {
                                        c_name(r)
                                    } else {
                                        format!("register_value(\"{r}\")")
                                    }
                                })
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        f.complete = false;
                        let result = names
                            .get(&abi.result)
                            .cloned()
                            .unwrap_or_else(|| c_name(&abi.result));
                        lines.push(Ast::Line {address:Some(*a),text:format!("{result} = {callee}({arguments}); /* argumentos/efectos de llamada inferidos */")});
                        for r in abi
                            .clobbers
                            .iter()
                            .filter(|r| *r != &abi.result && regs.contains(*r))
                        {
                            let name = names.get(r).cloned().unwrap_or_else(|| c_name(r));
                            lines.push(Ast::Line {
                                address: Some(*a),
                                text: format!("{name} = unknown_after_call(\"{r}\");"),
                            });
                        }
                        continue;
                    }
                    Statement::Branch {
                        condition: e,
                        target,
                    } => {
                        let cond = condition(e, &flags, &names);
                        if cond.starts_with("condition_") {
                            f.complete = false;
                        }
                        branch_conditions.insert(block.address, cond.clone());
                        if f.members.binary_search(target).is_err() {
                            f.complete = false;
                            format!(
                                "if ({cond}) transfer_control(0x{target}); /* fuera del cuerpo */"
                            )
                        } else {
                            format!("if ({cond}) goto loc_{target};")
                        }
                    }
                    Statement::Jump { target } => {
                        if let Flow::Switch { targets, index } = &ins.flow {
                            f.complete = false;
                            lines.push(Ast::Line {
                                address: Some(*a),
                                text: "/* Tabla absoluta y límites indicados por el usuario. */"
                                    .into(),
                            });
                            if targets
                                .iter()
                                .any(|to| f.members.binary_search(to).is_err())
                            {
                                lines.push(Ast::Line {
                                    address: Some(*a),
                                    text: format!(
                                        "switch ({}) {{",
                                        names.get(index).cloned().unwrap_or_else(|| c_name(index))
                                    ),
                                });
                                for (case, to) in targets.iter().enumerate() {
                                    let action = if f.members.binary_search(to).is_ok() {
                                        format!("goto loc_{to};")
                                    } else {
                                        format!("transfer_control(0x{to}); break;")
                                    };
                                    lines.push(Ast::Line {
                                        address: Some(*a),
                                        text: format!("case {case}: {action}"),
                                    });
                                }
                                lines.push(Ast::Line {
                                    address: Some(*a),
                                    text: "}".into(),
                                });
                                continue;
                            }
                            lines.push(Ast::Switch {
                                address: *a,
                                value: names.get(index).cloned().unwrap_or_else(|| c_name(index)),
                                cases: targets
                                    .iter()
                                    .enumerate()
                                    .map(|(i, a)| (i as u64, *a))
                                    .collect(),
                            });
                            continue;
                        }
                        if let Some(to) = target.eval(&BTreeMap::new()) {
                            if f.members.binary_search(&Addr(to)).is_err() {
                                f.complete = false;
                                format!("transfer_control(0x{}); /* fuera del cuerpo */", Addr(to))
                            } else {
                                format!("goto loc_{};", Addr(to))
                            }
                        } else {
                            f.complete = false;
                            format!("jump_indirect({});", expr(target, &names))
                        }
                    }
                    Statement::Intrinsic {
                        operation,
                        domain,
                        outputs,
                        inputs,
                        element_bits,
                        lanes,
                        ..
                    } => {
                        flags = None;
                        f.complete = false;
                        let args = inputs
                            .iter()
                            .map(|v| names.get(v).cloned().unwrap_or_else(|| c_name(v)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let output = if outputs.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "{} = ",
                                outputs
                                    .iter()
                                    .map(|v| names.get(v).cloned().unwrap_or_else(|| c_name(v)))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        };
                        format!("{output}intrinsic_{domain}_{operation}_u{element_bits}x{lanes}({args});")
                    }
                    Statement::Return => format!(
                        "return {};",
                        names
                            .get(&abi.result)
                            .cloned()
                            .unwrap_or_else(|| abi.result.clone())
                    ),
                    Statement::Stop { instruction } => {
                        f.complete = false;
                        format!("stop_instruction(\"{}\"); /* excepción/parada: contexto y reanudación no modelados */",c_name(instruction))
                    }
                    Statement::Nop => continue,
                    Statement::Unknown { description } => {
                        flags = None;
                        format!(
                            "unknown_effects(\"{}\");",
                            description.replace('\\', "\\\\").replace('"', "\\\"")
                        )
                    }
                };
                lines.push(Ast::Line {
                    address: Some(*a),
                    text,
                });
            }
        }
        for transfer in f
            .discovery
            .transfers
            .iter()
            .filter(|t| t.kind == "fallthrough" && block.members.last() == Some(&t.from))
        {
            f.complete = false;
            lines.push(Ast::Line {
                address: Some(transfer.from),
                text: format!(
                    "transfer_control(0x{}); /* continuación fuera del cuerpo */",
                    transfer.to
                ),
            });
        }
        block_lines.insert(block.address, lines);
    }
    // Single-block self loops are exactly representable as a do/while-shaped explicit while.
    let incoming = f
        .blocks
        .iter()
        .flat_map(|b| b.successors.iter().copied())
        .fold(BTreeMap::<Addr, usize>::new(), |mut m, a| {
            *m.entry(a).or_default() += 1;
            m
        });
    if f.blocks.first().is_some_and(|b| b.address != f.entry) {
        ast.push(Ast::Line {
            address: Some(f.entry),
            text: format!("goto loc_{};", f.entry),
        });
    }
    let mut consumed = BTreeSet::new();
    for b in &f.blocks {
        if consumed.contains(&b.address) {
            continue;
        }
        ast.push(Ast::Line {
            address: Some(b.address),
            text: format!("loc_{}:", b.address),
        });
        let mut lines = block_lines[&b.address].clone();
        if b.successors.contains(&b.address)
            && matches!(instructions[b.members.last().unwrap()].flow,Flow::Branch(to)if to==b.address)
        {
            lines.pop();
            let cond = branch_conditions
                .get(&b.address)
                .cloned()
                .unwrap_or("unknown_condition()".into());
            lines.push(Ast::Line {
                address: b.members.last().copied(),
                text: format!("if (!({cond})) break;"),
            });
            ast.push(Ast::While {
                address: b.address,
                condition: "1".into(),
                body: lines,
            });
        } else if let Some(last) = b.members.last().and_then(|a| instructions.get(a)) {
            if let Flow::Branch(target) = last.flow {
                let fall = last.next();
                let yes = f.blocks.iter().find(|x| x.address == target);
                let no = fall.and_then(|a| f.blocks.iter().find(|x| x.address == a));
                if let (Some(y), Some(n)) = (yes, no) {
                    if y.address != n.address
                        && incoming.get(&y.address) == Some(&1)
                        && incoming.get(&n.address) == Some(&1)
                        && y.successors.is_empty()
                        && n.successors.is_empty()
                        && matches!(instructions[y.members.last().unwrap()].flow, Flow::Return)
                        && matches!(instructions[n.members.last().unwrap()].flow, Flow::Return)
                    {
                        lines.pop();
                        ast.extend(lines);
                        ast.push(Ast::If {
                            address: last.address,
                            condition: branch_conditions[&b.address].clone(),
                            yes: block_lines[&y.address].clone(),
                            no: block_lines[&n.address].clone(),
                        });
                        consumed.insert(y.address);
                        consumed.insert(n.address);
                        continue;
                    }
                }
            }
            ast.extend(lines);
        } else {
            ast.extend(lines);
        }
    }
    ast.push(Ast::Line {
        address: None,
        text: "}".into(),
    });
    f.code = render(&ast, 0);
    if !f.complete {
        f.warnings.push("C parcial: efectos/llamadas o flujo sin reconstrucción completa. No es código recompilable sin el runtime abstracto.".into());
    }
    ast
}
pub fn render(ast: &[Ast], indent: usize) -> Vec<CodeLine> {
    let mut out = vec![];
    let pad = "  ".repeat(indent);
    for node in ast {
        match node {
            Ast::Line { address, text } => out.push(CodeLine {
                address: *address,
                text: format!("{pad}{text}"),
            }),
            Ast::If {
                address,
                condition,
                yes,
                no,
            } => {
                out.push(CodeLine {
                    address: Some(*address),
                    text: format!("{pad}if ({condition}) {{"),
                });
                out.extend(render(yes, indent + 1));
                out.push(CodeLine {
                    address: None,
                    text: format!("{pad}}} else {{"),
                });
                out.extend(render(no, indent + 1));
                out.push(CodeLine {
                    address: None,
                    text: format!("{pad}}}"),
                });
            }
            Ast::While {
                address,
                condition,
                body,
            } => {
                out.push(CodeLine {
                    address: Some(*address),
                    text: format!("{pad}while ({condition}) {{"),
                });
                out.extend(render(body, indent + 1));
                out.push(CodeLine {
                    address: None,
                    text: format!("{pad}}}"),
                });
            }
            Ast::Switch {
                address,
                value,
                cases,
            } => {
                out.push(CodeLine {
                    address: Some(*address),
                    text: format!("{pad}switch ({value}) {{"),
                });
                for (v, to) in cases {
                    out.push(CodeLine {
                        address: None,
                        text: format!("{pad}  case {v}: goto loc_{to};"),
                    });
                }
                out.push(CodeLine {
                    address: Some(*address),
                    text: format!("{pad}  default: unknown_control_flow();"),
                });
                out.push(CodeLine {
                    address: None,
                    text: format!("{pad}}}"),
                });
            }
        }
    }
    out
}
pub fn valid_signature(value: &str) -> bool {
    value.len() < 4096
        && !value.contains([';', '{', '}', '\n', '\r'])
        && value.ends_with(')')
        && value.contains('(')
        && value
            .split('(')
            .next()
            .is_some_and(|v| v.split_whitespace().count() >= 2)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _*,()[]".contains(c))
}
