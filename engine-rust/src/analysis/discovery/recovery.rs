//! Bounded heuristic roots. A frame prologue alone is not enough: require a padded
//! boundary and a closed, decodable CFG containing a return within the candidate window.
use crate::{architectures::Decoder, core::*, scheduler::Job, Result};
use std::collections::{BTreeSet, VecDeque};
pub fn roots(
    p: &Program,
    source: &[u8],
    known: &BTreeSet<Addr>,
    job: &mut Job,
) -> Result<BTreeSet<Addr>> {
    let arm = p.architecture.starts_with("AARCH64");
    let decoder = Decoder::new(&p.architecture)?;
    let mut found = BTreeSet::new();
    for r in p.regions.iter().filter(|r| r.executable) {
        let step = if arm { 4 } else { 16 };
        let first = (step as u64 - r.range.start.0 % step as u64) % step as u64;
        for off in (first..r.file_size).step_by(step) {
            job.tick()?;
            let a = Addr(r.range.start.0 + off);
            if !a.0.is_multiple_of(step as u64)
                || known.contains(&a)
                || p.overrides.excluded_functions.contains(&a)
                || !p.executable(a)
                || p.symbols.iter().any(|s| {
                    s.function
                        && s.size > 0
                        && s.address.is_some_and(|start| {
                            a > start && (a.0 as u128) < start.0 as u128 + s.size as u128
                        })
                })
            {
                continue;
            }
            let bytes = p.bytes_at(source, a, 8)?;
            let prologue = if arm {
                bytes.len() >= 8
                    && u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0xffc07fff == 0xa9807bfd
                    && bytes[4..8] == [0xfd, 3, 0, 0x91]
            } else {
                bytes.starts_with(&[0x55, 0x48, 0x89, 0xe5])
                    || bytes.starts_with(&[0x55, 0x48, 0x8b, 0xec])
            };
            if !prologue {
                continue;
            }
            let padding = if off == 0 {
                true
            } else if off < 4 {
                false
            } else {
                let previous = p.bytes_at(source, Addr(a.0 - 4), 4)?;
                if arm {
                    previous == [0x1f, 0x20, 3, 0xd5] || previous == [0; 4]
                } else {
                    previous.iter().all(|b| [0, 0x90, 0xcc].contains(b))
                }
            };
            if padding && closed_candidate(p, source, a, &decoder, known, job)? {
                found.insert(a);
            }
            if found.len() + known.len() > job.budget.max_functions {
                return Err("Límite de candidatos de función".into());
            }
        }
    }
    Ok(found)
}
fn closed_candidate(
    p: &Program,
    source: &[u8],
    entry: Addr,
    decoder: &Decoder,
    known: &BTreeSet<Addr>,
    job: &mut Job,
) -> Result<bool> {
    let mut queue = VecDeque::from([entry]);
    let mut decoded = std::collections::BTreeMap::<Addr, Instruction>::new();
    let mut returned = false;
    while let Some(a) = queue.pop_front() {
        job.tick()?;
        if decoded.contains_key(&a) {
            continue;
        }
        if (p.architecture.starts_with("AARCH64") && a.0 % 4 != 0)
            || decoded.len() >= 256
            || a < entry
            || a.0 - entry.0 >= 4096
            || (a != entry && known.contains(&a))
            || !p.executable(a)
        {
            return Ok(false);
        }
        let Ok(bytes) = p.bytes_at(source, a, 16) else {
            return Ok(false);
        };
        let Ok(i) = decoder.decode(bytes, a) else {
            return Ok(false);
        };
        if a.0 as u128 + i.bytes.len() as u128 > entry.0 as u128 + 4096
            || known
                .iter()
                .any(|root| *root > a && (root.0 as u128) < a.0 as u128 + i.bytes.len() as u128)
            || !i.semantic_complete
            || p.data.values().any(|d| {
                (d.range.start.0 as u128) < a.0 as u128 + i.bytes.len() as u128
                    && (a.0 as u128) < d.range.start.0 as u128 + d.range.size as u128
            })
        {
            return Ok(false);
        }
        match &i.flow {
            Flow::Return => returned = true,
            Flow::Next | Flow::Call(_) => {
                let Some(next) = i.next() else {
                    return Ok(false);
                };
                queue.push_back(next);
            }
            Flow::Jump(to) => queue.push_back(*to),
            Flow::Branch(to) => {
                queue.push_back(*to);
                let Some(next) = i.next() else {
                    return Ok(false);
                };
                queue.push_back(next);
            }
            _ => return Ok(false),
        }
        decoded.insert(a, i);
    }
    let mut end = 0u128;
    for i in decoded.values() {
        if (i.address.0 as u128) < end {
            return Ok(false);
        }
        end = i.address.0 as u128 + i.bytes.len() as u128;
    }
    Ok(returned)
}
