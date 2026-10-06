//! N14: bounded jobs, cancellation, progress and deterministic priority work queues.
use crate::{core::Addr, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_instructions: usize,
    pub max_functions: usize,
    pub max_work: usize,
    pub timeout_ms: u64,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            max_instructions: 200_000,
            max_functions: 20_000,
            max_work: 2_000_000,
            timeout_ms: 120_000,
        }
    }
}
pub struct Job {
    pub budget: Budget,
    start: Instant,
    pub work: usize,
    pub cancel_file: Option<PathBuf>,
    pub emit: bool,
}
impl Job {
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            start: Instant::now(),
            work: 0,
            cancel_file: None,
            emit: false,
        }
    }
    pub fn tick(&mut self) -> Result<()> {
        self.work += 1;
        if self.work > self.budget.max_work {
            return Err("Presupuesto de trabajo agotado".into());
        }
        if self.start.elapsed() > Duration::from_millis(self.budget.timeout_ms) {
            return Err("Tiempo de análisis agotado".into());
        }
        if self.cancel_file.as_ref().is_some_and(|p| p.exists()) {
            return Err("Análisis cancelado".into());
        }
        Ok(())
    }
    pub fn progress(&self, stage: &str, done: usize, total: usize) {
        if self.emit {
            eprintln!(
                "{}",
                serde_json::json!({"event":"progress","stage":stage,"done":done,"total":total})
            );
        }
    }
}
#[derive(Default)]
pub struct WorkQueue {
    items: BTreeMap<(u8, Addr), ()>,
    seen: BTreeSet<Addr>,
}
impl WorkQueue {
    pub fn push(&mut self, a: Addr, priority: u8) {
        if self.seen.insert(a) {
            self.items.insert((priority, a), ());
        }
    }
    pub fn pop(&mut self) -> Option<Addr> {
        let key = *self.items.keys().next()?;
        self.items.remove(&key);
        Some(key.1)
    }
}
