//! Independent static analysis engine. Never executes an imported program.
#![forbid(unsafe_code)]
pub mod analysis;
pub mod architectures;
pub mod capabilities;
pub mod capability_catalog;
pub mod commands;
pub mod core;
pub mod decompiler;
pub mod ir;
pub mod loaders;
pub mod protocol;
pub mod scheduler;
pub mod storage;
pub mod types;
pub const MAX_INPUT: usize = 32 * 1024 * 1024;
pub type Result<T> = std::result::Result<T, String>;
