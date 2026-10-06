//! N03 format policy. The generic object reader only consumes this typed decision.
use crate::Result;
use object::{BinaryFormat, File, Object, ObjectKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSpec {
    pub format: &'static str,
    pub architecture: &'static str,
}
pub fn identify(file: &File<'_>) -> Result<LoadSpec> {
    if !file.is_64() || !file.is_little_endian() {
        return Err("Solo formatos de 64 bits little-endian".into());
    }
    if !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic) {
        return Err(
            "Se requiere ejecutable o biblioteca enlazada; objetos relocatables pendientes".into(),
        );
    }
    let architecture = match file.architecture() {
        object::Architecture::Aarch64 => "AARCH64:LE:64",
        object::Architecture::X86_64 => "x86:LE:64",
        _ => return Err("Arquitectura aún no soportada".into()),
    };
    let format = match file.format() {
        BinaryFormat::Elf => "ELF 64-bit",
        BinaryFormat::MachO => "Mach-O 64-bit",
        BinaryFormat::Pe => "PE32+",
        _ => return Err("Formato no soportado".into()),
    };
    Ok(LoadSpec {
        format,
        architecture,
    })
}
