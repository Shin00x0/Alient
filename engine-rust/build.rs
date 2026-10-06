use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
};
fn sources(path: &Path, hash: &mut DefaultHasher) {
    let mut entries = fs::read_dir(path)
        .expect("source directory")
        .map(|e| e.expect("source entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            sources(&p, hash);
        } else if p.extension().is_some_and(|e| e == "rs") {
            p.hash(hash);
            fs::read(&p).expect("source contents").hash(hash);
        }
    }
}
fn main() {
    let mut hash = DefaultHasher::new();
    sources(Path::new("src"), &mut hash);
    for file in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        fs::read(file).expect("build input").hash(&mut hash);
        println!("cargo:rerun-if-changed={file}");
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rustc-env=NATIVE_BUILD_ID={:016x}", hash.finish());
}
