import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {homedir} from 'node:os';
import {fileURLToPath} from 'node:url';
const cargo=process.env.CARGO || (existsSync(`${homedir()}/.cargo/bin/cargo`)?`${homedir()}/.cargo/bin/cargo`:'cargo');
const root=fileURLToPath(new URL('..',import.meta.url));
const run=spawnSync(cargo,[process.argv.includes('--test')?'test':'build','--locked',...(!process.argv.includes('--test')?['--release']:[]),'--manifest-path','engine-rust/Cargo.toml'],{cwd:root,stdio:'inherit'});
if(run.error)console.error('Instala Rust con rustup para compilar el motor:',run.error.message);
process.exit(run.status??1);
