# Motor propio Rust 0.1

Núcleo de análisis estático independiente de Ghidra/Java. Capstone decodifica bytes; `object` interpreta contenedores. La IR, el descubrimiento, los análisis, el C parcial y las transacciones se implementan aquí. El ejecutable **no ejecuta el programa importado**.

## Compilación y pruebas

Desde `ghidra-web/`:

```sh
npm run engine:build
npm run engine:test
npm run build
npm start
```

Requisitos: Rust 1.98 o posterior y herramientas C nativas (para Capstone), Node 24/npm para la aplicación. `Cargo.lock` fija las dependencias. La compilación release usa LTO; el script encuentra Cargo en `~/.cargo/bin` o `PATH` y admite `CARGO`.

## Módulos

| ID | Archivo | Responsabilidad |
|---|---|---|
| N01 | `src/core.rs` | Programa, memoria, entidades, direcciones hex de 64 bits, IDs y revisiones |
| N02 | `src/capabilities.rs` | Contrato de cobertura y límites, consultable por CLI |
| N03 | `src/loaders/mod.rs` | ELF64/Mach-O64/PE32+ enlazados, símbolos, imports/exports y relocaciones |
| N04 | `src/architectures.rs` | Decodificación ARM64/x86-64 y traducción del subconjunto soportado |
| N05 | `src/analysis/discovery.rs` | Recorrido de código, funciones, bloques, referencias y cadenas |
| N06 | `src/ir.rs` | Operaciones de registros/memoria, anchos, flags, barreras y simplificación |
| N07 | `src/analysis/dataflow.rs` | Dominadores, definiciones, SSA/phi y constantes por punto fijo |
| N08 | `src/analysis/abi.rs` | AAPCS64/SysV/Win64, parámetros y slots de pila |
| N09 | `src/types.rs` | Tipos compuestos, layout validado y restricciones explícitas |
| N10 | `src/analysis/indirect.rs` | Punteros constantes, descubrimiento indirecto, resúmenes y tablas absolutas |
| N11 | `src/decompiler.rs`, `src/decompiler/symbolic.rs` | AST, C parcial y eliminación simbólica de temporales/stack privado |
| N12 | `src/storage.rs` | Snapshots, generaciones, bloqueo e índice persistente de palabras |
| N13 | `src/commands.rs` | Comandos validados, historial, undo/redo y cambios dependientes |
| N14 | `src/scheduler.rs` | Presupuestos, progreso, cancelación y prioridades de descubrimiento |
| Integración | `src/protocol.rs`, `src/main.rs` | Pipeline, caché por función, CLI y DTO de la aplicación |

Pipeline: carga → overrides/tipos → cadenas → descubrimiento → SSA/ABI → C → resolución indirecta → redescubrimiento acotado → reconciliación → índice → publicación. Se permiten hasta cuatro rondas de descubrimiento indirecto y dieciséis de resúmenes; alcanzar esos límites no demuestra que todos los destinos estén resueltos.

## Uso CLI

El directorio de proyecto contiene `input.bin`. Las consultas se imprimen como JSON en stdout; progreso y errores, como JSON por línea en stderr. Un fallo devuelve código distinto de cero.

```sh
engine-rust/target/release/ghidra-web-engine capabilities
engine-rust/target/release/ghidra-web-engine inspect fixtures/sample-macho
engine-rust/target/release/ghidra-web-engine analyze /ruta/proyecto nombre
engine-rust/target/release/ghidra-web-engine edit /ruta/proyecto nombre
engine-rust/target/release/ghidra-web-engine search /ruta/proyecto calculate_score function 0
engine-rust/target/release/ghidra-web-engine function /ruta/proyecto 100000460
engine-rust/target/release/ghidra-web-engine indirect /ruta/proyecto
engine-rust/target/release/ghidra-web-engine jump-table /ruta/proyecto 400100 3
```

`edit` lee `edit.json`; ejemplos:

```json
{"operation":"rename","address":"400100","value":"calculate"}
{"operation":"comment","address":"400100","value":"Comprueba la entrada"}
{"operation":"variable","address":"400100","variableId":"00400100:param:rdi","value":"count","dataType":"uint32_t"}
{"operation":"define-type","name":"Pair","ty":{"Struct":{"size":8,"fields":[{"name":"x","ty":"uint32_t","offset":0},{"name":"y","ty":"uint32_t","offset":4}]}}}
{"operation":"define-data","address":"400200","ty":"Pair"}
{"operation":"create-function","address":"400100"}
{"operation":"jump-table","address":"400110","base":"400200","count":3,"index":"rax"}
{"operation":"undo"}
{"operation":"redo"}
```

Cada ejemplo es un archivo separado, no JSON concatenado. Direcciones como cadenas hexadecimales; no usar números JS para direcciones. Los IDs de variables se obtienen del resultado, no se construyen en el cliente.

También existen `function-comment`, `signature`, `bookmark`, `clear-data` y `delete-function`. La firma es una anotación validada sintácticamente: no reconstruye automáticamente ABI o locales. `jump-table` requiere conocimiento del analista: dirección del salto, tabla absoluta de punteros de 64 bits, cantidad exacta e índice de registro. No infiere límites ni prueba que una entrada fuera del rango sea imposible; el C conserva un default desconocido. Las tablas relativas aún no se recuperan.

## Persistencia y API

`result.json` apunta a `listing-<id>/`. La generación contiene páginas de listing, índice, funciones, `program.json` schema 2 y `native.json` con programa/historial/índice. Se escriben y sincronizan antes de publicar el puntero con rename atómico. Los lectores ven generaciones completas. Se bloquea un proyecto para impedir escritores concurrentes; un comando rechazado no publica una generación. Las generaciones antiguas se conservan, sin limpieza automática.

El servidor invoca el ejecutable con argumentos separados, sin shell. Mantiene cola, logs, timeout y cancelación. Para un proyecto `internal` no existe fallback a Java ni al antiguo motor TS. `NATIVE_ENGINE` permite elegir ejecutable; por defecto release, después debug.

API adicional:

- `GET /api/projects/:id/program`: snapshot nativo.
- `GET /api/projects/:id/native-function?address=...`: función, IR, SSA y variables.
- `GET /api/projects/:id/native-indirect`: destinos/resúmenes/tablas.
- `GET /api/projects/:id/native-search?q=...&kind=...&offset=0`: índice global; palabras completas, AND, sin distinguir mayúsculas, hasta 100 resultados/página. Clases: `function`, `instruction`, `code`, `data`.
- `POST /api/projects/:id/edit`: comando. La respuesta 202 significa encolado; consultar estado/error al finalizar.

## Cobertura y límites

Esto es una implementación inicial funcional de los módulos, **no un clon completo ni un decompilador equivalente a Ghidra/IDA**.

- Contenedores enlazados de 64 bits little-endian. Sin Mach-O universal, objetos relocatables, otras arquitecturas o formatos manuales.
- Relocaciones conservadas como metadatos, no aplicadas. Sin enlace de bibliotecas ni carga dinámica; DWARF/PDB y fixups avanzados pendientes.
- Capstone reconoce más instrucciones que las cubiertas por nuestra semántica. SIMD/FP, instrucciones especiales y variantes no implementadas generan efectos desconocidos y limitan las inferencias.
- Parámetros/stack y tipos son inferencias acotadas: no cubren varargs, agregados ABI, aliasing general, vtables o C++ avanzado.
- SSA de registros y estado abstracto de memoria, no SSA precisa por objeto de memoria. El análisis de pila propaga aliases demostrados por punto fijo entre bloques; un conflicto de offsets se conserva como desconocido.
- Se leen punteros estáticos sólo cuando la memoria es de sólo lectura y no hay una relocación pendiente solapada; no se inventan valores del estado dinámico.
- El C bajo nivel usa helpers abstractos para memoria, flags y efectos desconocidos. No se anuncia como fuente recuperada ni recompilable general. Sólo algunos patrones se estructuran como if/bucles/switch; otros conservan saltos explícitos.
- 32 MiB por archivo, 200.000 instrucciones, 20.000 funciones, 2.000.000 pasos y 120 segundos de presupuesto de análisis. El servidor mata el proceso a los 125 segundos. No hay sandbox ni cuota de memoria nativa impuesta por SO.
- Reanálisis completo de carga/descubrimiento; la caché evita repetir SSA/decompilación de funciones no afectadas. Una huella de las fuentes y dependencias invalida resultados al cambiar de build. No hay reanudación granular de un trabajo interrumpido.

Evidencia, pendientes y último punto de control: [registro de avance](../docs/AVANCE-MOTOR-RUST.md).

## Última entrega: N04

Extensiones `movzx`/`movsx`/`movsxd`, bases TLS FS/GS simbólicas, LEA y paradas/excepciones explícitas. Cobertura y pruebas: [entrega N04](../docs/N04-ARQUITECTURAS.md). Las excepciones y reanudaciones no se simulan; el C continúa siendo parcial.

### Entrega N05

El descubrimiento reconstruye cuerpos con todas las entradas conocidas, respeta tamaños de símbolos y registra procedencia, thunks directos, transferencias y código compartido. `src/analysis/discovery/recovery.rs` recupera candidatos de prólogo ARM64/x86-64 con padding y CFG acotado (4096 bytes/256 instrucciones). No es recuperación exhaustiva. Detalle y pendientes: [N05-DESCUBRIMIENTO.md](../docs/N05-DESCUBRIMIENTO.md).

### Entrega N06

`src/ir/contract.rs` valida anchos, operaciones y memoria y describe efectos conservadores. `function` añade `ir` con la dirección, índice, sentencia y efectos de cada operación. Los snapshots anteriores mantienen su formato. Alcance, semántica y pendientes: [N06-IR.md](../docs/N06-IR.md).

### Entrega N07

`analysis/dataflow/structure.rs` añade dominadores inmediatos, fronteras y liveness. `dataflow` expone índices def-use/phi y constantes por sentencia. Se evitan phis redundantes fuera de fusiones vivas y se validan entradas del CFG. Alcance: [N07-FLUJO-DE-DATOS.md](../docs/N07-FLUJO-DE-DATOS.md).
