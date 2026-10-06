# Registro de avance del motor propio Rust

Actualizado: 2026-09-20. **Los catorce módulos N01–N14 tienen implementación funcional inicial en Rust; su cobertura profesional sigue parcial. No existe paridad con Ghidra/IDA.**

## Forma de trabajo vigente

Por instrucción del usuario: una entrega de un módulo por vez y luego parar. **Entrega actual: N08**, ABI y recuperación de parámetros; no se avanzará a N09. Registro granular: [REGISTRO-FUNCIONALIDADES.md](REGISTRO-FUNCIONALIDADES.md). La lista de pendientes no autoriza iniciar todos los módulos a la vez.

## Decisiones y alcance

- Motor nuevo en `engine-rust/`, independiente de Java/Ghidra. TypeScript conserva API e interfaz sin framework.
- Se usan `object` para formatos, Capstone para decodificación, y código Rust propio para IR, análisis, decompilación, comandos y persistencia.
- Sólo análisis estático. No se ejecutan los binarios. Debugger excluido.
- Formatos declarados: ELF64, Mach-O64 y PE32+ enlazados, little-endian, ARM64/x86-64. La declaración de soporte no reemplaza las pruebas pendientes de cada formato.
- No modificar `ghidra-original/`. Conservar cambios previos del usuario. No hay commits realizados en esta etapa.

## Estado de los módulos

La suite verifica casos concretos de todos los módulos. “Implementado” no significa soporte exhaustivo: la última columna registra límites pendientes.

| Módulo | Implementado en código | Pendiente antes de cerrarlo |
|---|---|---|
| N01 Modelo | Direcciones hex 64 bits, memoria, entidades, IDs, revisiones, reconciliación; valida identidades, journal, solapamientos y cobertura CFG | Overlays/espacios complejos, corpus de corrupción más amplio |
| N02 Capacidades | CLI y API de cobertura; UI y acciones distinguen runtime, proyecto persistente y funciones parciales | Generar ambos contratos desde una fuente común para evitar divergencias |
| N03 Cargadores | ELF64/Mach-O64/PE32+ vía `object`; símbolos, imports/exports y relocaciones; pruebas Mach-O, ELF y PE sintético | Corpus PE real con imports/exports, universal, objetos relocatables, DWARF/PDB y aplicación de relocaciones |
| N04 Arquitecturas | Capstone ARM64/x86-64; longitudes reales, subregistros, movzx/movsx/movsxd, FS/GS dinámicos y paradas explícitas | Semántica SIMD/FP e instrucciones especiales; pruebas diferenciales extensas |
| N05 Descubrimiento | Entradas/símbolos/llamadas, límites declarados, reparto final de cuerpos, colas compartidas, thunks directos, prólogos inferidos ARM64/x86-64 y procedencia visible | Funciones sin prólogo, unwind, thunks indirectos, no-retorno, precisión en binarios optimizados/ofuscados |
| N06 IR | Contrato validado de anchos/operaciones/memoria, efectos conservadores, IR por dirección/índice vía API, evaluación y simplificación verificadas | Conversiones explícitas, SIMD/FP, flags exhaustivos, memoria avanzada y pruebas diferenciales de instrucciones |
| N07 Flujo de datos | Dominadores inmediatos/fronteras, liveness, SSA con phis en fusiones vivas, índices def-use/phi y constantes por sentencia | SSA de memoria/alias precisa, SCCP, firmas completas para liveness y optimización incremental |
| N08 ABI | Perfiles AAPCS64/SysV/Win64, parámetros por registros, pila por CFG, slots, shadow space Win64, evidencia de call sites y callee-saved | Varargs/FP, agregados, sret, unwind, marcos dinámicos y prototipos interprocedurales |
| N09 Tipos | Enteros, punteros, arrays, structs, unions y enums; layouts/restricciones y edición JSON | Inferencia global, signedness, tipos C++/vtables y editor gráfico |
| N10 Indirectos | Punteros constantes conservadores, resúmenes interprocedurales, nuevas funciones indirectas y tablas absolutas acotadas por usuario | Tablas relativas, límites automáticos, desvirtualización y resolución dinámica |
| N11 Decompilador | AST, expresiones, if/bucles simples, switch manual, reducción simbólica de stack privado; 1.000 valores comprobados para el fixture aritmético | Reconstrucción general de C, prototipos precisos y validación semántica de todo el corpus; helpers abstractos siguen presentes |
| N12 Persistencia | Generaciones y puntero atómico sincronizado, bloqueo, índice por palabras, revisión e historial persistentes | Limpieza/compactación, migraciones futuras y escalado de almacenamiento |
| N13 Comandos | Nombres, comentarios, firmas, variables, tipos, datos, funciones, tablas, undo/redo; API/UI y rechazo sin perder resultado | Parches, edición contextual, referencias manuales y editor visual de estructuras |
| N14 Ejecución | Proceso Rust, cola, progreso, prioridades de descubrimiento, presupuestos, cancelación y caché por función con identidad de build | Reanudación granular, límites de memoria nativa por SO y planificación interactiva avanzada |

## Evidencia disponible

- Rust 1.98.1 instalado; el bloqueo anterior de toolchain/espacio ya se resolvió. Requisito de compilación declarado: Rust 1.98 o posterior.
- `cargo test`: **76 pruebas aprobadas** (25 de integración de módulos, 10 de N04, 14 de N05, 13 de N06, 13 de N07 y 1 de equivalencia simbólica con 1.000 valores).
- `npm run build`: TypeScript compila.
- `npm test`: **16 pruebas aprobadas**, incluida la regresión con Ghidra real (~64 segundos).
- Prueba API sin Java/Ghidra: análisis, schema 2, listing, consulta de función/SSA, búsqueda, reinicio, undo/redo y edición inválida que conserva generación anterior.
- Cancelación real por CLI antes de publicar: el `result.json` previo permanece idéntico.
- Navegador local: selección de Rust, listing/C, rename de función, undo y búsqueda global con 3 coincidencias comprobados. Sin errores de consola en esas interacciones.
- Tres proyectos nuevos de verificación, sin modificar los proyectos Ghidra originales:

| Fixture | Formato/arquitectura | Instrucciones | Funciones | Semántica desconocida |
|---|---|---:|---:|---:|
| sample-macho | Mach-O ARM64 | 31 | 3 | 0 |
| listing-large | Mach-O ARM64 | 1431 | 231 | 0 |
| XorGate, después de N04 | ELF x86-64 | 210 | 15 | 0 |

N05 conserva los recuentos de los tres binarios y clasifica `frame_dummy` de XorGate como thunk hacia `0x1160`; ver `VERIFICACION-N05.json`.

Después de N04 se conservan 2 accesos TLS con base desconocida y 1 parada explícita. Cero instrucciones desconocidas no implica decompilación completa. Las llamadas externas, ABI y patrones de flujo aún tienen límites. Mediciones iniciales e IDs: `VERIFICACION-MOTOR-RUST.json`; actualización de XorGate tras N04: `VERIFICACION-N04.json`; los tiempos incluyen API/polling y persistencia, no son benchmarks generales.

## Punto de control de ejecución

- Servidor local iniciado en `http://127.0.0.1:4310/`, sesión de terminal 46998. Selección actual: `internal`; Ghidra también detectado.
- Release de N07 actualizado, build `a7fe1058006cfc81`; mediciones de flujo de datos por API en `VERIFICACION-N07.json`. Clippy estricto aprobado. No quedan compilaciones o pruebas pendientes de esta entrega. Regresión API interna final: 4 pruebas aprobadas.
- Quedaban unos 2.2 GiB libres en la última consulta. No es un bloqueo actual; evitar instalaciones innecesarias.
- No se han hecho commits ni modificado `ghidra-original/`.

## Próximos pasos de calidad

1. N04: ampliar semántica y corpus diferencial ARM64/x86-64; SIMD/FP, prefijos especiales y familias pendientes. Los 5 `movzx`, 2 accesos TLS y 1 `hlt` de XorGate ya tienen representación explícita. No confundir esta entrega con cobertura exhaustiva de N04.
2. Mejorar N08–N11: prototipos/argumentos, aliasing, inferencia de tipos, tablas relativas y C estructurado general. No presentar C con helpers como fuente recompilable.
3. Añadir fixtures reales PE y bibliotecas, DWARF/PDB, relocaciones y Mach-O universal según prioridad.
4. Ampliar pruebas de cancelación durante escritura, límites de memoria, compactación y recuperación de generaciones.
5. Añadir edición contextual y editor de estructuras; el editor JSON ya funciona pero es una interfaz básica.

## Archivos principales y comandos

- Núcleo: `engine-rust/src/{core,architectures,ir,types,decompiler,protocol,storage,commands,scheduler}.rs`.
- Análisis: `engine-rust/src/analysis/`; simplificación: `engine-rust/src/decompiler/symbolic.rs`.
- Adaptador API: `backend/engine/native.ts`, `backend/server.ts`, `backend/engine/capabilities.ts`.
- Construcción: `npm run engine:build` (release), `npm run engine:test`, `npm run build`.
- CLI: `capabilities`, `inspect <binario>`, `analyze <proyecto> [nombre]`, `edit <proyecto> [nombre]`, `search`, `function`, `indirect`, `jump-table`.
- Los proyectos nativos usan `input.bin`, `edit.json`, `result.json` y `listing-<id>/native.json`; el historial está dentro del snapshot. No borrar proyectos para resolver fallos.
- Se eliminaron los cargadores nativos incompletos `reader.rs`/`elf.rs` que quedaron sin referenciar; el adaptador vigente es `loaders/mod.rs`.

## Próximo registro

Actualizar antes de una pausa, interrupción o límite de recursos. Anotar último comando, errores pendientes, procesos activos y resultados medidos. Nunca marcar como terminados módulos sólo por existir sus archivos.
