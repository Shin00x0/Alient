# N04 — entrega de arquitecturas del 15 de septiembre de 2026

**Estado: entrega acotada ampliada con FP/SIMD e instrucciones especiales, probada en el motor Rust. N04 no tiene cobertura exhaustiva de las ISA.**

Esta entrega continúa únicamente N04. Los cambios mínimos en IR y emisión de C permiten representar sus nuevas instrucciones; no constituyen una nueva etapa de los otros módulos. Se detiene el trabajo aquí, conforme a la instrucción de avanzar de uno en uno.

## Implementado en esta entrega

| Capacidad | Comportamiento |
|---|---|
| `movzx` x86-64 | Extensión con ceros desde byte/word, memoria o registros; escritura en EAX limpia la mitad superior de RAX |
| `movsx` / `movsxd` | Extensión de signo; destinos parciales preservan los bits que la ISA no sobrescribe |
| Registros altos | Lectura de AH antes de escribir EAX en instrucciones que comparten registro físico |
| TLS FS/GS | Dirección efectiva con base dinámica `fs_base`/`gs_base`, base, índice, escala y desplazamiento; no se supone base cero ni se leen datos TLS del archivo |
| `lea` con segmento | El segmento no participa en el cálculo de LEA, conforme a su semántica en modo de 64 bits |
| Direccionamiento RIP | Suma modular de 64 bits, evitando desbordamiento del proceso analizador |
| Paradas/excepciones | `hlt`, `ud2`, `int3` y ARM64 `brk` se representan mediante `Statement::Stop` y un límite de flujo; no se convierten en nop |
| Prefijos pendientes | Dirección de 32 bits y operaciones con prefijo lock no soportadas siguen como barreras desconocidas |
| Snapshots anteriores | El campo opcional de segmento admite snapshots previos sin ese campo; la huella de build invalida la caché al regenerar |

Los efectos TLS se representan, pero sus valores dependen del proceso analizado y permanecen desconocidos. En las paradas/excepciones no se modelan privilegios, manejadores ni reanudación: el C conserva una advertencia y no se anuncia como reconstrucción completa.

## Pruebas y resultado

- **10 pruebas nuevas específicas** en `engine-rust/tests/n04_architectures.rs`.
- **36 pruebas Rust aprobadas** en total (incluida la comprobación simbólica de 1.000 valores del fixture aritmético).
- `cargo clippy --all-targets -- -D warnings`: aprobado.
- Compilación release: aprobada. Build verificado: `968fa708cbe11e84`.
- Regresión del motor/API interno: 4 pruebas aprobadas con el ejecutable release y sin Java/Ghidra disponibles en ese servidor de prueba.
- XorGate regenerado desde la API real en el proyecto **Rust · XorGate**, conservando el proyecto Ghidra original.

| Métrica de XorGate | Antes | Después |
|---|---:|---:|
| Instrucciones | 210 | 210 |
| Funciones | 15 | 15 |
| Instrucciones sin representación semántica | 8 | 0 |
| Accesos TLS representados con base dinámica | 0 | 2 |
| Paradas explícitas | 0 | 1 |

Las ocho anteriores eran cinco `movzx`, dos accesos FS y un `hlt`. **Cero instrucciones desconocidas en este archivo no implica cobertura completa de x86-64 ni C equivalente a Ghidra.**

Evidencia con SHA-256, revisión y generación: [VERIFICACION-N04.json](VERIFICACION-N04.json).

## Ampliación FP/SIMD del 22 de septiembre de 2026

Se añade Statement::Intrinsic: una operación tipada y conservadora que transporta sus entradas, salidas, dominio (float, simd o special), ancho de elemento, lanes, efectos de memoria y posibilidad de excepción. El IR escalar continúa limitado a 64 bits; por eso un vector no se falsea como un entero ni se propaga como constante.

| Familia | Implementación |
|---|---|
| x86 FP | SS/SD: aritmética, raíz, mínimo/máximo, movimiento, conversiones y comparaciones |
| x86 SIMD XMM | PS/PD: aritmética y movimiento; lógica, padd*, psub*, pshufd y shufps |
| x86 especial | cpuid, rdtsc/rdtscp, xgetbv, rdrand y rdseed |
| ARM64 FP | aritmética, raíz, comparación, conversión y movimiento |
| ARM64 especial | mrs, msr, dmb, dsb e isb |

Se verificaron 14 pruebas N04. Incluyen prefijos F2/F3 reales, efectos de una carga FP desde memoria, división con posible excepción, fadd s0, s0, s1, mrs, rdtsc y cpuid.

### F32Ghidra

La extensión solicitada está en /Users/matiasaltamirano/Desktop/extensiones/F32Ghidra, pero macOS deniega la lectura de Escritorio al proceso de trabajo. No se ha copiado, inspeccionado ni integrado código de ella. Para hacer la integración real debe moverse a /Users/matiasaltamirano/ghidra-web/F32Ghidra o a la raíz del proyecto de trabajo.

## Pendientes de N04

- AVX, AVX-512, NEON/SVE, máscaras, predicación y operaciones precisas por lane.
- Direccionamiento x86 de 32 bits, operaciones atómicas y prefijos especiales.
- Estado FP (MXCSR/FPCR), redondeo, NaN, flags, excepciones y efectos del sistema completos.
- Corpus diferencial amplio por arquitectura y validación contra una referencia de ejecución controlada.

## Archivos cambiados para N04

- `engine-rust/src/architectures.rs`: decodificación y lifting.
- `engine-rust/src/ir.rs`: segmentos dinámicos y efecto de parada.
- `engine-rust/src/decompiler.rs`: representación explícita de la parada en C parcial.
- `engine-rust/tests/n04_architectures.rs`: regresiones específicas.

## Punto de parada

Se termina esta entrega de N04. **No se inicia N05 ni otra ampliación automáticamente.** El servidor local queda disponible en `http://127.0.0.1:4310/` y el registro general indica desde dónde continuar.
