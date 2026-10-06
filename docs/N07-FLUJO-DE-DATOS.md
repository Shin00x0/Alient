# N07 — Flujo de datos y SSA

Entrega: 2026-09-18. Motor Rust independiente de Ghidra. Esta entrega amplía la base existente de definiciones alcanzables, SSA y propagación conservadora de constantes.

## Implementado

- Validación del CFG antes del análisis: entrada existente, bloques no duplicados, sucesores válidos, instrucciones presentes y rechazo de bloques inalcanzables. Errores explícitos y presupuesto de trabajo/cancelación.
- Dominadores inmediatos y fronteras de dominancia, además de los conjuntos de dominadores existentes.
- Variables vivas a la entrada y salida de cada bloque mediante punto fijo hacia atrás. Llamadas, retornos y operaciones desconocidas conservan posibles entradas implícitas de forma conservadora, sin asumir una firma completa.
- Nodos phi restringidos a fusiones reales o entradas de bucles con versiones distintas y variable viva. Los bloques con un único predecesor propagan la versión SSA previa, evitando phis redundantes aguas abajo de una fusión.
- Los tokens implícitos `__memory` y `__flags` tienen versiones de entrada incluso cuando no aparecen en operandos explícitos; evita fusiones SSA sin una definición inicial.
- Las entradas externas de bucles siguen representadas mediante `entry_input`.
- Índice inverso `def_uses` de definiciones a usos explícitos de sentencias. Índice `phi_uses` para consumidores phi, incluidos sus valores externos de entrada. No se afirma que el índice enumere todos los argumentos implícitos ABI.
- Estado de constantes antes de cada sentencia IR (`constants_at_statement`), además del estado por instrucción. Permite distinguir operaciones sucesivas pertenecientes a una misma instrucción.
- Los nuevos campos se serializan en `dataflow`, disponibles en el snapshot y en CLI/API `function`/`native-function`. Lectura compatible con snapshots antiguos mediante valores predeterminados.

## Validación

13 pruebas específicas en `engine-rust/tests/n07_dataflow.rs`: dominadores/fronteras en diamante, liveness, phi vivo/muerto, usos inversos, bucle con entrada externa, constantes por sentencia, confluencias iguales/distintas, barrera desconocida, llamada con entradas implícitas, clobbers ABI, CFG inválido, presupuesto, orden de bloques, compatibilidad JSON y versiones implícitas de memoria/flags sin operandos explícitos.

Suite Rust: 76 pruebas aprobadas. Clippy estricto, formato Rust y compilación TypeScript aprobados. Regresión interna: 4 pruebas aprobadas, incluida operación sin Java/Ghidra. Build release `a7fe1058006cfc81`. Reanálisis de sample-macho, listing-large y XorGate: se conservan 31/1431/210 instrucciones y 3/231/15 funciones. La función inspeccionada de XorGate expone 30 bloques con dominadores/liveness y 39 nodos phi. Mediciones completas: `VERIFICACION-N07.json`.

## Pendiente de cobertura profesional

- SSA precisa de memoria por objetos, regiones y alias. El token `__memory` sigue siendo una abstracción global; no permite concluir independencia entre accesos.
- SCCP (propagación condicional dispersa), exclusión de aristas imposibles, rangos, relaciones entre variables y resolución general de condiciones/flags. El cálculo actual considera todas las aristas del CFG.
- Eliminación de código muerto y reescritura optimizada del programa. Liveness reduce phis; no elimina instrucciones.
- Liveness de llamadas/retornos con prototipos completos: la aproximación vigente conserva todos los registros rastreados como posibles entradas implícitas y puede sobreestimar variables vivas.
- Escalabilidad incremental: dominadores, fronteras y puntos fijos se recalculan por función; están presupuestados, pero no son algoritmos incrementales de rendimiento profesional.
- Verificador formal de SSA, corpus de CFG irreducibles/obfuscados y pruebas diferenciales amplias. Las pruebas actuales verifican casos concretos y no equivalencia con Ghidra/IDA.
- Interfaz gráfica específica de SSA/liveness. Los datos están disponibles por API/CLI; esta entrega no añade un editor visual.

La entrega termina en N07. No se inicia N08.
