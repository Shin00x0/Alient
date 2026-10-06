# N06 — Representación intermedia del motor Rust

Entrega: 2026-09-15. Alcance escalar ARM64/x86-64, independiente de Java/Ghidra. Se amplía la IR existente; no se afirma paridad con P-code ni con Ghidra/IDA.

## Implementado en esta entrega

- Contrato validado para expresiones y sentencias: anchos escalares entre 1 y 64 bits, operadores aritméticos/lógicos y comparaciones permitidos, nombres de registros no vacíos y destinos de control de 64 bits.
- Accesos de memoria con dirección de 64 bits y tamaño múltiplo de byte hasta 64 bits. Los formatos vigentes son little-endian; no se añadió soporte big-endian.
- Profundidad máxima de 128 niveles al validar una expresión. Los snapshots conservan el formato serializado anterior.
- Validación del IR producido por el decodificador: si el contrato falla, la instrucción queda como efecto desconocido. Validación de las sentencias al comprobar el programa persistido, con dirección e índice de operación en el error.
- Resumen serializable de efectos por sentencia: registros leídos/escritos, lectura/escritura de memoria, posible alteración de registros no especificados, control y posibilidad de excepción.
- Llamadas y efectos desconocidos se describen conservadoramente. Los resúmenes no sustituyen las reglas de ABI ni el análisis de aliasing. Los registros implícitos de retorno y las restricciones de cada convención siguen siendo responsabilidad del análisis ABI.
- Consulta CLI `function` y API `native-function`: campo adicional `ir`, con `address`, `statementIndex`, `statement` y `effects`. Permite inspección por operación sin modificar el snapshot ni duplicar la IR persistente.
- Evaluación de desplazamientos: los contadores grandes no se truncan a 32 bits; los contadores fuera del evaluador de 64 bits producen resultado desconocido. El enmascaramiento específico del contador de una arquitectura sigue siendo responsabilidad del levantador de instrucciones.
- Evaluación con ancho inválido devuelve desconocido en lugar de desbordar. Escrituras en subregistros fuera de su contenedor de 64 bits se convierten en efecto desconocido.
- Plegado de comparaciones constantes a booleanos de 1 bit. Por compatibilidad, `Compare.bits` sigue describiendo el ancho de sus operandos. Las operaciones de anchos diferentes mantienen la evaluación de los operandos seguida del enmascaramiento al ancho del resultado.

## Verificación

`engine-rust/tests/n06_ir.rs` contiene 13 pruebas: aritmética modular contra referencia `u128` (15.000 casos), comparaciones con/sin signo (3.840 casos), simplificación, subregistros, desplazamientos extremos, contratos inválidos, profundidad, serialización y efectos de memoria/control, y rechazo de IR corrupta con su ubicación.

Suite Rust final: 63 pruebas aprobadas. Clippy estricto, formato Rust y compilación TypeScript aprobados. Regresión interna: 4 pruebas aprobadas, incluida operación sin Java/Ghidra. Build release `ddcbdd45099776fc`. Los tres proyectos conservan 31/1431/210 instrucciones y 3/231/15 funciones. La API devuelve 22/1201/148 operaciones IR en las funciones inspeccionadas. Resultados completos: `VERIFICACION-N06.json`.

## Pendientes para cobertura profesional

- Operadores adicionales y tipos explícitos para conversiones, extracción/concatenación, división, carry/borrow, rotaciones, SIMD y punto flotante.
- Semántica exhaustiva de flags por arquitectura; condiciones aún abstractas y sin un intérprete completo de flags.
- Modelo de memoria con espacios, endianness explícito por operación, alineamiento, atomicidad y volatilidad. No hay emulación de un binario ni simulación de excepciones.
- Alias de memoria, SSA de memoria y resúmenes precisos de llamadas. `Effects` ofrece un contrato conservador para consumidores; no reemplaza N07–N10.
- Fuzzing persistente, pruebas diferenciales contra ejecución de referencia y un corpus más amplio de instrucciones. La referencia aritmética actual verifica la IR, no la equivalencia exhaustiva de cada instrucción de CPU.
- Vista gráfica/editor específico de IR. Esta entrega permite consultarla por API/CLI; no añade una nueva pestaña de interfaz.

Entrega limitada a N06. No se inicia N07.
