# N05 — Descubrimiento de código y funciones

Entrega: 2026-09-15. Implementación Rust independiente de Ghidra. Alcance verificado para ARM64 y x86-64; no constituye recuperación exhaustiva ni paridad con Ghidra/IDA.

## Implementado

- Recorrido desde símbolos, entrada del ejecutable, funciones del usuario y destinos de llamadas. El origen queda persistido en `Function.discovery` y expuesto por la API.
- Reconstrucción de los cuerpos después de conocer todas las entradas: una función descubierta por una llamada tardía deja de formar parte del llamador anterior.
- Tamaños de símbolos válidos como límites exclusivos. Rechazo de instrucciones que crucen ese límite, con diagnóstico; respeto a los datos definidos y a instrucciones previamente decodificadas.
- Bloques reconstruidos con sucesores internos. Saltos, ramas, tablas y continuaciones hacia otras entradas o fuera del tamaño declarado se registran como transferencias separadas.
- Thunks de salto directo a otra entrada conocida, ignorando NOP/ENDBR. Destino y clasificación disponibles en API y vista Flujo.
- Colas de código compartidas: pueden pertenecer a varias funciones, con direcciones y aviso explícitos; no se fuerza un único propietario.
- Recuperación conservadora de funciones sin símbolos con prólogo de marco x86-64 o ARM64, frontera con padding y CFG decodificable que contiene retorno. Se marca `frame-prologue-inferred`, nunca como certeza.
- Ventana heurística máxima de 4096 bytes y 256 instrucciones por candidato; alineación de 16 bytes en x86-64 y 4 en ARM64. Se rechazan destinos desconocidos, instrucciones sin semántica, datos definidos y cruces de entradas conocidas. Respeta presupuesto/cancelación del trabajo.
- Vista Flujo: procedencia, cantidad de instrucciones compartidas, destino thunk y navegación de transferencias.
- Pseudocódigo: destinos ajenos al cuerpo se representan con `transfer_control`, incluyendo continuaciones; no se presentan como etiquetas locales inexistentes. Es una operación abstracta, no C recompilable ni una prueba de tail-call.
- Compatibilidad de lectura con snapshots anteriores sin el campo `discovery`; la caché incluye la nueva metadata y la identidad de build.

## Validación

14 pruebas específicas en `engine-rust/tests/n05_discovery.rs`: llamada tardía, thunk, cola compartida, tamaño de símbolo, cruce de instrucción, prólogos positivos/negativos, datos definidos, alineación ARM64, región no alineada, límite de trabajo y pseudocódigo de transferencias.

Suite Rust completa: 50 pruebas aprobadas (25 de integración general, 10 N04, 14 N05 y 1 de equivalencia simbólica). Compilación TypeScript y Clippy estricto aprobados. Regresión API interna: 4 pruebas aprobadas, incluyendo operación sin Java/Ghidra. Mediciones con tres proyectos existentes: `VERIFICACION-N05.json`. Se conservan 31/1431/210 instrucciones y 3/231/15 funciones; XorGate clasifica un thunk. Build release: `c682beb56f743e4e`. Navegador: procedencia visible en la pestaña Flujo de XorGate; navegación a `frame_dummy` muestra el thunk, la transferencia desde `0x11e4` y su destino `0x1160`.

## Pendiente de cobertura profesional

- Recuperación de funciones sin prólogo, no alineadas, optimizadas o con varias entradas. El patrón heurístico puede omitir funciones y producir candidatos falsos; requiere revisión.
- Metadatos de unwind/excepciones, DWARF/PDB y rangos fragmentados de funciones como fuentes adicionales.
- Identificación general de thunks indirectos/importaciones, tail-calls y funciones que no retornan. Hoy no se infieren como hechos a partir de un salto aislado.
- Código/datos intercalados sin definición explícita, tablas relativas y destinos indirectos complejos; dependen también de N03/N04/N10.
- Binarios ofuscados, flujos superpuestos intencionales y código automodificable. No se ejecuta el binario.
- Corpus diferencial amplio y métricas de precisión/recobrado frente a análisis de referencia. Las pruebas actuales demuestran casos concretos.

La entrega se detiene en N05. N06 no se inicia en esta tarea.
