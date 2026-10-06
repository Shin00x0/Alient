# Motor interno TS 0.1

Módulo propio e independiente. No importa código de Ghidra, no invoca `analyzeHeadless`, no usa Java, SLEIGH, bibliotecas nativas ni servicios externos. Se inspira en la separación de responsabilidades del análisis estático de Ghidra: carga → instrucciones → representación intermedia → referencias y flujo → vistas. **No es un port del decompilador de Ghidra ni produce C equivalente.**

## API y componentes

- `loader.ts`: lectores con comprobación de rangos para Mach-O ARM64 enlazado y ELF ARM64 little-endian de 64 bits. Secciones, símbolos, entrada y segmentos ELF cuando no existen secciones.
- `arm64.ts`: subconjunto de instrucciones enteras ARM64, flujos directos/indirectos, operaciones sobre registros y memoria. Una palabra no reconocida se representa como `.inst`, con efectos desconocidos.
- `index.ts`: `analyzeInternal(buffer, name)` devuelve análisis y filas sin escribir archivos. `writeInternalAnalysis(buffer, name, directory)` genera el contrato JSON del frontend y el listing paginado.
- `worker.ts`: ejecución en un worker Node aislado del bucle HTTP. Límite de heap de 256 MB y de ejecución de dos minutos administrado por el servidor. No es un sandbox de seguridad.

El módulo utiliza exclusivamente APIs estándar de Node y tipos de la aplicación. Puede importarse sin tener instalado Ghidra. No ejecuta los programas analizados.

## Alcance verificable

Mach-O/ELF ARM64; listing de palabras de 4 bytes de las regiones de código, símbolos, cadenas ASCII terminadas en NUL (incluidos tabuladores y saltos de línea), llamadas y saltos directos, referencias constantes ADR/ADRP + ADD, funciones inferidas, bloques de flujo e IR enlazada a direcciones.

La IR describe registros y accesos a memoria mediante operaciones abstractas (`u32`, `u64`, `load_u*`, `store_u*`, flags). No es código C compilable ni un emulador. Los registros W escriben la mitad baja y ponen a cero la alta del registro X correspondiente; las llamadas, ABI y aliasado de memoria no se reconstruyen. Los efectos de instrucciones desconocidas invalidan la propagación de constantes.

Los nombres en secciones de código Mach-O, la entrada y los destinos de llamadas sirven como candidatos de funciones. Se divide por candidatos ordenados, **no** por recuperación precisa de cuerpos; regiones sin símbolos reciben un candidato sintético. El barrido lineal puede incluir datos incrustados en código. No se afirma que todas las palabras correspondan a instrucciones ejecutables.

## Límites y pendientes

- Máximo 100000 palabras ARM64 y 20000 cadenas de hasta 4096 caracteres.
- Sin x86/x86-64, PE, Mach-O universal, objetos relocatables, otras arquitecturas ni big-endian.
- Sin NEON/SIMD, coma flotante, conjunto completo de instrucciones, relocaciones, resolución completa de importaciones ni formatos de depuración.
- Sin SSA, recuperación de pila/variables/tipos, propagación interprocedural, resolución de saltos indirectos ni reconstrucción de `if`/bucles/C.
- Sin edición de programa, parches, undo/redo o tipos definidos por el usuario. Las anotaciones web sí están disponibles.
- La persistencia es JSON; Ghidra conserva su propia base de datos únicamente en proyectos del motor Ghidra.

## Configuración

`GET /api/settings` y `PUT /api/settings` con `{"engine":"internal"}` o `{"engine":"ghidra"}`. Se guarda en `data/settings.json`; por defecto, motor interno para nuevas instalaciones. La selección afecta nuevas importaciones. Cada proyecto conserva `engine` y se regenera con ese motor. Los proyectos anteriores sin ese campo se interpretan como Ghidra. Para comparar motores, importa el archivo de nuevo con la otra opción; no se convierten ni sobrescriben proyectos.
