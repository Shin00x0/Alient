# Registro de funcionalidades del motor propio

Actualizado: 2026-10-06. Este registro separa capacidades implementadas de pendientes. “Lista” significa que tiene pruebas concretas; no implica paridad con Ghidra o IDA.

## Módulos listos para uso acotado

| Módulo | Funcionalidades listas | Pendientes específicos |
|---|---|---|
| N01 Modelo | Direcciones de 64 bits, referencias con espacio, overlays con prioridad de lectura, IDs estables, revisiones e historial | Descubrimiento y CFG multiespacio completos; corpus de corrupción ampliado |
| N02 Capacidades | Selección de motor, estados de proyecto y límites visibles | Fuente única para contratos |
| N03 Carga | ELF64, Mach-O64, PE32+, símbolos, imports y aplicación virtual de relocaciones absolutas conocidas | PDB/DWARF, relocaciones relativas/complejas y objetos relocatables |
| N04 Arquitecturas | ARM64/x86-64, subregistros, extensiones, FS/GS, paradas, intrínsecas FP/SIMD acotadas y especiales | AVX/AVX-512, NEON completo, flags FP, atómicas y corpus diferencial |
| N05 Descubrimiento | Entradas, llamadas, límites, thunks, prólogos y no-retorno directo | Unwind, no-retorno indirecto y código optimizado |
| N06 IR | Anchos, efectos, validación, evaluación, intrínsecas, flags concretos CF/ZF/SF/OF/PF y condiciones x86/ARM64 | Atomicidad, estado FP y endianness configurable por acceso |
| N07 Flujo de datos | Dominadores, liveness, SSA/phi, def-use, SCCP iterativo por aristas, rangos exactos, SSA de memoria y alias de pila/global | Rangos no exactos, alias estructural e incremental persistente |













## M14 — grafo de control de flujo web

| Funcionalidad | Estado | Alcance |
|---|---|---|
| CFG interactivo | Lista | Three.js local presenta los bloques básicos de la función seleccionada con sus instrucciones. |
| Aristas tipadas | Lista | Fallthrough, salto y llamada usan colores distintos; los bucles se mantienen como aristas de retorno. |
| Navegación | Lista | Seleccionar un bloque abre su dirección en el listing existente. |
| Cámara | Lista | Zoom con rueda, arrastre para pan y acción para centrar la vista. |
| Layout avanzado | Pendiente | Sin colapso de regiones, agrupaciones, layout cruzado mínimo ni comparación entre funciones. |
| Grafo de contexto IA | Pendiente | Es una vista separada del CFG y no forma parte de esta entrega. |

## N07 — propagación sensible a ramas

| Funcionalidad | Estado | Alcance |
|---|---|---|
| Aristas factibles | Lista | Una Branch con condición constante conserva sólo el destino tomado o el fallthrough |
| Constantes por ruta | Lista | Segunda pasada de constantes excluye predecesores imposibles antes de mezclar estados |
| Bloques inalcanzables | Lista | Se exponen como resultado del refinamiento, sin reescribir todavía el CFG persistido |
| SCCP por punto fijo | Lista | Repite constantes y aristas factibles hasta estabilizarse; expone bloques inalcanzables sin reescribir el CFG. |
| Rangos exactos y memoria | Lista | Publica valores constantes como rangos puntuales, accesos de memoria, alias de pila/global y versiones SSA de memoria. |
| Rangos no exactos y alias estructural | Pendiente | Sin intervalos derivados de condiciones ni solapamiento de campos/estructuras. |

## N06 — condiciones de flags

| Funcionalidad | Estado | Alcance |
|---|---|---|
| Flags leídos por condición | Lista | Condiciones x86 y ARM64 declaran CF/ZF/SF/OF/PF concretos además del estado agregado |
| Evaluación de condición | Lista | Condiciones comunes se evalúan cuando los flags concretos están disponibles |
| Escritura de flags | Lista | Statement::Flags declara el conjunto de flags que puede actualizar |
| Producción exacta de flags | Lista | Operaciones escalares soportadas calculan CF/ZF/SF/OF/PF si sus operandos son constantes; las ramas `cmp; je` se refinan. |
| Memoria y alias | Parcial | Hay SSA de memoria y alias de pila/global; faltan atomicidad, alias estructural y endianness por acceso. |

## N05 — funciones sin retorno

| Funcionalidad | Estado | Alcance |
|---|---|---|
| Clasificación por nombre | Lista | abort, exit, panic, fatal y nombres equivalentes se marcan sólo cuando son funciones locales descubiertas |
| Clasificación por parada | Lista | Una función alcanzable que sólo termina en Stop se marca sin retorno |
| Propagación de llamada directa | Lista | El caller de una función marcada sin retorno no conserva un fallthrough falso |
| Control conservador | Lista | Retornos, saltos indirectos, saltos fuera del cuerpo o rutas ambiguas impiden la clasificación |
| Imports y llamadas indirectas | Pendiente | No se resuelven aún bibliotecas externas, PLT/IAT ni destinos indirectos |

## N01 — espacios de direcciones

| Funcionalidad | Estado | Alcance |
|---|---|---|
| Referencia de dirección | Lista | AddressRef identifica espacio y dirección; las API anteriores siguen usando ram |
| Regiones por espacio | Lista | region_in, read_in y bytes_at_in resuelven una región sólo dentro del espacio solicitado |
| Overlays declarativos | Lista | Regiones con la misma dirección son válidas cuando sus espacios son distintos |
| Identidad de región | Lista | ID estable incluye programa, clase, espacio y dirección; duplicados se rechazan |
| Selección de overlay | Lista | `region_in`, lectura y offsets seleccionan la región de mayor prioridad en el mismo espacio. |
| Código/datos fuera de ram | Parcial | Instrucciones y datos guardan su espacio y se validan/serializan por él; discovery y CFG siguen en ram. |

## N02 y N03 — contratos desacoplados

| Módulo | Funcionalidad | Estado | Alcance |
|---|---|---|---|
| N02 | Catálogo de capacidades tipado | Lista | Arquitecturas, formatos, módulos, límites, ediciones y limitaciones se declaran fuera de la serialización JSON |
| N02 | Contrato de capacidades | Lista | Protocolo 2 expone catálogo detallado y conserva listas activas para la interfaz |
| N03 | Política de carga | Lista | Identificación de formato, arquitectura, endianness y tipo de objeto en loaders/catalog.rs |
| N03 | Lector de objetos | Lista | loaders/mod.rs conserva el recorrido de secciones, símbolos, imports y relocaciones tras validar la política |
| N04 | Catálogo de opcodes | Lista | FP/SIMD y especiales en architectures/opcodes.rs; el decodificador sólo ejecuta el lifting |
| N03 | Aplicación de relocaciones absolutas | Lista | Overlay virtual de bytes para destinos absolutos conocidos; no modifica el binario de entrada. |
| Objetos relocatables y relocaciones complejas | Pendiente | Sin enlace, PDB/DWARF, relocaciones relativas/PLT ni bibliotecas dinámicas. |

## N04 — SIMD, FP e instrucciones especiales

| Funcionalidad | Estado | Alcance comprobable |
|---|---|---|
| IR tipado opaco | Lista | Statement::Intrinsic conserva dominio, entradas/salidas, ancho de elemento, lanes, memoria y posibles traps; no convierte vectores a enteros de 64 bits |
| x86 FP escalar | Lista | add/sub/mul/div/sqrt/min/max SS/SD, movimientos, conversiones y comparaciones listadas por el levantador |
| x86 SIMD 128-bit acotado | Lista | PS/PD aritmético, movimientos XMM, lógica y suma/resta empaquetada listadas por el levantador |
| Prefijos SIMD x86 | Lista | F2/F3 dejan de ser una barrera genérica; LOCK y dirección de 32 bits permanecen como barrera |
| ARM64 FP | Lista | fadd/fsub/fmul/fdiv/fsqrt/fmax/fmin/fmov, comparaciones y conversiones representadas como intrínsecas |
| ARM64 especiales | Lista | mrs, msr, dmb, dsb e isb conservan efectos explícitos |
| x86 especiales | Lista | cpuid, rdtsc/rdtscp, xgetbv, rdrand y rdseed conservan salidas arquitectónicas |
| Memoria vectorial | Lista | Lecturas conservan __memory y los registros de la dirección; divisiones FP marcan posible excepción |
| F32Ghidra | Bloqueada | La ruta en Escritorio no es legible por el proceso debido a permisos de macOS; no se ha incorporado ni se atribuye código a esa extensión |
| AVX/AVX-512/NEON | Pendiente | Sin máscaras, predicación, registros ZMM, SVE ni operaciones de lane precisas |
| Estado FP | PendienteIm | Sin MXCSR/FPCR, redondeo, NaN, flags ni excepciones detalladas |
| Validación diferencial | Pendiente | Falta corpus amplio y comparación contra Ghidra/F32Ghidra una vez accesible |

## N08 ABI

| Funcionalidad | Estado | Alcance comprobable |
|---|---|---|
| Perfiles ABI | Lista | AAPCS64, SysV AMD64 y Win64: argumentos enteros, retorno y pila |
| Registros preservados | Lista | Metadatos ABI; no prueba de preservación por función |
| Parámetros por registro | Lista | Derivación desde entradas a través de phi cíclicos |
| Tipo básico | Lista | Enteros y candidato uint8_ptr cuando se usa como dirección |
| Estado de pila por CFG | Lista | Desplazamientos desde pila de entrada y unión conservadora |
| Slots locales | Lista | Lecturas/escrituras de pila con ancho máximo |
| Argumentos de pila | Lista | SysV desde +8, Win64 desde +40, AAPCS64 desde +0 |
| Shadow space Win64 | Lista | Rango +8..+39 separado de argumentos |
| Informe ABI por función | Lista | Llamadas, retornos, accesos de pila, evidencia de call sites y confianza por API/CLI |
| Argumentos constantes de llamada directa | Lista | Registro y valor constante disponibles por llamada; no infiere firma completa |
| Evidencia callee-saved | Lista | Save/restore en pila con registro, offset y dirección; no prueba todas las rutas |
| Argumentos FP/SIMD por registro | Lista | AAPCS64 V0–V7, SysV XMM0–XMM7 y Win64 XMM0–XMM3; evidencia de definición en llamada directa |
| Varargs, agregados y sret | Pendiente | Sin duplicación Win64, structs, HFA/HVA ni retorno indirecto |
| Marcos dinámicos/unwind | Pendiente | Sin alloca, red-zone, unwind ni excepciones |
| Prototipos interprocedurales | Pendiente | Sin firmas verificadas de callee |

## Próximas tareas específicas

1. N08: recuperar argumentos enteros de llamadas directas y exponer evidencia por call site.
2. N08: detectar guardado/restauración de callee-saved con evidencia por ruta.
3. N10: tablas de salto relativas a RIP/PC con límites comprobables.
4. N09: signedness y punteros desde accesos y comparaciones.
5. N11: estructuración de CFG reducibles de varias ramas.
