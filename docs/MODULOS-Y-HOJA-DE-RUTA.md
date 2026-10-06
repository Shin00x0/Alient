# Módulos, cobertura y hoja de ruta

> **Actualización 2026-09-15:** migración activa del motor interno a Rust. Consulta el [registro de avance y pendientes](AVANCE-MOTOR-RUST.md); las secciones históricas del motor TypeScript aún no describen el nuevo runtime.


**Proyecto:** Ghidra Web · **Fecha de revisión:** 9 de septiembre de 2026  
**Base revisada:** código local, `ESTADO.md`, documentación del motor interno y pruebas existentes.  
**Objetivo:** construir una herramienta web de análisis estático con precisión, navegación, capacidad de edición y legibilidad de resultados de nivel profesional, tomando Ghidra e IDA Pro como referencias de calidad.

Este documento inventaría nuestra implementación y propone su evolución. No es una comparación exhaustiva de versiones o licencias de esos productos, ni afirma paridad con ellos. El debugger queda fuera del alcance. Se mantiene TypeScript y una interfaz HTML/CSS/JavaScript sin framework.

## 1. Diagnóstico actual

Existen dos motores con capacidades diferentes:

- **Ghidra conectado:** utiliza el análisis y la decompilación reales de Ghidra. La aplicación web expone parte de sus resultados y operaciones; todavía tiene límites de exportación, latencia y edición.
- **Motor interno TS 0.1:** implementación propia sin dependencia de Ghidra ni Java. Lee Mach-O/ELF ARM64 y genera listing, referencias y una IR —representación intermedia— de operaciones sobre registros. **No recupera todavía C de alto nivel.**

Una interfaz que muestre pseudocódigo de Ghidra no demuestra que el motor propio sepa decompilar. Deben medirse por separado la calidad del motor, la cobertura expuesta por la API y la experiencia de la interfaz.

La prioridad propuesta es conseguir primero un análisis ARM64 fiable y comprobable, después una cadena de decompilación propia completa para un conjunto acotado de programas, y ampliar las arquitecturas sobre esa base. La integración con Ghidra permite seguir usando el producto y comparar resultados mientras se desarrolla el motor interno.

## 2. Inventario de módulos existentes

“Implementado” significa que existe código; las limitaciones y el nivel de validación se indican aparte. Las rutas se expresan respecto de la raíz `ghidra-web`.

| ID | Módulo y ubicación | Implementado | Falta o requiere evolución |
|---|---|---|---|
| M01 | Servidor y configuración · `backend/server.ts` | API local, selector interno/Ghidra, configuración persistida, motor por proyecto, capacidades consultables, límites de importación y cola | Extraer adaptadores de motor, errores y progreso estructurados, configuración por análisis |
| M02 | Contrato de resultados · `backend/types.ts` | Proyectos, funciones, instrucciones, referencias, páginas, tokens y estados de decompilación | Modelo semántico independiente de la vista, IDs estables, revisiones por entidad, procedencia/confianza y migraciones explícitas |
| M03 | Cargadores internos · `backend/engine/internal/loader.ts` | Mach-O enlazado y ELF ARM64 LE de 64 bits; regiones, base, entrada, símbolos y comprobación de rangos | PE, Mach-O universal, objetos relocatables, relocaciones, resolución de importaciones, metadatos de depuración y carga manual |
| M04 | Decodificador ARM64 · `backend/engine/internal/arm64.ts` | Subconjunto entero: saltos, llamadas, retornos, direcciones, inmediatos, aritmética, lógica y variantes de carga/almacenamiento; desconocidas como `.inst` | ARM64 completo, semántica exhaustiva de flags y registros, SIMD/FP, casos reservados y pruebas diferenciales extensas |
| M05 | Análisis interno · `backend/engine/internal/index.ts` | Barrido de regiones de código, candidatos de funciones, llamadas/saltos directos, constantes ADR/ADRP + ADD, cadenas, referencias y bloques de flujo | Separar código/datos, cuerpos precisos, análisis de flujo de datos, pila, ABI, saltos indirectos, tablas de salto y análisis entre funciones |
| M06 | IR interna · `arm64.ts` e `index.ts` | Descripción de operaciones sobre registros y memoria con dirección de origen; salida marcada como parcial | IR estructurada y tipada, SSA, modelo de memoria, optimizaciones justificadas, reconstrucción de variables y C |
| M07 | Ejecución interna · `backend/engine/internal/worker.ts` y servidor | Worker Node, cancelación, límites de tiempo/heap, publicación de JSON y listing | Planificador incremental, reanudación, límites efectivos de recursos y recuperación tras fallo; el worker no es un sandbox de seguridad |
| M08 | Adaptador Ghidra · `scripts/ExportWeb.java`, `ExportListing.java` y servidor | Programa persistente, análisis headless, C real, tokens, variables, tipos, referencias, listing completo y decompilación bajo demanda | Servicio residente, opciones de análisis, consultas paginadas para todos los índices y eliminación de exportaciones auxiliares truncadas |
| M09 | Ediciones Ghidra · `scripts/MutateWeb.java` | Nombres/etiquetas, comentarios, firmas, nombre/tipo de variable y marcadores; transacción con rechazo/rollback | Crear/borrar funciones e instrucciones, definir datos, referencias manuales, estructuras, parches y undo/redo |
| M10 | API del listing · `backend/listing.ts` | Páginas de 256 filas, búsqueda por dirección, espacios de memoria, direcciones interiores y precisión de 64 bits | Selecciones/rangos, índices de datos además de instrucciones, consultas escalables y cambios incrementales |
| M11 | Navegación · `frontend/listing-view.ts`, `frontend/app.ts` | Páginas, selección, historial, salto a dirección/nombre, atajos y enlaces a referencias | Desplazamiento virtual continuo, selección múltiple, menús contextuales, navegación más precisa entre vistas y preferencias |
| M12 | Vista de C/IR · `frontend/code-view.ts`, `frontend/app.ts` | Tokens, copia del texto, enlaces al listing, distinción visual C/IR y descarte de respuestas obsoletas | Identidad semántica de variables, referencias por token, edición contextual, correspondencia muchos-a-muchos C/instrucciones |
| M13 | Exploradores · `frontend/explorer.ts` | Cadenas, XREF, símbolos, importaciones/entradas, tipos, variables, marcadores y filtros | Búsqueda global indexada, regex, escalares, UTF-16, cadenas no definidas y resultados paginados completos |
| M14 | Grafos · `frontend/cfg-graph.ts`, `cfg-layout.ts` y `explorer.ts` | CFG local Three.js con bloques, instrucciones, aristas tipadas, layout por capas, zoom/pan, bucles y salto al listing; relaciones de llamadas en SVG | Agrupaciones, colapso de subgrafos, grafo global y presentación de incertidumbre |
| M15 | Proyectos y almacenamiento · servidor, `data/` | Archivo original, SHA-256, estado, notas, resultados JSON, generaciones del listing; base Ghidra en su modo | Borrado/renombrado, limpieza de revisiones, migraciones, respaldos, índice transaccional y recuperación robusta |
| M16 | Pruebas y comparación · `tests/`, `scripts/VerifyWeb.java`, `scripts/verify-project.mjs` | Pruebas unitarias/API y de Ghidra real; verificación independiente de resultados y fixtures | Corpus amplio, fuzzing, pruebas semánticas, rendimiento, interacción del navegador y matriz de plataformas |
| M17 | Distribución y extensibilidad · `package.json`, `scripts/build-native-macos.sh` | Compilación TypeScript, inicio local, preparación nativa de Ghidra en macOS | Instalador reproducible, CI multiplataforma, API de analizadores/plugins y política de compatibilidad |

## 3. Cobertura funcional por motor

La interfaz compartida puede mostrar una pestaña aunque el motor seleccionado no tenga datos para ella. Eso no cuenta como una capacidad implementada del motor.

| Funcionalidad | Ghidra conectado en esta aplicación | Motor interno |
|---|---|---|
| Formatos y arquitecturas | Detección delegada a Ghidra; cobertura probada limitada a los fixtures usados | Mach-O/ELF ARM64 LE de 64 bits enlazados |
| Listing | Todas las instrucciones definidas por Ghidra, paginadas | Barrido lineal de palabras ARM64; puede incluir datos incrustados |
| Reconocimiento de funciones | Funciones del programa Ghidra | Candidatos por símbolos, entrada, llamadas y regiones; cuerpos inferidos |
| Desensamblado | Motor Ghidra | Subconjunto ARM64; palabras desconocidas visibles |
| C decompilado | Sí, generado por Ghidra; otras funciones bajo demanda | No; IR de registros explícitamente parcial |
| Variables, parámetros y tipos | Consulta y algunas ediciones | Pendiente; firma desconocida y sin recuperación de variables |
| Cadenas | Cadenas definidas exportadas desde Ghidra | ASCII/NUL en regiones no marcadas como código, con tabuladores/saltos de línea |
| XREF | Referencias exportadas, con límites | Saltos/llamadas directos y algunas direcciones constantes |
| Flujo | Bloques del programa Ghidra | Bloques derivados del barrido y de flujos reconocidos |
| Símbolos/importaciones | Tablas exportadas con límites | Símbolos de archivo; sin enlace completo de importaciones o relocaciones |
| Edición del programa | Operaciones concretas ya soportadas | Pendiente |
| Anotaciones web | Sí | Sí |
| Buscar bytes | Archivo original, con límite de coincidencias | Misma API compartida |
| Persistencia | Base Ghidra, JSON y notas | JSON, listing y notas |
| Independencia de Ghidra | No | Sí, probada con Java/Ghidra no disponibles |

## 4. Límites que deben quedar visibles

| Ámbito | Límite actual |
|---|---|
| Importación/planificación | 32 MiB por archivo; hasta tres análisis pendientes/activos; un trabajo de motor a la vez |
| Exportación inicial Ghidra | Hasta 200 funciones; se pueden solicitar otras bajo demanda |
| Datos auxiliares por función Ghidra | Hasta 500 instrucciones, 200 referencias entrantes, 500 bloques, 100 destinos por bloque y 500 variables |
| Índices Ghidra | Hasta 2000 cadenas, 100000 referencias globales, 20000 símbolos, 10000 tipos y 5000 marcadores |
| Listing principal Ghidra | No hereda los topes de 200 funciones/500 instrucciones; contiene las instrucciones definidas por el motor |
| Búsqueda textual | La vista de ensamblador/C busca en datos cargados, no garantiza cobertura global del programa |
| Presentación | Tablas auxiliares limitadas a 300 resultados filtrados; grafo de llamadas acotado |
| Bytes | Patrón de hasta 64 bytes y hasta 200 coincidencias devueltas |
| Ghidra: recursos | Heap Java 2 GiB; análisis automático 5 min; trabajo completo 10 min; decompilación según opciones, normalmente 30 s/función; solicitud bajo demanda 2 min totales |
| Motor interno | Hasta 100000 palabras ARM64; 20000 cadenas de hasta 4096 caracteres; worker con heap de 256 MB y 2 min |
| Persistencia | Se conservan generaciones anteriores del listing; no hay limpieza automática |

No debe aumentarse un límite sin medir memoria, latencia y comportamiento ante cancelación. La solución a escala es consultar e indexar por demanda, no cargar todo el programa en el navegador.

## 5. Módulos nuevos necesarios para el motor propio

Las siguientes rutas son **propuestas**, salvo N01 (`backend/engine/core/program/`) y N02 (`backend/engine/capabilities.ts`), ya implementados en su alcance descrito. Se recomienda separar estos módulos a medida que entren en desarrollo, evitando convertir `index.ts` en un analizador monolítico.

| ID | Módulo propuesto | Responsabilidad | Dependencias principales |
|---|---|---|---|
| N01 | `backend/engine/core/program/` · implementado | Programa, espacios de direcciones, memoria, instrucciones, funciones y datos; IDs estables, transacciones, revisiones y snapshots validados | Contrato M02 |
| N02 | `backend/engine/capabilities.ts` · primera versión implementada | Contrato de cobertura, runtime y operaciones por motor/proyecto; consulta API e integración con pestañas | M01, M02 |
| N03 | `engine/loaders/` | Un lector por formato; imports/exports, relocaciones y fuentes de nombres | N01, M03 |
| N04 | `engine/architectures/` | Decodificadores y semántica por arquitectura; registros, anchos y endianness | M04, N01 |
| N05 | `engine/analysis/discovery` | Descubrimiento de código, separación de datos, límites de funciones y CFG | N03, N04 |
| N06 | `engine/ir/` | Operaciones tipadas, efectos, registros, memoria y procedencia por dirección | N04 |
| N07 | `engine/analysis/dataflow` | SSA (asignación única), dominadores, constantes, usos/definiciones y simplificación | N05, N06 |
| N08 | `engine/analysis/abi` | Convenciones de llamada, pila, parámetros, retornos y registros preservados | N03, N06, N07 |
| N09 | `engine/types/` | Tipos, punteros, estructuras/uniones/enums, propagación y restricciones del usuario | N07, N08 |
| N10 | `engine/analysis/indirect` | Tablas de salto, llamadas indirectas y propagación entre funciones | N07, N08, N09 |
| N11 | `engine/decompiler/` | Expresiones, variables, `if`, bucles, `switch`, AST y emisión de C legible | N05–N10 |
| N12 | `engine/storage/` | Índices persistentes, búsquedas, revisiones, transacciones y caché | N01 |
| N13 | `engine/commands/` | Ediciones, validación, deshacer/rehacer e invalidación de resultados dependientes | N01, N09, N12 |
| N14 | `engine/scheduler/` | Trabajos incrementales, progreso, prioridades, cancelación y presupuestos | N01, N12 |
| N15 | `engine/extensions/` | Analizadores y cargadores extensibles con contratos versionados | N02, N13, N14 |

El módulo interno debe seguir funcionando sin importar código del adaptador Ghidra. Ghidra puede utilizarse en pruebas comparativas opcionales, pero su ausencia no debe impedir instalar, iniciar ni analizar formatos soportados por el motor interno.

## 6. Orden recomendado de implementación

Las prioridades indican dependencia e impacto, no una promesa de fechas. Cada fase debe dejar una versión utilizable y pruebas de regresión.

### Fase A — Base fiable y medible · prioridad P0

- Definir capacidades por motor y estados uniformes: completo, parcial, no soportado, cancelado y fallido.
- Separar modelo de programa, decodificador, análisis y presentación.
- Corregir el descubrimiento de funciones y la clasificación código/datos; conservar procedencia y permitir marcar incertidumbre.
- Ampliar ARM64 entero sobre casos reales y comprobar tamaños, operandos, saltos y efectos.
- Crear corpus versionado de binarios pequeños con fuentes, compilador/opciones y resultados esperados.
- Mejorar recuperación de errores, publicación de resultados y limpieza de generaciones.

**Criterio de salida:** todos los casos declarados soportados del corpus pasan; instrucciones no soportadas nunca se inventan; una caída o cancelación no altera un resultado previamente válido. Se publica la cobertura y el número de errores conocidos.

### Fase B — Fundamentos de decompilación · prioridad P0

- Sustituir la IR textual como base de análisis por operaciones estructuradas, con anchos, efectos y tipos elementales.
- Construir CFG fiable, dominadores y SSA; implementar propagación de constantes y eliminación de operaciones solo cuando sea válida.
- Modelar flags, alias de registros y memoria de manera conservadora.
- Recuperar pila, argumentos y retornos para la ABI ARM64 elegida.

**Criterio de salida:** aritmética, comparaciones, llamadas y accesos a pila del corpus se representan correctamente. Las transformaciones de IR preservan resultados en pruebas semánticas controladas. La salida sigue llamándose IR mientras no exista recuperación de alto nivel.

### Fase C — Primer decompilador propio útil · prioridad P1

- Recuperar variables locales, expresiones y tipos básicos; integrar nombres e información disponible del binario.
- Reconstruir condicionales, bucles y `switch`; usar `goto` explícito cuando el flujo no pueda estructurarse con seguridad.
- Emitir un AST y C legible con enlaces a sus instrucciones de origen.
- Admitir renombrado y correcciones de tipos con recálculo de la función afectada.

**Criterio de salida:** funciones del corpus con argumentos, variables locales, llamadas, condiciones y bucles generan C comprensible y semánticamente comprobado. Se distingue entre resultado válido, parcial y fallido por función. La similitud visual con Ghidra o IDA no sustituye la validación de comportamiento.

### Fase D — Cobertura de binarios habituales · prioridad P1

- Añadir ELF/Mach-O x86-64 y PE x86-64 mediante el contrato de arquitectura.
- Incorporar relocaciones, enlace de importaciones, thunks, tablas de salto y convenciones de llamada relevantes.
- Leer símbolos de depuración; recuperar tipos/estructuras y mejorar nombres C++.
- Ampliar ARM64 y otros conjuntos de instrucciones según el corpus objetivo.

**Criterio de salida:** matriz explícita formato × arquitectura × compilador × optimización, con resultados reproducibles. No anunciar soporte de una arquitectura solo porque su cabecera se reconoce.

### Fase E — Flujo de trabajo de análisis completo · prioridad P1

- Crear/borrar funciones, desensamblar rangos y definir datos/cadenas.
- Editar referencias, tipos y estructuras; añadir undo/redo y marcadores completos.
- Integrar menús contextuales, navegación por tokens, selección sincronizada, búsqueda global y grafos navegables.
- Paginar los índices Ghidra restantes y reducir su latencia sin introducir dependencia en el motor interno.

**Criterio de salida:** un analista puede corregir una función mal detectada, tipar sus datos, revisar XREF y guardar/reabrir el proyecto sin perder sus cambios. Las búsquedas informan su cobertura real.

### Fase F — Escala y distribución · prioridad P2

- Análisis incremental, almacenamiento indexado, virtualización de vistas y caché con invalidación comprobada.
- Benchmarks, fuzzing sostenido y pruebas de recuperación ante falta de espacio o interrupciones.
- Instalación/CI multiplataforma, importación/exportación de proyectos y extensión por analizadores.
- Incorporar aislamiento y sesiones únicamente si se habilita operación remota o multiusuario.

**Criterio de salida:** objetivos de rendimiento fijados sobre hardware y corpus publicados; cancelación efectiva, consumo acotado y recuperación verificada. Los límites se elevan con mediciones.

## 7. Cómo medir un resultado «muy bueno»

Se proponen estas métricas; **no son resultados ya alcanzados**. Los umbrales numéricos se deben acordar después de medir una línea base sobre el corpus objetivo.

| Dimensión | Medición | Regla para aceptar una mejora |
|---|---|---|
| Decodificación | Longitud, operandos, destino y semántica frente a casos conocidos | Cero discrepancias sin explicar dentro del subconjunto declarado soportado |
| Funciones | Precisión/recobrado de entradas y cuerpos frente a fixtures con verdad conocida | Informar falsos positivos y omisiones; no contar todas las etiquetas como funciones correctas |
| Referencias | XREF esperadas/encontradas, directas e indirectas por separado | Sin referencias inventadas; distinguir referencia confirmada de hipótesis |
| Decompilación | Casos completados, errores semánticos, construcciones recuperadas y lectura humana | No aceptar una simplificación que cambia el comportamiento por mejorar la apariencia |
| Tipos y variables | Argumentos, retornos, pila y estructuras recuperados | Comparar contra casos conocidos y conservar correcciones del usuario |
| Interacción | Recorrido importación → cadena → XREF → función → edición → reapertura | Pruebas automatizadas del navegador y revisión de accesibilidad |
| Rendimiento | Tiempo de importación, memoria máxima, latencia p50/p95 y cancelación | Publicar hardware, tamaño de archivo, funciones y condiciones de caché |
| Robustez | Entradas malformadas, truncadas, enormes, cancelaciones y disco lleno | Fallo explícito, sin bloqueo del servidor ni corrupción del proyecto válido |
| Independencia | Arranque/análisis/pruebas con rutas Ghidra/Java ausentes | La suite del motor interno continúa funcionando |

Las pruebas semánticas que ejecuten código deben limitarse a fixtures propios, compilados para pruebas y en un entorno controlado. El producto sigue siendo de análisis estático y no ejecuta los binarios importados por el usuario.

## 8. Validación disponible y vacíos

La última implementación dejó registradas **ocho pruebas aprobadas**; cuatro específicas del motor interno se repitieron después de los ajustes finales. Esta revisión documental no vuelve a ejecutar la suite ni amplía su cobertura.

Evidencia existente:

- API y flujo con Ghidra real: importación, decompilación, ediciones, persistencia, listing y decompilación fuera de las primeras 200 funciones.
- Motor interno: ELF sintético, saltos con direcciones de 64 bits, desconocidas, entradas truncadas y rangos inválidos.
- Mach-O interno: fixture de 31 instrucciones, cadenas con saltos de línea y XREF; otro de 1431 instrucciones y más de 200 funciones.
- Funcionamiento interno sin Java/Ghidra disponibles, selección persistente, anotaciones y regeneración.
- Navegación del listing: direcciones interiores, huecos, espacios de memoria y precisión de 64 bits.

Vacíos principales:

- No hay corpus representativo de ejecutables grandes y optimizados.
- No hay demostración de equivalencia semántica de un decompilador interno de C: todavía no existe esa etapa.
- No hay validación extensa de cada codificación ARM64 ni de recuperación precisa de cuerpos de función.
- No se han automatizado las interacciones completas de la interfaz.
- No se ha medido una matriz amplia de formatos, arquitecturas o sistemas operativos.

Ocho pruebas aprobadas validan esos escenarios concretos, no equivalen a ocho módulos completos ni a un porcentaje de paridad profesional.

## 9. Próximo incremento propuesto

El siguiente incremento debería concentrarse en la **Fase A** y preparar la **Fase B**:

1. **Implementado:** contrato `EngineCapabilities` y UI que deshabilita operaciones inexistentes. El siguiente punto pendiente es la IR estructurada.
2. Separar la IR estructurada de su representación textual, manteniendo enlaces a instrucciones.
3. Añadir fixtures ARM64 con ramas, bucles, pila, llamadas, datos incrustados y símbolos ausentes.
4. Corregir el descubrimiento de cuerpos y crear pruebas de límites de funciones y CFG.
5. Registrar cobertura de instrucciones y análisis por archivo y por función.

**Resultado esperado de ese incremento:** motor interno más fiable y con una base comprobable para decompilar. La ampliación a x86-64 debe reutilizar ese diseño en lugar de duplicar un analizador textual.

## 10. Mantenimiento del documento

Por cada entrega, actualizar: módulo/ID afectado, capacidad nueva, motor al que aplica, límites, pruebas/evidencias, pendientes y criterio de aceptación cumplido. Mantener separados «implementado», «probado» y «propuesto».

`ESTADO.md` sirve como resumen de cobertura. Este documento reúne el mapa de módulos, dependencias y prioridades. `backend/engine/internal/README.md` describe el contrato y los límites técnicos del módulo independiente.

## Entrega N02 — Contrato de capacidades

Implementado `backend/engine/capabilities.ts` con versión de esquema, identidad del motor, disponibilidad del runtime, alcance de entrada, capacidades `supported/partial/unsupported`, operaciones de edición y disponibilidad de acciones según el estado del proyecto. No es un detector exhaustivo de formatos ni una garantía de éxito del análisis.

API: `GET /api/engines` presenta ambos motores; `GET /api/projects/:id/capabilities` describe el motor del proyecto, independientemente de la configuración de nuevas importaciones. Los proyectos antiguos sin motor explícito siguen siendo Ghidra.

UI: pestaña «Capacidades del motor», pestañas no soportadas deshabilitadas, nombre «Buscar IR» para el motor interno, edición y regeneración según disponibilidad. Los resultados Ghidra guardados siguen consultables aunque falte el runtime. La API valida las ediciones con el mismo contrato; las comprobaciones de cola y concurrencia siguen aplicándose al enviar la operación.

El contrato describe la cobertura del adaptador web, no todas las funciones del Ghidra original. Quedan pendientes los presupuestos estructurados, la selección detallada de arquitectura/formato y la actualización en tiempo real de capacidades si cambia el runtime durante la sesión. Próximo módulo: N06, IR estructurada, antes de SSA y reconstrucción de C.

## Entrega N01 — Modelo central del programa

Implementado el núcleo independiente `backend/engine/core/program/`: espacios de direcciones por byte de hasta 64 bits, rangos, memoria respaldada por archivo/cero/desconocida, instrucciones, funciones y datos. Identidades deterministas por contenido original y anclaje, revisión global/por entidad, transacciones atómicas, conflictos de revisión, diario de IDs creados/actualizados/borrados y snapshots de esquema 1 con validación al restaurar.

El motor interno usa el núcleo para leer regiones y registrar el análisis; guarda `program.json` en cada generación del listing. Regenerar sin cambios conserva identidades y revisiones. Los proyectos antiguos crean el modelo al regenerar. Consulta de solo lectura: `/api/projects/:id/program`. El adaptador Ghidra no se ha migrado al núcleo propio.

Este módulo no implementa SSA/IR semántica, edición del programa desde la UI, undo/redo, invalidación de análisis dependientes ni migraciones de esquemas futuros. Esas funciones pertenecen a N06, N13, N14 y la evolución del almacenamiento. M02 sigue parcial; completar N01 no completa todos los contratos de resultados de la aplicación.

## Entrega N04 — Rust, 15 de septiembre de 2026

Entrega acotada completada: extensiones x86 con/sin signo, TLS FS/GS simbólico, LEA, direccionamiento RIP y paradas explícitas. Diez pruebas nuevas; 36 pruebas Rust aprobadas en total. XorGate conserva 210 instrucciones y 15 funciones y pasa de 8 instrucciones sin representación semántica a 0, con los límites de TLS y excepciones explícitos. [Detalle y pendientes de N04](N04-ARQUITECTURAS.md).

Modo de trabajo vigente: implementar una entrega de un módulo y parar. Se cierra N04 en este alcance; no se inicia N05 automáticamente.

## Entrega N05 — 2026-09-15

Descubrimiento Rust ampliado con límites declarados, cuerpos corregidos tras llamadas tardías, colas compartidas, thunks directos y recuperación conservadora de prólogos. Procedencia y transferencias visibles en Flujo. 14 pruebas específicas; pendientes y alcance en [N05-DESCUBRIMIENTO.md](N05-DESCUBRIMIENTO.md). La entrega se detiene aquí, sin iniciar N06.

## Entrega N06 — 2026-09-15

Contrato IR validado, efectos conservadores por sentencia, consulta con procedencia por dirección/índice y correcciones de evaluación de desplazamientos y subregistros. 13 pruebas específicas. Alcance y pendientes: [N06-IR.md](N06-IR.md). La tarea se detiene en N06, sin iniciar N07.

## Entrega N07 — 2026-09-18

Dominadores inmediatos/fronteras, liveness, phis restringidos a fusiones vivas, índices inversos de usos y constantes por sentencia. 13 pruebas específicas. Alcance y pendientes: [N07-FLUJO-DE-DATOS.md](N07-FLUJO-DE-DATOS.md). Se detiene en N07, sin iniciar N08.
