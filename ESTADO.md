# Cobertura funcional — Ghidra Web 0.2

> **Actualización 2026-09-15:** migración activa del motor interno a Rust. Consulta el [registro de avance y pendientes](docs/AVANCE-MOTOR-RUST.md); las secciones históricas del motor TypeScript aún no describen el nuevo runtime.


Clon en desarrollo del flujo de análisis estático de Ghidra. TypeScript, HTML y CSS sin framework. Dos opciones de motor: Ghidra 12.1.3 e interno Rust (ARM64/x86-64). La tabla inicial describe la cobertura del motor Ghidra; el interno tiene la cobertura específica indicada al final. **No tiene todavía paridad completa con Ghidra de escritorio.** Debugger excluido por decisión del usuario.

## Implementado

| Área | Funcionalidades disponibles |
|---|---|
| Proyectos | Importar binarios, detectar formato/arquitectura con Ghidra, cola, registro, cancelación, reapertura, SHA-256 |
| Persistencia del motor | Se conserva la base de datos Ghidra; regeneración y edición reutilizan el programa. Los proyectos antiguos se migran al regenerar |
| Funciones | Buscar por nombre/dirección/etiqueta, firmas, función de entrada, distinguir funciones, thunks e importaciones sin código |
| Listing | Todas las instrucciones definidas por Ghidra, en páginas de 256; primera/anterior/siguiente/última, número de página, salto a dirección, bytes, comentarios, etiquetas, función y enlaces a referencias |
| Decompilación | Opciones del motor y compilador, nombres C++ desambiguados por demanglers GNU, tokens semánticos, sangría, copia exacta, enlaces a instrucciones |
| Cadenas | Filtrar por texto/dirección, contar y abrir XREF; referencias al inicio o interior de la cadena |
| Referencias cruzadas | Índice real de Ghidra, XREF entrantes/salientes por dirección, referencias de función, salto al origen y destino |
| Búsqueda | Funciones, cadenas, símbolos, instrucciones/bytes/comentarios de listing, líneas de pseudocódigo, tipos, marcadores |
| Búsqueda de bytes | Patrón hexadecimal y comodín `??` sobre el archivo original; resultados enlazados al visor hexadecimal |
| Navegación | Ir a dirección o nombre exacto de función, historial atrás/adelante, atajos G, X, Alt+flechas |
| Símbolos | Tabla con namespace/nombre completo, dirección, tipo y XREF; vistas de importaciones y puntos de entrada exportados |
| Memoria | Bloques, base, tamaño y permisos; hexadecimal original paginado |
| Flujo | Grafo de bloques básicos obtenido de Ghidra; aristas por tipo, selección para navegar al listing |
| Llamadas | Relaciones de llamada de la función seleccionada, lista y grafo navegable |
| Variables | Variables locales y parámetros de HighFunction, tipo y almacenamiento |
| Tipos | Catálogo del programa con nombre, ruta y tamaño |
| Edición real | Renombrar función/símbolo o crear etiqueta; comentario EOL y de función; firma C; nombre/tipo de variable; marcador |
| Aplicación de cambios | Transacción Ghidra con rollback si se rechaza la operación; guardado y actualización del pseudocódigo |
| Anotaciones web | Etiquetas/notas por función independientes de los cambios del motor |
| Marcadores | Mostrar marcadores de Ghidra y crear notas del programa |
| Exportación | JSON de resultados/metadatos y copia del C de la función |
| Validación local | Loopback, Host/Origin, tamaño y colas limitados, límites de tiempo y heap Java |

## Límites actuales (visibles o documentados)

- El listing principal y el índice de nombres de función no tienen límite de 200 funciones ni de 500 instrucciones. Se generan desde todas las instrucciones definidas por Ghidra.
- La exportación auxiliar para decompilación, grafos y búsquedas de texto mantiene hasta 200 funciones, 500 instrucciones por función, 200 referencias a entrada de función y 2000 cadenas definidas.
- Índice global: 100 000 referencias, 20 000 símbolos, 10 000 tipos, 5000 marcadores; 500 bloques de flujo y 500 variables por función. Cada tabla presenta los primeros 300 resultados filtrados.
- La búsqueda de instrucciones y C cubre la exportación, no las funciones/instrucciones omitidas. La búsqueda de bytes sí lee todo el archivo original, con máximo 200 coincidencias y patrón de 64 bytes.
- Los grafos usan las relaciones reales de Ghidra con distribución visual simple. El grafo de llamadas muestra hasta 100 nodos de la función seleccionada, no todo el programa.
- 32 MiB por archivo; hasta tres trabajos activos/en cola y uno ejecutándose. Análisis automático 5 minutos, decompilación 30 segundos/función, trabajo completo 10 minutos. Heap Java 2 GiB.
- La JVM se inicia por trabajo. Hay proyecto persistente, pero no un motor residente con interacción de baja latencia.
- Cambiar el tipo de variable requiere una ruta existente del panel Tipos y almacenamiento compatible; Ghidra puede rechazarla. No hay editor gráfico de estructuras.
- Importaciones sin implementación no se decompilan. Los thunks con instrucciones conservan el pseudocódigo del motor.
- La regeneración conserva cambios del programa. La verificación independiente contra una importación limpia solo es comparable antes de aplicar cambios personalizados.
- Uso local, sin autenticación multiusuario, contenedores ni control del consumo de memoria nativa.

## Pendiente para acercarse a la paridad con Ghidra

| Subsistema | Pendiente |
|---|---|
| Escala | Búsqueda de texto global bajo demanda, eliminar límites de la exportación auxiliar (listing completo paginado ya disponible) |
| Análisis | Selección de loader, arquitectura, endianness/base; configuración de analizadores y análisis parcial/interactivo |
| Listing editable | Crear/borrar funciones e instrucciones, desensamblar rangos, definir datos/cadenas, referencias manuales |
| Tipos | Crear estructuras/uniones/enums, campos, aplicar tipos a memoria, importar/exportar archivos de tipos |
| Decompilador | Interacción completa con tokens/variables, selecciones, referencias tipadas, cambios de convención/almacenamiento avanzados |
| Referencias | Cobertura sin límites, referencias indirectas adicionales y edición manual |
| Grafo | Layout jerárquico avanzado, agrupación, zoom/pan, grafo completo del programa |
| Búsquedas | Expresiones regulares, escalares, instrucciones estructuradas, patrones avanzados y cadenas todavía no definidas |
| Edición | Undo/redo persistente, parcheo de bytes, exportación del binario parcheado, borrado de marcadores/símbolos |
| Proyectos | Borrar/renombrar proyectos, importar/exportar proyectos Ghidra completos, recuperación robusta tras interrupciones |
| Extensiones | Scripts de usuario, plugins, Function ID/BSim, comparación/version tracking, herramientas especializadas |
| Distribución | Instalador multiplataforma, soporte Windows y validación extensa Linux/PE/otras arquitecturas |
| Operación | Sesiones multiusuario, permisos, aislamiento y alojamiento remoto |
| Interfaz | Pruebas completas de interacción/accesibilidad, paneles redimensionables avanzados y preferencias |

## Verificación

- TypeScript estricto y pruebas automatizadas de integración con Ghidra real.
- Mach-O AArch64: decompilación, instrucciones, cadenas con XREF y C++ con namespace recuperado.
- Ediciones: nombre de función, firma C, nombre de parámetro, comentarios EOL/de función, marcador; persistencia al reiniciar y rechazo transaccional de nombre vacío.
- Búsqueda de bytes y entradas inválidas; comparación de direcciones de 64 bits y XREF al interior de cadenas.
- XorGate ELF x86-64: verificación previa independiente de 16 funciones e instrucciones idénticas y 11 entradas EXTERNAL sin cuerpo. Informe conservado en `docs/XorGate-verification.json`.
- No se ha verificado paridad con preferencias particulares del escritorio ni se ha realizado una prueba automatizada de interacción de todas las vistas web.

Verificación de exploración en XorGate 0.2: 88 cadenas, 240 referencias, 120 símbolos y 46 bloques de flujo. Se verificaron dos XREF de una cadena de bienvenida hacia instrucciones de `main` que están incluidas en el listing. Informe: `docs/XorGate-explorer-verification.json`. Los cinco proyectos previos completados fueron migrados al esquema 4 con base de datos persistente.

## Listing completo

El script `ExportListing.java` genera páginas de instrucciones de todo el programa e índice completo de funciones desde Ghidra. La API sirve páginas o resuelve una dirección, incluyendo direcciones interiores a una instrucción y espacios de memoria. Si no existe una instrucción en el destino, muestra la más cercana y lo informa; no inventa instrucciones ni desensambla bytes no analizados.

Las nuevas generaciones se publican al completar el análisis y se regeneran tras editar. Los proyectos anteriores necesitan regenerarse para incorporar el índice. Se conservan las generaciones anteriores en disco; la limpieza automática de ese historial de índices sigue pendiente.

La navegación del listing usa clic, flechas arriba/abajo, Page Up/Page Down y controles de páginas. Las funciones fuera de la exportación C se decompilan bajo demanda al seleccionarlas.

Verificación del listing: cuatro pruebas aprobadas, incluida integración con Ghidra real; fixture de 1431 instrucciones distribuidas en seis páginas y más de 200 funciones. Se comprobaron recorrido sin duplicados ni omisiones, salto a una instrucción posterior a la número 500, índice completo de funciones, páginas inválidas, direcciones interiores, huecos, espacios de memoria y precisión de 64 bits. Los cambios de nombre/comentario también aparecen en el índice regenerado.

## Decompilación bajo demanda

Implementado: selección de cualquier función desde el listing y solicitud al mismo `ExportWeb.java`, con las mismas opciones y PrettyPrinter que la exportación inicial. Incluye tokens, variables y grafo con sus límites auxiliares existentes. Caché en disco por generación del listing; los cambios y reanálisis generan una revisión nueva. Las solicitudes simultáneas a la misma función comparten trabajo y la interfaz descarta respuestas de selecciones anteriores. Las anotaciones web aceptan también funciones del índice completo.

Límites: arranque de JVM por función nueva, una operación de motor a la vez, botón para reintentar si está ocupado y límite total de dos minutos. La exportación inicial sigue precargando 200 funciones; las búsquedas locales de pseudocódigo solo cubren funciones cargadas. No hay motor residente ni paridad completa con la interfaz del escritorio.

Verificación adicional: cuatro pruebas aprobadas (integración real en 59 segundos). Se decompiló `listing_part_229`, ausente de la exportación inicial, se comprobó la respuesta compartida de dos solicitudes simultáneas, la recuperación posterior desde caché y el rechazo de una función inexistente. No se ha probado visualmente esta interacción en el navegador.

## Motor interno Rust — estado vigente

N01–N14 tienen una implementación inicial conectada a la aplicación: carga, decodificación, CFG, IR, SSA, ABI/tipos, indirectos, C parcial, persistencia, comandos y ejecución. Incluye undo/redo y búsqueda indexada. No tiene paridad con Ghidra/IDA. La cobertura, límites y verificaciones actuales están en [AVANCE-MOTOR-RUST.md](docs/AVANCE-MOTOR-RUST.md) y [la documentación del motor](engine-rust/README.md).

## Histórico: motor interno TypeScript — sustituido por Rust

| Área | Implementado | Pendiente |
|---|---|---|
| Configuración | Selección interna/Ghidra persistida; motor propio por proyecto; proyectos antiguos conservan Ghidra | Conversión entre motores dentro del mismo proyecto |
| Independencia | Código TypeScript y APIs Node; análisis en worker; sin invocar Java/Ghidra | Motor residente incremental |
| Carga | Mach-O y ELF ARM64 LE de 64 bits enlazados; comprobación de rangos; secciones y símbolos | x86/x86-64, PE, FAT, objetos relocatables y demás arquitecturas |
| Listing | Palabras ARM64 en páginas de 256, navegación y referencias; `.inst` para desconocidas | Conjunto completo ARM64, separación precisa entre código y datos |
| Análisis | Cadenas ASCII/NUL, llamadas/saltos directos, ADR/ADRP + ADD, bloques de flujo y funciones inferidas | Referencias indirectas completas, relocaciones, límites precisos de cuerpos |
| Pseudocódigo | IR de registros enlazada a instrucciones, identificada como parcial | SSA, pila, variables, tipos, control estructurado y decompilación C comparable a Ghidra |
| Persistencia | Resultados JSON, regeneración, anotaciones web, cancelación de worker | Ediciones del programa y tipos, parches y undo/redo |

El motor interno no es un port del decompilador de Ghidra. Se inspira en su organización por fases, con implementación propia y sin dependencia de su código ni runtime. Máximo 100000 palabras ARM64 y 20000 cadenas ASCII de hasta 4096 caracteres. Véase `backend/engine/internal/README.md`.

Verificación del motor interno: suite completa de ocho pruebas aprobada, incluyendo regresión con Ghidra real. Las cuatro pruebas específicas del módulo se repitieron tras corregir la base de imagen y pasaron. Cubren ELF sintético con instrucciones desconocidas, entradas truncadas/rangos inválidos, saltos de 64 bits, Mach-O con 31 instrucciones y XREF a cadenas, 1431 instrucciones y más de 200 funciones, API sin Java/Ghidra disponibles, configuración persistente, anotaciones y regeneración. No se realizó prueba visual en navegador.

Mapa de módulos, cobertura por motor, prioridades y criterios de calidad: [Módulos y hoja de ruta](docs/MODULOS-Y-HOJA-DE-RUTA.md).

## N02 — Capacidades por motor

Implementado `EngineCapabilities` en `backend/engine/capabilities.ts`; catálogo `/api/engines` y consulta `/api/projects/:id/capabilities`. Cobertura disponible/parcial/no implementada, runtime, operaciones de edición y acciones según el proyecto. La UI incluye «Capacidades del motor», deshabilita pestañas no soportadas y preserva acceso a resultados guardados sin runtime. La API de edición usa el mismo contrato. Los proyectos antiguos siguen identificándose como Ghidra y cambiar el motor predeterminado no altera sus capacidades.

Siguiente módulo del incremento: separar una IR estructurada de su representación textual. Esta entrega no amplía el conjunto de instrucciones ni añade decompilación C interna.

Validación N02: compilación TypeScript y once pruebas aprobadas, incluidas políticas de pestañas, proyecto antiguo, falta de runtime, estados de edición, consulta API por proyecto y regresión con Ghidra real. No se realizó validación visual en navegador.

## N01 — Modelo central del programa

Implementado `backend/engine/core/program/`, independiente de interfaz y Ghidra. Espacios de hasta 64 bits, memoria y backing de archivo/cero/desconocido, instrucciones, funciones con rangos y datos; IDs deterministas, procedencia, confianza, revisiones por programa/entidad y transacciones con rollback. Consultas de memoria, direcciones de archivo y entidades; snapshots validados y seguimiento de creaciones, cambios y borrados.

Integrado en el motor interno y su persistencia por generación: `program.json`; API de solo lectura `/api/projects/:id/program`. Reanálisis sin diferencias conserva IDs y revisiones. Proyectos internos anteriores requieren regenerar para crear el modelo. El motor Ghidra conserva su persistencia actual.

Pendientes fuera de N01: N06 (IR estructurada), N13 (ediciones de programa/undo), N14 (invalidación incremental), paginación y migraciones futuras de almacenamiento. El modelo no corrige todavía las heurísticas de descubrimiento de funciones. Documentación: `backend/engine/core/program/README.md`.

Validación N01: compilación TypeScript y suite completa de 16 pruebas aprobadas (incluida regresión con Ghidra real). Las 5 pruebas del núcleo se repitieron tras reforzar la identidad inmutable y el rechazo de callbacks asíncronos. Cubren límites de 64 bits, overlays, BSS, memoria desconocida, invariantes, rollback, IDs, revisiones, historial, snapshots corruptos y reanálisis sin diferencias. La integración API comprueba persistencia después de reiniciar y regenerar.
