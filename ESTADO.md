# Registro de funcionalidades — Ghidra Web 0.1

## Objetivo

Construir por etapas un clon web del flujo de análisis estático de Ghidra, con interfaz propia sin framework y motores existentes. Debugger excluido expresamente.

## Implementadas

| Funcionalidad | Alcance de esta versión |
|---|---|
| Interfaz de trabajo | HTML/CSS y TypeScript; paneles de proyectos, funciones, ensamblador y decompilación |
| Importar ejecutables | Archivo local de hasta 32 MiB; detección de formato/arquitectura delegada a Ghidra |
| Motor real | Adaptador Java a Ghidra headless; decompilador nativo original |
| Cola y estado | Un proceso activo, hasta tres solicitudes pendientes/activas; registro y cancelación |
| Funciones | Lista, búsqueda por nombre/dirección/etiqueta, firma y selección sincronizada |
| Desensamblado | Dirección, bytes y texto de instrucciones originales |
| Decompilación | Opciones Ghidra + programa, tokens semánticos, nombres originales, copia exacta, firma decompilada y errores por función |
| Memoria | Bloques, dirección inicial, tamaño y permisos |
| Cadenas | Cadenas definidas por el análisis de Ghidra y sus direcciones |
| Referencias | Referencias entrantes a la entrada de cada función; salto al origen si está exportado |
| Hexadecimal | Páginas de 256 bytes del archivo original con ASCII y offsets |
| Anotaciones | Etiqueta y comentario por función, guardados en el proyecto web |
| Persistencia | Binario, hash SHA-256, resultados JSON y anotaciones; reapertura tras reiniciar |
| Exportación | Descarga JSON con resultados y metadatos |
| Control local | Loopback, validación de Host/Origin, límite de tamaño, límites de tiempo y heap Java |

## Pendientes

- Sesión persistente del motor y base de datos de proyecto Ghidra editable.
- Renombrado real de funciones, símbolos, parámetros y variables con redecompilación.
- Edición de tipos, firmas, estructuras, enums y convenciones de llamada.
- Comentarios vinculados a instrucciones y tokens del decompilador.
- Desensamblado completo bajo demanda, paginación y virtualización para binarios grandes.
- Decompilación bajo demanda y caché por función.
- Navegación bidireccional entre tokens C, instrucciones, datos y referencias.
- Referencias cruzadas completas, incluidas referencias salientes y a datos.
- Salto a cualquier dirección virtual, historial atrás/adelante y marcadores.
- Árbol de símbolos, namespaces, importaciones y exportaciones como vistas independientes.
- Grafos de flujo y llamadas.
- Edición de bytes, parcheo, reanálisis y exportación del ejecutable modificado.
- Selección manual de loader, arquitectura, endianness, base y opciones de análisis.
- Eliminación de proyectos y recuperación automática de análisis interrumpidos (regeneración manual ya disponible).
- Pruebas específicas de ELF, PE, más arquitecturas, entradas malformadas y binarios grandes.
- Otros adaptadores de decompilación y ejecución WebAssembly dentro del navegador.
- Instalador reproducible multiplataforma con verificación de artefactos.
- Aislamiento por contenedores, autenticación y despliegue multiusuario.
- Pruebas automatizadas de interacción de la interfaz y accesibilidad.

## Límites explícitos

- 200 funciones, 500 instrucciones por función, 200 referencias por función, 2000 cadenas.
- Las anotaciones web no cambian el pseudocódigo ni los símbolos del motor.
- Las exportaciones son instantáneas: se elimina el proyecto temporal de Ghidra al finalizar.
- El análisis automático puede quedar parcial si alcanza 5 minutos; consultar siempre el registro. El proceso total tiene un límite de 10 minutos y cada función 30 segundos de decompilación.
- No hay porcentaje de progreso exacto; se muestran estados y mensajes reales.
- Heap Java de 2 GiB, sin contenedor ni límite de memoria nativa.
- Uso local en macOS Apple Silicon; compatibilidad adicional sin verificar.
- El debugger no está pendiente: queda fuera del alcance.

## Verificación de esta entrega

- Compilación estricta de TypeScript: aprobada.
- Integración con binario Mach-O AArch64 real: aprobada; tres funciones reales, pseudocódigo, instrucciones y cadenas reconocidas.
- Persistencia y anotaciones tras reiniciar el servidor: aprobadas.
- Rechazo de origen externo, archivo vacío, offset negativo y dirección de anotación inválida: aprobado.
- Decompilador nativo macOS ARM64: compilado desde los fuentes de la distribución Ghidra 12.1.3 e instalado en `.runtime/`.
- Revisión visual/interacción en navegador: no ejecutada; vista local abierta para revisión del usuario.

## Actualización de fidelidad del pseudocódigo

- Opciones predeterminadas de Ghidra y especificación de compilador del programa aplicadas explícitamente.
- Texto de la vista generado desde el markup Clang con nombres originales, sin la transformación de identificadores utilizada por la exportación C.
- Sangría y categorías semánticas originales; colores adaptados al tema oscuro web, numeración visual, copia exacta y salto de tokens a instrucciones exportadas.
- Versión del motor y perfil registrados en cada resultado.
- Regeneración del análisis conservando las anotaciones; copia anterior en previous-result.json.
- Demanglers GNU 2.41 y 2.24 compilados para macOS, necesarios para recuperar nombres y firmas C++.
- La coincidencia con Ghidra de escritorio requiere la misma versión, análisis, símbolos, tipos y opciones. No se importan preferencias personalizadas de una instalación de escritorio.

Verificado en esta actualización: texto reconstruido idéntico al generado por Ghidra, regeneración sin pérdida de anotaciones, rechazo de regeneraciones duplicadas, binario C++ con namespace recuperado por el demangler. El archivo importado `data` fue regenerado y ahora muestra `std::operator<<` y `ostream *` en su función de entrada. La verificación no equivale a comparar contra una sesión de escritorio con preferencias personalizadas.

## Verificación del binario XorGate (ELF x86-64)

- Motor: distribución Ghidra 12.1.3 en `.runtime/`. El repositorio `ghidra-original/` no se ejecuta ni modifica.
- Detectado y corregido: se solicitaba decompilación de entradas del bloque EXTERNAL sin instrucciones, produciendo `halt_baddata()`. Ahora se muestran como importaciones sin implementación disponible.
- Se conserva la decompilación de los thunks/PLT con instrucciones reales; una llamada a una función con el mismo nombre puede corresponder a ese trampolín, no a recursión.
- Comparación mediante una segunda importación headless independiente: 16 funciones con código e instrucciones idénticos; 11 entradas EXTERNAL correctamente sin cuerpo. Cero diferencias.
- Informe con hashes y método: `docs/XorGate-verification.json`.
- Los avisos originales del motor se conservan. La igualdad comprobada es con Ghidra 12.1.3 y sus opciones predeterminadas más la especificación del programa, no con cualquier proyecto o configuración de escritorio.
- La prueba valida este ELF concreto; no equivale a compatibilidad exhaustiva con todos los ELF o arquitecturas.
