# Ghidra Web — versión 0.2

> **Actualización 2026-09-15:** migración activa del motor interno a Rust. Consulta el [registro de avance y pendientes](docs/AVANCE-MOTOR-RUST.md); las secciones históricas del motor TypeScript aún no describen el nuevo runtime.


Aplicación web de análisis estático inspirada en Ghidra. Interfaz y servidor HTTP en TypeScript, sin framework, sin dependencias npm de producción. Permite elegir en Configuración entre el motor interno Rust (ARM64/x86-64) y el motor real de Ghidra mediante scripts Java headless. No ejecuta el binario importado. No incluye debugger.

## Iniciar

El motor interno requiere Node.js 24, npm y Rust estable con compilador C para Capstone. Solo la opción Ghidra requiere además una distribución **ejecutable** de Ghidra y un JDK compatible. El código fuente clonado por sí solo no es una instalación ejecutable.

```sh
cd /Users/matiasaltamirano/Documents/ChatGPT/CloneGhidraWeb/ghidra-web
npm ci
npm run engine:build
npm run build
npm start
```

Abrir http://127.0.0.1:4310. En este equipo se descargaron Ghidra 12.1.3 y Temurin JDK 21 dentro de `.runtime/`; el servidor los detecta automáticamente. No se modificó la instalación Java del sistema. La descarga local no se incluye en Git.

Para usar otra instalación:

```sh
export GHIDRA_HOME="/ruta/ghidra_12.1.3_PUBLIC"
export JAVA_HOME="/ruta/jdk/Contents/Home"
npm start
```

En macOS, si la distribución no incluye el decompilador nativo, compílalo con las herramientas de línea de comandos de Xcode:

```sh
sh scripts/build-native-macos.sh
```

En este equipo ese paso ya se completó para Apple Silicon, utilizando los fuentes C++ de la misma distribución 12.1.3. Reinicia el servidor después de instalar componentes del motor.

Distribuciones oficiales: [Ghidra 12.1.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build), [Eclipse Temurin](https://adoptium.net/temurin/releases/). Sigue los requisitos de Java de la versión de Ghidra elegida. La detección automática de Java incluida está orientada a macOS; en Linux configura JAVA_HOME. Windows no está implementado ni probado.

## Uso

1. Importar un ejecutable, hasta 32 MiB. El análisis se ejecuta en segundo plano y el registro muestra sus mensajes; se puede cancelar.
2. Seleccionar un proyecto completado y buscar una función por nombre o dirección.
3. Seleccionar la función para ver sus instrucciones y su pseudocódigo C original de Ghidra.
4. Consultar cadenas, bloques de memoria, referencias entrantes y bytes originales del archivo.
5. Guardar etiquetas y comentarios en Anotaciones. Son metadatos de la web: no renombran símbolos en Ghidra ni cambian el pseudocódigo.
6. Exportar JSON para descargar resultados y anotaciones.

`fixtures/sample.c` y `fixtures/sample-macho` ofrecen un ejemplo pequeño para comenzar. Puedes regenerarlo en macOS con `clang -O0 -g fixtures/sample.c -o fixtures/sample-macho`.

## Arquitectura

```text
Navegador: HTML + CSS + TypeScript
  → API HTTP local de Node.js
    → cola: un análisis a la vez
      → Ghidra analyzeHeadless + scripts/ExportWeb.java
        → JSON con resultados reales
  → data/<uuid>: binario, resultados y anotaciones persistentes
```

El proyecto Ghidra se conserva en `data/<uuid>/analysis.gpr` y `analysis.rep/`. Las ediciones y regeneraciones reabren ese programa. La JVM se inicia por trabajo; no existe todavía un servicio residente. Los proyectos antiguos deben regenerarse una vez. No hay paridad completa con Ghidra de escritorio.

- `frontend/`: interfaz sin framework. El contenido procedente del binario se inserta como texto, nunca como HTML.
- `backend/`: API, persistencia, cola y proceso del motor.
- `scripts/ExportWeb.java`: adaptador de Ghidra.
- `tests/`: prueba de integración con motor real.
- `ESTADO.md`: funcionalidades implementadas, pendientes y límites.
- `ghidra-original/`: repositorio original de referencia, separado y sin modificaciones.

## Límites y alcance

El listing principal incluye todas las instrucciones definidas por Ghidra y todas las funciones del listado, paginadas desde disco. La exportación auxiliar de pseudocódigo, grafos y búsquedas de texto sigue limitada a 200 funciones, 500 instrucciones por función, 200 referencias por función y 2000 cadenas definidas por Ghidra. Decompilación limitada a 30 segundos por función; análisis automático a 5 minutos; proceso completo a 10 minutos. Ghidra dispone de hasta 2 GiB de heap Java y dos CPU de análisis; el consumo del proceso nativo no queda limitado por ese heap.

Las direcciones se transportan como texto hexadecimal para evitar pérdida de precisión de 64 bits. El visor hexadecimal muestra offsets del archivo, no direcciones virtuales. Las referencias saltan a funciones solamente cuando la instrucción de origen está incluida en la exportación.

El servidor escucha únicamente en loopback, verifica Host/Origin y no publica CORS. Está pensado para uso local de un usuario: no tiene autenticación multiusuario ni aislamiento mediante contenedores. No debe exponerse directamente a Internet. Los datos locales no se eliminan automáticamente y no están cifrados por la aplicación.

## Verificación

```sh
npm run build
npm test
```

La prueba exige el motor disponible, importa el fixture, verifica función y pseudocódigo reales, cadenas y bytes, guarda una anotación y reinicia el servidor para comprobar persistencia. También verifica rechazo de origen externo, archivos vacíos y offsets/anotaciones inválidos. Usa el puerto 4311 y un directorio temporal independiente. Requiere permisos para abrir puertos locales y ejecutar Java.

Esta primera entrega se prueba en macOS Apple Silicon con Mach-O AArch64. PE y ELF dependen del cargador automático de Ghidra y todavía requieren fixtures y pruebas específicas. No se afirma compatibilidad verificada con todas las arquitecturas del motor.

## Licencias y atribución

Implementación independiente; no es un producto oficial de la NSA. Ghidra conserva sus avisos y licencias en la distribución y en `ghidra-original/ghidra/LICENSE`, `NOTICE` y `licenses/`. No se copió su interfaz de escritorio ni se modificó el repositorio original. La distribución del motor y del JDK mantiene sus respectivos archivos de licencia.

## Actualización de fidelidad del pseudocódigo

- Opciones predeterminadas de Ghidra y especificación de compilador del programa aplicadas explícitamente.
- Texto de la vista generado desde el markup Clang con nombres originales, sin la transformación de identificadores utilizada por la exportación C.
- Sangría y categorías semánticas originales; colores adaptados al tema oscuro web, numeración visual, copia exacta y salto de tokens a instrucciones exportadas.
- Versión del motor y perfil registrados en cada resultado.
- Regeneración del análisis conservando las anotaciones; copia anterior en previous-result.json.
- Demanglers GNU 2.41 y 2.24 compilados para macOS, necesarios para recuperar nombres y firmas C++.
- La coincidencia con Ghidra de escritorio requiere la misma versión, análisis, símbolos, tipos y opciones. No se importan preferencias personalizadas de una instalación de escritorio.

### Comparar un proyecto con una ejecución independiente del motor

Tras regenerar un proyecto desde la interfaz:

```sh
node scripts/verify-project.mjs <uuid-del-proyecto>
```

El script reimporta el mismo binario en otro proyecto Ghidra, sin invocar el adaptador ExportWeb, y compara pseudocódigo e instrucciones exportadas. Conserva el informe y registro en `data/<uuid>/verification/`. No ejecuta el binario. Requiere el mismo runtime local y acceso a Java. La prueba de `XorGate` está en `docs/XorGate-verification.json`: 16 funciones iguales y 11 entradas externas sin implementación. No es una comparación automatizada con la interfaz de escritorio ni sus preferencias personalizadas.

## Nuevos flujos de trabajo (0.2)

- Cadenas: usa el filtro de la vista y pulsa el contador XREF para ver quién utiliza cada cadena, incluyendo referencias a su interior. Pulsa una dirección para navegar.
- Navegación: introduce una dirección hexadecimal o nombre exacto de función. Atajos G (ir), X (referencias), Alt+izquierda/derecha (historial).
- Las pestañas incluyen símbolos, importaciones/exportaciones, búsqueda de ensamblador/C/bytes, flujo, llamadas, variables, tipos y marcadores. El filtro acota la pestaña activa; las tablas muestran hasta 300 resultados.
- Editar programa: aplica nombres, comentarios, firmas C, cambios de variable o marcadores en Ghidra. Para firmas/variables usa la entrada de la función. Para tipos de variable utiliza una ruta existente del panel Tipos.
- Las anotaciones web siguen siendo independientes. Para cambiar el pseudocódigo usa Editar programa.
- Las búsquedas de texto cubren los datos exportados, con los límites detallados en ESTADO.md. La búsqueda de bytes cubre el archivo original.
- No expongas este servidor local directamente a Internet.

## Recorrer el listing completo

El panel Listing tiene controles para primera/anterior/siguiente/última página y un campo de número de página. Cada página contiene hasta 256 instrucciones. Haz clic en una fila para seleccionarla; usa flechas o Page Up/Page Down para desplazarte. La barra Ir acepta direcciones hexadecimales (también espacio:dirección) y nombres del índice completo de funciones.

El contenido sale de Ghidra, incluyendo instrucciones fuera de funciones y posteriores al límite de la exportación C. Los saltos y referencias de cada instrucción son enlaces. Las direcciones sin instrucciones muestran la más cercana con un aviso. No se realiza desensamblado nuevo por navegar. Regenera los proyectos antiguos para activar el índice.

### Pseudocódigo desde el listing

Seleccionar una función que no esté entre las primeras 200 solicita su decompilación a Ghidra sobre el proyecto persistente, en modo de solo lectura y sin repetir el análisis. Se conserva el resultado por revisión; editar o regenerar crea una revisión nueva. Si el motor está ocupado, el panel permite reintentar. El primer acceso puede tardar por el arranque de Java. La búsqueda de pseudocódigo abarca las funciones cargadas, no todo el programa automáticamente.

### Motor interno Rust

En **Configuración · Motor** elige **Motor Rust (ARM64 / x86-64)** o **Conectar con Ghidra**. Cada proyecto conserva su motor. Para comparar importa el mismo binario con ambas opciones.

`engine-rust/` es un ejecutable independiente. Carga ELF64, Mach-O64 y PE32+ enlazados mediante `object`, decodifica con Capstone y utiliza IR, análisis y decompilador propios. No invoca Ghidra, Java ni ejecuta el binario analizado. El código TypeScript antiguo se conserva como referencia y para sus pruebas; el servidor ya no lo usa como motor.

Incluye descubrimiento de funciones/CFG, SSA, constantes, ABI, tipos, resolución indirecta acotada, C parcial, persistencia, búsqueda indexada, comandos y undo/redo. **No tiene paridad con Ghidra/IDA**: faltan semánticas SIMD/FP, tipado avanzado, prototipos complejos, tablas relativas y reconstrucción general de C, entre otros límites.

- Compilar: `npm run engine:build`. Probar Rust: `npm run engine:test`.
- `NATIVE_ENGINE=/ruta/al/ghidra-web-engine` permite seleccionar un ejecutable. Sin esa variable se prefiere release y luego debug; reinicia el servidor después de cambiarlo.
- El panel **Editar programa** expone operaciones y undo/redo; tipos y tablas reciben JSON estructurado con ejemplos en el formulario.
- **Buscar C** usa el índice global nativo por palabras completas y páginas de 100 resultados. Otros filtros de tablas mantienen su alcance mostrado.
- Los proyectos internos anteriores se regeneran con schema 2. Las anotaciones web se conservan; las identidades del antiguo modelo TS no son equivalentes a las nativas.
- API: `/api/projects/:id/program`, `/native-search?q=...`, `/native-function?address=...` y `/native-indirect`.
- Cambiar el motor de nuevos proyectos no convierte los existentes.

Detalle de módulos, límites y evidencias: [registro de avance](docs/AVANCE-MOTOR-RUST.md) y [documentación del motor Rust](engine-rust/README.md).
