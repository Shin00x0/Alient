# Alien — versión 0.2

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


## Verificación

```sh
npm run build
npm test
```

La prueba exige el motor disponible, importa el fixture, verifica función y pseudocódigo reales, cadenas y bytes, guarda una anotación y reinicia el servidor para comprobar persistencia. También verifica rechazo de origen externo, archivos vacíos y offsets/anotaciones inválidos. Usa el puerto 4311 y un directorio temporal independiente. Requiere permisos para abrir puertos locales y ejecutar Java.

Esta primera entrega se prueba en macOS Apple Silicon con Mach-O AArch64. PE y ELF dependen del cargador automático de Ghidra y todavía requieren fixtures y pruebas específicas. No se afirma compatibilidad verificada con todas las arquitecturas del motor.




### Motor interno Rust

En **Configuración · Motor** elige **Motor Rust (ARM64 / x86-64)** o **Conectar con Ghidra**. Cada proyecto conserva su motor. Para comparar importa el mismo binario con ambas opciones.

`engine-rust/` es un ejecutable independiente. Carga ELF64, Mach-O64 y PE32+ enlazados mediante `object`, decodifica con Capstone y utiliza IR, análisis y decompilador propios. No invoca Ghidra, Java ni ejecuta el binario analizado. El código TypeScript antiguo se conserva como referencia y para sus pruebas; el servidor ya no lo usa como motor.

Incluye descubrimiento de funciones/CFG, SSA, constantes, ABI, tipos, resolución indirecta acotada, C parcial, persistencia, búsqueda indexada, comandos y undo/redo. **No tiene paridad con Ghidra/IDA**: faltan semánticas SIMD/FP, tipado avanzado, prototipos complejos, tablas relativas y reconstrucción general de C, entre otros límites.


