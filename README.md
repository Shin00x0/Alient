# Ghidra Web — versión mínima 0.1

Aplicación web de análisis estático inspirada en Ghidra. Interfaz y servidor HTTP en TypeScript, sin framework, sin dependencias de producción. Utiliza el motor real de Ghidra mediante un script Java ejecutado en modo headless. No ejecuta el binario importado. No incluye debugger.

## Iniciar

Requiere Node.js 24, npm, una distribución **ejecutable** de Ghidra y un JDK compatible. El código fuente clonado por sí solo no es una instalación ejecutable.

```sh
cd /Users/matiasaltamirano/Documents/ChatGPT/CloneGhidraWeb/ghidra-web
npm ci
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

El proyecto temporal de Ghidra se elimina al terminar; se conserva la instantánea JSON y el archivo original. No se conserva una sesión interactiva del motor. El clon está en una primera etapa de exploración de resultados, no tiene paridad funcional con Ghidra de escritorio.

- `frontend/`: interfaz sin framework. El contenido procedente del binario se inserta como texto, nunca como HTML.
- `backend/`: API, persistencia, cola y proceso del motor.
- `scripts/ExportWeb.java`: adaptador de Ghidra.
- `tests/`: prueba de integración con motor real.
- `ESTADO.md`: funcionalidades implementadas, pendientes y límites.
- `ghidra-original/`: repositorio original de referencia, separado y sin modificaciones.

## Límites y alcance

Exportación limitada a 200 funciones, 500 instrucciones por función, 200 referencias por función y 2000 cadenas definidas por Ghidra. No es una vista completa de binarios grandes. Decompilación limitada a 30 segundos por función; análisis automático a 5 minutos; proceso completo a 10 minutos. Ghidra dispone de hasta 2 GiB de heap Java y dos CPU de análisis; el consumo del proceso nativo no queda limitado por ese heap.

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
