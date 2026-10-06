# N01 — Modelo central de programa

Módulo independiente de Ghidra, del cargador y de la interfaz. Implementado en TypeScript con APIs estándar de Node. Es la base de entidades y memoria sobre la que puede construirse la IR estructurada de N06; no es un decompilador.

## Componentes

- `types.ts`: descriptor de programa, espacios, memoria, instrucciones, funciones, datos, procedencia y cambios.
- `address.ts`: direcciones por espacio y rangos con precisión de 64 bits. Offsets hexadecimales canónicos, tamaños decimales positivos y final exclusivo.
- `validation.ts`: invariantes, memoria mapeada y comprobación de superposiciones.
- `program.ts`: identidad, consultas, lectura de memoria, transacciones atómicas y snapshots versionados.

## Identidad

El programa se identifica por SHA-256 del contenido original, tamaño, formato y arquitectura. El nombre de archivo, la ruta de importación y el UUID del proyecto web no cambian esa identidad.

Cada entidad tiene un ID determinista dentro del programa: clase y dirección de anclaje, o nombre en los espacios. Cambiar el nombre de una función, su cuerpo, texto de instrucción o tamaño de dato conserva el ID cuando no cambia el anclaje. Mover una entidad o cambiarla de clase crea otra identidad. Borrar y recrear en el mismo anclaje recupera el ID lógico, con una revisión posterior. Los overlays se representan como espacios distintos.

El contrato no identifica equivalencias entre binarios diferentes ni sigue una función a través de recompilaciones. Las direcciones y tamaños se serializan como cadenas para evitar pérdida de precisión en JSON.

## Entidades e invariantes

| Entidad | Contenido |
|---|---|
| Espacio | Nombre, ancho de 1 a 64 bits, endianness; direcciones por byte |
| Memoria | Rango, nombre, permisos, offset/tamaño respaldado por archivo y cola cero/desconocida |
| Instrucción | Dirección, tamaño, bytes, representación textual, decodificación conocida/desconocida |
| Función | Entrada, nombre, uno o varios rangos del cuerpo, procedencia y confianza |
| Dato | Rango, nombre de tipo, valor textual opcional, procedencia y confianza |

Los rangos de memoria no pueden superponerse dentro del mismo espacio. Los rangos de instrucciones y datos tampoco pueden superponerse. Todos deben estar mapeados y respetar el ancho del espacio. Los cuerpos de funciones pueden compartir código entre funciones, pero no contener rangos solapados dentro del mismo cuerpo; la entrada debe pertenecer a su cuerpo. El modelo valida coherencia, no demuestra que una región sea realmente código ni mejora por sí mismo las heurísticas del analizador.

No se materializan regiones enormes en RAM. La memoria se consulta por índice de rangos; las lecturas se limitan a 1 MiB por llamada. Se verifica que los bytes originales coincidan con el descriptor SHA-256. Una lectura puede atravesar regiones adyacentes; los huecos y bytes desconocidos producen error. Las colas declaradas a cero devuelven ceros. Las consultas de instrucciones/datos por dirección incluyen direcciones interiores y usan un índice reconstruido después de cambiar el modelo.

## Cambios y revisiones

`program.transaction(reason, callback, expectedRevision?)` aplica una transacción síncrona. `put`, `remove` y `get` trabajan sobre un borrador. Solo se publica si el callback termina y todas las invariantes se cumplen. Una excepción, un rango inválido o un conflicto de revisión deja intacto el estado anterior. No se admiten transacciones anidadas o asíncronas.

La revisión global aumenta una vez por transacción efectiva. Cada entidad conserva la revisión global de su último cambio. Una operación sin diferencias no aumenta ninguna revisión. `changesSince(revision)` devuelve IDs creados, actualizados y borrados y el motivo del cambio. Los objetos que devuelve el modelo son copias; no permiten modificar el estado por referencia.

`reconcile(entities, reason)` reemplaza el conjunto de entidades en una transacción y preserva identidades/revisiones no modificadas. Rechaza entradas duplicadas. Es una reconciliación del análisis, **no** una política de combinación de cambios del usuario. La edición pública del motor interno sigue pendiente en N13.

El registro de cambios es de identidades, no de valores históricos: no implementa undo/redo ni invalidación automática de análisis dependientes. Esas capacidades corresponden a N13/N14.

## Persistencia e integración

`program.snapshot()` devuelve JSON de esquema 1. `Program.restore(value)` valida versión, descriptor, identidades, entidades, revisiones y coherencia del historial. Las versiones desconocidas se rechazan; no se convierten silenciosamente. La migración de futuros esquemas queda como trabajo posterior.

El motor interno crea espacios y memoria desde el cargador mediante `internal/program-adapter.ts`, lee las secciones de código a través del modelo y registra instrucciones, cuerpos inferidos y cadenas. Las funciones e instrucciones del contrato de presentación incorporan ID y revisión. `analysis.program` identifica el programa y su revisión.

Cada generación de listing contiene `program.json`. El resultado nuevo se publica mediante reemplazo de `result.json` después de escribir el modelo y las páginas. Reanalizar el mismo archivo conserva el historial y las revisiones sin cambios. Proyectos anteriores sin modelo lo crean al regenerar; un snapshot existente corrupto provoca un error explícito.

`GET /api/projects/:id/program` consulta el snapshot de un proyecto interno listo. Devuelve 409 si aún no está listo o requiere regeneración y 422 para el adaptador Ghidra, que sigue usando su base de datos propia. Esta API es de solo lectura y devuelve el snapshot completo; paginación, almacenamiento indexado y limpieza de generaciones corresponden a N12.

## Ejemplo

```ts
import {Program, address, range} from './program.ts';

const program = new Program({
    source: {sha256: digestOfOriginalBytes, size: originalBytes.length},
    format: 'ELF 64-bit',
    architecture: 'AARCH64:LE:64'
});
program.transaction('Importar memoria', tx => {
    tx.put({kind: 'space', name: 'ram', bits: 64, endianness: 'little'});
    tx.put({
        kind: 'memory', name: 'text', range: range(address('ram', 0x400000n), originalBytes.length),
        permissions: 'r-x',
        backing: {fileOffset: 0, fileSize: originalBytes.length, tail: 'unknown'},
        provenance: {origin: 'loader', confidence: 'confirmed'}
    });
});
const restored = Program.restore(JSON.parse(JSON.stringify(program.snapshot())));
```

El tamaño del ejemplo debe ser positivo. Los bytes del archivo no se copian dentro del snapshot; permanecen en el archivo original del proyecto.
