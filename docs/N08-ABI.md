# N08 — ABI y recuperación de parámetros

Entrega en curso: 2026-09-20.

## Implementado

- Perfiles AAPCS64, SysV AMD64 y Win64 para argumentos enteros, retorno, pila y caller-saved.
- AAPCS64 incluye x30 como caller-saved.
- Parámetros de registro se conservan a través de phi anidados; ciclos sin entrada no inventan parámetros.
- Se infiere uint8_ptr cuando el parámetro se usa como dirección de carga o almacenamiento.
- El seguimiento de pila exige expresiones de 64 bits; registros truncados no se aceptan como alias de sp o rsp.
- Se recogen cargas de pila en asignaciones, stores, flags, ramas y destinos; se retiene el ancho máximo.
- Win64 distingue dirección de retorno, shadow space y argumentos de pila.
- Las llamadas a destino constante incluyen argumentos enteros con valor conocido.
- Save/restore de registros callee-saved en pila queda registrado como evidencia con offset y dirección.
- La consulta de función añade un informe ABI con accesos de pila, llamadas, retornos y límites.

## Verificación

Diez pruebas específicas: perfiles, shadow space, phi anidados, ciclos phi sin entrada, truncamiento de pila, cargas en flags/stores, balance conocido/desconocido y presupuesto.

## Pendiente

Varargs, argumentos FP/SIMD, agregados, sret, red-zone, alloca, unwind, excepciones y prototipos interprocedurales. Los candidatos de pila no son una firma C confirmada.
