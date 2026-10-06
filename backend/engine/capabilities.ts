import type {EngineId, Project} from '../types.ts';

export type CapabilityStatus = 'supported' | 'partial' | 'unsupported';
export type FeatureId = 'listing' | 'strings' | 'references' | 'symbols' | 'flow' | 'cCode' | 'registerIR' | 'variables' | 'types' | 'bookmarks' | 'programEditing' | 'annotations' | 'byteSearch' | 'textSearch';
export interface Capability {label:string;status:CapabilityStatus;detail:string}
export interface EngineCapabilities {
    schemaVersion:1;
    engine:EngineId;
    name:string;
    runtimeAvailable:boolean;
    runtimeReason:string;
    inputs:string;
    features:Record<FeatureId,Capability>;
    editOperations:readonly string[];
    actions:Record<'analyze'|'edit', {enabled:boolean;reason:string}>;
}
const feature=(label:string,status:CapabilityStatus,detail:string):Capability=>({label,status,detail});
const editOperations=['rename','comment','function-comment','signature','variable','bookmark'] as const;

/** Describes this application's adapter coverage, not all features of the upstream engine. */
export function engineCapabilities(engine:EngineId,ghidraAvailable:boolean,project?:Pick<Project,'status'|'persistent'>,nativeAvailable=true):EngineCapabilities {
    const internal=engine==='internal',runtimeAvailable=internal?nativeAvailable:ghidraAvailable;
    const runtimeReason=runtimeAvailable?'':internal?'Compila el motor Rust con npm run engine:build.':'Ghidra o su runtime no están disponibles. Los resultados guardados siguen siendo consultables.';
    const features:Record<FeatureId,Capability>={
        listing:feature('Listing',internal?'partial':'supported',internal?'Decodificación Capstone ARM64/x86-64 y recorrido desde entradas, símbolos y llamadas.':'Todas las instrucciones definidas por Ghidra, paginadas.'),
        strings:feature('Cadenas','partial',internal?'ASCII terminado en NUL; máximo 20000 cadenas de hasta 4096 caracteres.':'Hasta 2000 cadenas definidas por el motor.'),
        references:feature('Referencias','partial',internal?'Saltos, llamadas, direcciones constantes e indirectos resolubles; destinos desconocidos explícitos.':'Índice exportado de hasta 100000 referencias.'),
        symbols:feature('Símbolos','partial',internal?'Símbolos, imports, exports y relocaciones ELF, Mach-O y PE; sin resolución dinámica.':'Hasta 20000 símbolos exportados.'),
        flow:feature('Grafos','partial',internal?'Flujo derivado de instrucciones reconocidas y funciones inferidas.':'Bloques y llamadas reales con límites de exportación y visualización.'),
        cCode:feature('Decompilación C',internal?'partial':'supported',internal?'C parcial: expresiones, ramas y bucles simples; efectos desconocidos explícitos.':'C real de Ghidra, con carga de funciones bajo demanda. Puede fallar por función.'),
        registerIR:feature('IR de registros',internal?'partial':'unsupported',internal?'IR entera con anchos, SSA, dominadores y constantes; API native-function.':'Esta interfaz expone C y tokens, no una vista de IR de Ghidra.'),
        variables:feature('Variables','partial',internal?'Parámetros de registros y slots de pila; AAPCS64, SysV AMD64 y Win64.':'Hasta 500 variables por función exportada.'),
        types:feature('Tipos','partial',internal?'Enteros, punteros, arrays, estructuras, uniones y enums validados.':'Catálogo de hasta 10000 tipos; sin editor de estructuras.'),
        bookmarks:feature('Marcadores','partial',internal?'Marcadores persistentes y editables con undo/redo.':'Lectura de hasta 5000 marcadores y creación de notas.'),
        programEditing:feature('Edición del programa','partial',internal?'Nombres, comentarios, firmas, variables, tipos, datos, funciones y undo/redo transaccionales.':'Nombres, comentarios, firmas, variables y marcadores; sin parches ni undo/redo.'),
        annotations:feature('Anotaciones web','supported','Etiquetas y notas por función; no modifican el programa del motor.'),
        byteSearch:feature('Búsqueda de bytes','partial','Archivo original completo; patrón de hasta 64 bytes, hasta 200 coincidencias.'),
        textSearch:feature('Búsqueda de texto','partial',internal?'Índice persistente global de funciones, instrucciones, C y datos (palabras completas).':'Busca en las funciones cargadas; no es una búsqueda global del programa.')
    };
    const analyzing=project&&['queued','analyzing'].includes(project.status);
    const analyzeReason=!runtimeAvailable?runtimeReason:analyzing?'Este proyecto ya tiene un análisis pendiente.':'';
    const editReason=!runtimeAvailable?runtimeReason:project?.status!=='ready'?'Espera a que el proyecto esté listo.':!project.persistent?'Regenera el proyecto para habilitar su base de datos persistente.':'';
    return {schemaVersion:1,engine,name:internal?'Motor interno Rust':'Ghidra conectado',runtimeAvailable,runtimeReason,inputs:internal?'ELF64, Mach-O64 y PE32+ enlazados, ARM64/x86-64 little-endian.':'Detección delegada a la instalación de Ghidra; la cobertura depende de sus cargadores.',features,editOperations:internal?[...editOperations,'define-type','define-data','clear-data','create-function','delete-function','jump-table','undo','redo']:[...editOperations],actions:{analyze:{enabled:!analyzeReason,reason:analyzeReason},edit:{enabled:!editReason,reason:editReason}}};
}
export function projectEngine(project:Pick<Project,'engine'>):EngineId {return project.engine||'ghidra';}
