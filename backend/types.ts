export interface CrossReference {from:string;to:string;type:string;call:boolean;function?:string;functionAddress?:string}
export interface Analysis {
    allReferences?: CrossReference[];
    referencesTruncated?: boolean;
    symbols?: {name:string;address:string;type:string;external:boolean;entry:boolean}[];
    symbolsTruncated?: boolean;
    types?: {name:string;path:string;size:number}[];
    bookmarks?: {address:string;type:string;category:string;comment:string}[];
    listingFunctions?: number;
    externalSymbols?: number;
    schemaVersion?: number;
    engineVersion?: string;
    decompilerProfile?: string;
    decompileTimeout?: number;
    name: string;
    format: string;
    language: string;
    imageBase: string;
    totalFunctions: number;
    limits: string;
    blocks: {
        name: string;
        start: string;
        size: string;
        permissions: string;
    }[];
    strings: {
        address: string;
        value: string;
        end?: string;
    }[];
    functions: FunctionInfo[];
}
export interface FunctionInfo {
    end?:string;
    comment?:string;
    flowBlocks?: {address:string;end:string;edges:{to:string;type:string}[]}[];
    variables?: {id:string;name:string;type:string;storage:string;parameter:boolean}[];
    kind?: 'external' | 'thunk' | 'function';
    decompileStatus?: 'external' | 'no-instructions' | 'failed' | 'complete';
    warning?: string;
    decompiledSignature?: string;
    codeLines?: {indent: string; tokens: {text: string; syntax: number; address?: string}[]}[];
    address: string;
    name: string;
    signature: string;
    code: string;
    error: string;
    instructionsTruncated: boolean;
    instructions: {
        address: string;
        bytes: string;
        comment?:string;
        text: string;
    }[];
    references: {
        from: string;
        type: string;
    }[];
}
export interface Project {
    persistent?: boolean;
    id: string;
    name: string;
    created: string;
    status: 'queued' | 'analyzing' | 'ready' | 'failed' | 'cancelled';
    error?: string;
    log: string;
    sha256: string;
    size: number;
    annotations: Record<string, {
        label: string;
        comment: string;
    }>;
}
