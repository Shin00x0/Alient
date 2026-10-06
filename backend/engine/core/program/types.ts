/** JSON-safe core model. Offsets are hexadecimal; sizes are decimal strings. */
export interface Address {space:string;offset:string}
export interface AddressRange {start:Address;size:string}
export interface Provenance {origin:'loader'|'analysis'|'user';confidence:'confirmed'|'inferred'|'unknown'}
export interface ProgramDescriptor {source:{sha256:string;size:number};format:string;architecture:string}
export interface SpaceInput {kind:'space';name:string;bits:number;endianness:'little'|'big'}
export interface MemoryInput {kind:'memory';name:string;range:AddressRange;permissions:string;backing:{fileOffset:number;fileSize:number;tail:'zero'|'unknown'};provenance:Provenance}
export interface InstructionInput {kind:'instruction';address:Address;size:number;bytes:string;text:string;decodeStatus:'decoded'|'unknown';provenance:Provenance}
export interface FunctionInput {kind:'function';entry:Address;name:string;body:AddressRange[];provenance:Provenance}
export interface DataInput {kind:'data';range:AddressRange;dataType:string;value?:string;provenance:Provenance}
export type EntityInput = SpaceInput|MemoryInput|InstructionInput|FunctionInput|DataInput;
export type EntityKind = EntityInput['kind'];
export type Entity<T extends EntityInput=EntityInput> = T & {id:string;revision:number};
export interface ChangeSet {revision:number;reason:string;created:string[];updated:string[];deleted:string[]}
export interface ProgramSnapshot {schemaVersion:1;id:string;descriptor:ProgramDescriptor;revision:number;entities:Entity[];changes:ChangeSet[]}
