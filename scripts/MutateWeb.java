// Applies one explicit, validated user edit to the persisted Ghidra program.
// @category GhidraWeb
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import java.nio.file.*;
import com.google.gson.*;

public class MutateWeb extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        JsonObject c=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonObject receipt=new JsonObject();
        int transaction=currentProgram.startTransaction("Ghidra Web edit");
        boolean committed=false;
        try {
            var address=toAddr(c.get("address").getAsString());
            if(address==null || !currentProgram.getMemory().contains(address)) throw new Exception("Dirección fuera de la memoria del programa");
            String operation=c.get("operation").getAsString();
            String value=c.get("value").getAsString();
            Function function=currentProgram.getFunctionManager().getFunctionAt(address);
            switch(operation) {
                case "rename":
                    if(value.isBlank()) throw new Exception("El nombre no puede estar vacío");
                    if(function!=null) function.setName(value,SourceType.USER_DEFINED);
                    else { Symbol symbol=currentProgram.getSymbolTable().getPrimarySymbol(address); if(symbol!=null) symbol.setName(value,SourceType.USER_DEFINED); else currentProgram.getSymbolTable().createLabel(address,value,SourceType.USER_DEFINED); }
                    break;
                case "comment": currentProgram.getListing().setComment(address,CodeUnit.EOL_COMMENT,value); break;
                case "function-comment":
                    if(function==null) throw new Exception("Selecciona la entrada de una función");
                    function.setComment(value); break;
                case "signature":
                    if(function==null) throw new Exception("Selecciona la entrada de una función");
                    var signature=CParserUtils.parseSignature((DataTypeManagerService)null,currentProgram,value);
                    if(signature==null) throw new Exception("Firma C inválida");
                    var command=new ApplyFunctionSignatureCmd(address,signature,SourceType.USER_DEFINED);
                    if(!command.applyTo(currentProgram,monitor)) throw new Exception(command.getStatusMsg());
                    break;
                case "bookmark": currentProgram.getBookmarkManager().setBookmark(address,BookmarkType.NOTE,"Ghidra Web",value); break;
                case "variable":
                    if(function==null) throw new Exception("Selecciona la entrada de una función");
                    DecompInterface engine=new DecompInterface();
                    try {
                        DecompileOptions options=new DecompileOptions(); options.grabFromProgram(currentProgram); engine.setOptions(options);
                        if(!engine.openProgram(currentProgram)) throw new Exception(engine.getLastMessage());
                        var result=engine.decompileFunction(function,options.getDefaultTimeout(),monitor);
                        if(!result.decompileCompleted() || result.getHighFunction()==null) throw new Exception("No se pudo decompilar la función");
                        HighSymbol target=null;var symbols=result.getHighFunction().getLocalSymbolMap().getSymbols();
                        while(symbols.hasNext()) { var symbol=symbols.next(); if(Long.toString(symbol.getId()).equals(c.get("variableId").getAsString())) {target=symbol;break;} }
                        if(target==null)throw new Exception("Variable no encontrada. Actualiza el análisis");
                        DataType type=null;
                        if(c.has("dataType") && !c.get("dataType").getAsString().isBlank()) {type=currentProgram.getDataTypeManager().getDataType(c.get("dataType").getAsString());if(type==null)throw new Exception("Tipo desconocido. Usa una ruta del panel Tipos");}
                        HighFunctionDBUtil.updateDBVariable(target,value.isBlank()?null:value,type,SourceType.USER_DEFINED);
                    } finally {engine.dispose();}
                    break;
                default: throw new Exception("Operación no soportada");
            }
            committed=true;receipt.addProperty("ok",true);
        } catch(Exception e) {receipt.addProperty("ok",false);receipt.addProperty("error",e.getMessage());}
        finally {currentProgram.endTransaction(transaction,committed);}
        Files.writeString(Path.of(args[1]),new Gson().toJson(receipt));
    }
}
