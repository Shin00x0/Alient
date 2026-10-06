// Complete instruction index. Each page is bounded; the number of pages is not capped.
// @category GhidraWeb
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import com.google.gson.*;
import java.nio.file.*;
import java.util.UUID;

public class ExportListing extends GhidraScript {
    public void run() throws Exception {
        Path root=Path.of(getScriptArgs()[0]);
        String generation="listing-"+UUID.randomUUID();
        Path directory=root.resolve(generation);Files.createDirectories(directory);
        JsonArray pages=new JsonArray(), rows=new JsonArray();
        String space=null;long count=0;
        InstructionIterator iterator=currentProgram.getListing().getInstructions(true);
        while(iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction=iterator.next();
            String currentSpace=instruction.getAddress().getAddressSpace().getName();
            if(rows.size()>0 && (rows.size()==256 || !currentSpace.equals(space))) {flush(directory,pages,rows,space);rows=new JsonArray();}
            space=currentSpace;
            JsonObject row=new JsonObject();
            row.addProperty("address",instruction.getAddress().toString());
            row.addProperty("offset",Long.toUnsignedString(instruction.getAddress().getOffset(),16));
            row.addProperty("endOffset",Long.toUnsignedString(instruction.getMaxAddress().getOffset(),16));
            row.addProperty("space",space);
            row.addProperty("text",instruction.toString());
            row.addProperty("comment",instruction.getComment(CodeUnit.EOL_COMMENT));
            StringBuilder bytes=new StringBuilder();for(byte b:instruction.getBytes())bytes.append(String.format("%02x ",b&255));
            row.addProperty("bytes",bytes.toString().trim());
            Function f=currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
            if(f!=null){row.addProperty("function",f.getName());row.addProperty("functionAddress",f.getEntryPoint().toString());}
            var symbol=currentProgram.getSymbolTable().getPrimarySymbol(instruction.getAddress());
            if(symbol!=null)row.addProperty("label",symbol.getName(true));
            JsonArray references=new JsonArray();
            for(Reference ref:instruction.getReferencesFrom()) {
                if(!ref.isMemoryReference())continue;
                JsonObject r=new JsonObject();r.addProperty("to",ref.getToAddress().toString());r.addProperty("type",ref.getReferenceType().toString());references.add(r);
            }
            row.add("references",references);rows.add(row);count++;
        }
        if(rows.size()>0)flush(directory,pages,rows,space);
        JsonObject manifest=new JsonObject();manifest.addProperty("generation",generation);manifest.addProperty("totalInstructions",count);manifest.addProperty("pageSize",256);
        manifest.addProperty("defaultSpace",currentProgram.getAddressFactory().getDefaultAddressSpace().getName());manifest.add("pages",pages);
        JsonArray functions=new JsonArray();var fi=currentProgram.getFunctionManager().getFunctions(true);
        while(fi.hasNext()){Function f=fi.next();JsonObject entry=new JsonObject();entry.addProperty("address",f.getEntryPoint().toString());entry.addProperty("name",f.getName());entry.addProperty("qualifiedName",f.getName(true));entry.addProperty("signature",f.getSignature().toString());functions.add(entry);}
        Files.writeString(directory.resolve("functions.json"),new Gson().toJson(functions));
        Files.writeString(directory.resolve("index.json"),new Gson().toJson(manifest));
        // The result snapshot selects the completed generation; never publish a partial index.
        Path resultPath=root.resolve("result.json");
        JsonObject result=JsonParser.parseString(Files.readString(resultPath)).getAsJsonObject();
        result.addProperty("listingGeneration",generation);result.addProperty("totalInstructions",count);
        Files.writeString(resultPath,new Gson().toJson(result));
    }
    private void flush(Path directory,JsonArray pages,JsonArray rows,String space)throws Exception {
        int page=pages.size();JsonObject first=rows.get(0).getAsJsonObject(),last=rows.get(rows.size()-1).getAsJsonObject();
        JsonObject entry=new JsonObject();entry.addProperty("page",page);entry.addProperty("space",space);entry.addProperty("start",first.get("offset").getAsString());entry.addProperty("end",last.get("endOffset").getAsString());entry.addProperty("count",rows.size());
        Files.writeString(directory.resolve(page+".json"),new Gson().toJson(rows));pages.add(entry);
    }
}
