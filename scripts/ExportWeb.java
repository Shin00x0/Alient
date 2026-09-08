// Exports real static analysis for Ghidra Web. No target program is executed.
// @category GhidraWeb
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;
import ghidra.program.model.pcode.*;
import ghidra.framework.Application;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class ExportWeb extends GhidraScript {
    public void run() throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("name", currentProgram.getName());
        root.addProperty("format", currentProgram.getExecutableFormat());
        root.addProperty("language", currentProgram.getLanguageID().toString());
        root.addProperty("imageBase", currentProgram.getImageBase().toString());
        root.addProperty("schemaVersion", 4);
        root.addProperty("engineVersion", Application.getApplicationVersion());
        JsonArray blocks = new JsonArray();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", b.getName()); o.addProperty("start", b.getStart().toString());
            o.addProperty("size", Long.toString(b.getSize()));
            o.addProperty("permissions", (b.isRead()?"r":"-")+(b.isWrite()?"w":"-")+(b.isExecute()?"x":"-"));
            blocks.add(o);
        }
        root.add("blocks", blocks);
        JsonArray functions = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.setSimplificationStyle("decompile");
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        root.addProperty("decompilerProfile", "Ghidra defaults + program compiler specification; decompile; identity names");
        root.addProperty("decompileTimeout", options.getDefaultTimeout());
        if (!decompiler.openProgram(currentProgram)) throw new Exception("Cannot initialize decompiler");
        int count = 0;
        try {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && count < 200) {
                monitor.checkCancelled();
                Function f = it.next(); count++;
                JsonObject o = new JsonObject();
                o.addProperty("address", f.getEntryPoint().toString()); o.addProperty("name", f.getName());
                o.addProperty("signature", f.getSignature().toString());
                o.addProperty("end", f.getBody().getMaxAddress().toString());
                o.addProperty("comment", f.getComment());
                JsonArray flowBlocks = new JsonArray();
                var bi = new BasicBlockModel(currentProgram).getCodeBlocksContaining(f.getBody(), monitor);
                while (bi.hasNext() && flowBlocks.size() < 500) {
                    CodeBlock b = bi.next(); JsonObject node = new JsonObject();
                    node.addProperty("address", b.getFirstStartAddress().toString());
                    node.addProperty("end", b.getMaxAddress().toString());
                    JsonArray edges = new JsonArray(); var ei = b.getDestinations(monitor);
                    while(ei.hasNext() && edges.size() < 100) { var e = ei.next(); JsonObject edge = new JsonObject(); edge.addProperty("to",e.getDestinationAddress().toString()); edge.addProperty("type",e.getFlowType().toString()); edges.add(edge); }
                    node.add("edges",edges); flowBlocks.add(node);
                }
                o.add("flowBlocks",flowBlocks);
                JsonArray instructions = new JsonArray();
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                int n = 0;
                while(ii.hasNext() && n++ < 500) {
                    Instruction inst = ii.next(); JsonObject row = new JsonObject();
                    row.addProperty("address", inst.getAddress().toString()); row.addProperty("text", inst.toString()); row.addProperty("comment", inst.getComment(CodeUnit.EOL_COMMENT));
                    StringBuilder hex = new StringBuilder(); for(byte b : inst.getBytes()) hex.append(String.format("%02x ", b & 255));
                    row.addProperty("bytes", hex.toString().trim()); instructions.add(row);
                }
                o.add("instructions", instructions); o.addProperty("instructionsTruncated", ii.hasNext());
                JsonArray refs = new JsonArray();
                var ri = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while(ri.hasNext() && refs.size() < 200) { Reference r = ri.next(); JsonObject ref = new JsonObject(); ref.addProperty("from", r.getFromAddress().toString()); ref.addProperty("type", r.getReferenceType().toString()); refs.add(ref); }
                o.add("references", refs);
                MemoryBlock entryBlock = currentProgram.getMemory().getBlock(f.getEntryPoint());
                boolean external = f.isExternal() || (entryBlock != null && MemoryBlock.EXTERNAL_BLOCK_NAME.equals(entryBlock.getName()));
                o.addProperty("kind", external ? "external" : f.isThunk() ? "thunk" : "function");
                if (external || instructions.size() == 0) {
                    o.addProperty("decompileStatus", external ? "external" : "no-instructions");
                    o.addProperty("code", "");
                    o.add("codeLines", new JsonArray());
                    o.addProperty("error", "");
                    functions.add(o);
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(f, options.getDefaultTimeout(), monitor);
                JsonArray variables = new JsonArray();
                if (result.getHighFunction() != null) {
                    var vsi = result.getHighFunction().getLocalSymbolMap().getSymbols();
                    while (vsi.hasNext() && variables.size()<500) { HighSymbol v=vsi.next(); JsonObject entry=new JsonObject(); entry.addProperty("id",Long.toString(v.getId())); entry.addProperty("name",v.getName()); entry.addProperty("type",v.getDataType().getPathName()); entry.addProperty("storage",v.getStorage().toString()); entry.addProperty("parameter",v.isParameter()); variables.add(entry); }
                }
                o.add("variables",variables);
                JsonArray lines = new JsonArray();
                String code = "";
                if (result.decompileCompleted() && result.getCCodeMarkup() != null) {
                    // Preserve UI names: getDecompiledFunction() instead sanitizes names for C export.
                    PrettyPrinter printer = new PrettyPrinter(f, result.getCCodeMarkup(), null);
                    code = printer.print().getC();
                    o.addProperty("decompiledSignature", printer.print().getSignature());
                    for (ClangLine line : printer.getLines()) {
                        JsonObject l = new JsonObject();
                        l.addProperty("indent", line.getIndentString());
                        JsonArray tokens = new JsonArray();
                        for (ClangToken token : line.getAllTokens()) {
                            JsonObject t = new JsonObject();
                            t.addProperty("text", token.getText());
                            t.addProperty("syntax", token.getSyntaxType());
                            if (token.getMinAddress() != null) t.addProperty("address", token.getMinAddress().toString());
                            tokens.add(t);
                        }
                        l.add("tokens", tokens);
                        lines.add(l);
                    }
                }
                o.addProperty("code", code);
                o.addProperty("decompileStatus", code.isEmpty() ? "failed" : "complete");
                o.addProperty("warning", result.decompileCompleted() ? result.getErrorMessage() : "");
                o.add("codeLines", lines);
                o.addProperty("error", result.decompileCompleted() ? "" : result.getErrorMessage());
                functions.add(o);
            }
        } finally { decompiler.dispose(); }
        root.add("functions", functions);
        root.addProperty("totalFunctions", currentProgram.getFunctionManager().getFunctionCount());
        int internalCount = 0;
        FunctionIterator allInternal = currentProgram.getFunctionManager().getFunctions(true);
        while (allInternal.hasNext()) { allInternal.next(); internalCount++; }
        root.addProperty("listingFunctions", internalCount);
        root.addProperty("externalSymbols", currentProgram.getFunctionManager().getFunctionCount() - internalCount);
        JsonArray strings = new JsonArray();
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while(di.hasNext() && strings.size() < 2000) { Data d = di.next(); if(d.hasStringValue()) { JsonObject s = new JsonObject(); s.addProperty("address", d.getAddress().toString()); s.addProperty("end", d.getMaxAddress().toString()); s.addProperty("value", String.valueOf(d.getValue())); strings.add(s); } }
        root.add("strings", strings);
        JsonArray references = new JsonArray();
        var sources = currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(), true);
        while(sources.hasNext() && references.size()<100000) {
            var from = sources.next();
            for(Reference ref: currentProgram.getReferenceManager().getReferencesFrom(from)) {
                if(references.size()>=100000) break;
                JsonObject r = new JsonObject(); r.addProperty("from",from.toString()); r.addProperty("to",ref.getToAddress().toString()); r.addProperty("type",ref.getReferenceType().toString()); r.addProperty("call",ref.getReferenceType().isCall());
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(from);
                if(owner!=null) { r.addProperty("function",owner.getName()); r.addProperty("functionAddress",owner.getEntryPoint().toString()); }
                references.add(r);
            }
        }
        root.add("allReferences",references);
        root.addProperty("referencesTruncated",sources.hasNext());
        JsonArray symbols = new JsonArray(); var si = currentProgram.getSymbolTable().getAllSymbols(true);
        while(si.hasNext() && symbols.size()<20000) { Symbol symbol=si.next(); JsonObject entry=new JsonObject(); entry.addProperty("name",symbol.getName(true)); entry.addProperty("address",symbol.getAddress().toString()); entry.addProperty("type",symbol.getSymbolType().toString()); entry.addProperty("external",symbol.isExternal()); entry.addProperty("entry",currentProgram.getSymbolTable().isExternalEntryPoint(symbol.getAddress())); symbols.add(entry); }
        root.add("symbols",symbols); root.addProperty("symbolsTruncated",si.hasNext());
        JsonArray types = new JsonArray(); var ti=currentProgram.getDataTypeManager().getAllDataTypes();
        while(ti.hasNext() && types.size()<10000) { var type=ti.next(); JsonObject entry=new JsonObject(); entry.addProperty("name",type.getName()); entry.addProperty("path",type.getPathName()); entry.addProperty("size",type.getLength()); types.add(entry); }
        root.add("types",types);
        JsonArray bookmarks=new JsonArray(); var bki=currentProgram.getBookmarkManager().getBookmarksIterator();
        while(bki.hasNext() && bookmarks.size()<5000) { Bookmark b=bki.next(); JsonObject entry=new JsonObject();entry.addProperty("address",b.getAddress().toString());entry.addProperty("type",b.getTypeString());entry.addProperty("category",b.getCategory());entry.addProperty("comment",b.getComment());bookmarks.add(entry); }
        root.add("bookmarks",bookmarks);
        root.addProperty("limits", "Máximo 200 funciones, 500 instrucciones/función, 200 referencias/función y 2000 cadenas. Decompilación: " + options.getDefaultTimeout() + " s/función. Análisis automático: 5 min.");
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(root), StandardCharsets.UTF_8);
    }
}
