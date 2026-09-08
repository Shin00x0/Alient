// Independent re-import verification: never invokes ExportWeb or the web API.
// @category GhidraWeb
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.framework.Application;
import java.nio.file.*;
import com.google.gson.*;

public class VerifyWeb extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        JsonObject expected = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonArray mismatches = new JsonArray();
        int compared = 0, external = 0;
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        DecompInterface engine = new DecompInterface();
        engine.setOptions(options);
        try {
            if (!engine.openProgram(currentProgram)) throw new Exception(engine.getLastMessage());
            for (JsonElement element : expected.getAsJsonArray("functions")) {
                JsonObject item = element.getAsJsonObject();
                String address = item.get("address").getAsString();
                Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
                if (function == null) { mismatches.add(address + ": function missing"); continue; }
                MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
                boolean isExternal = function.isExternal() || block != null && block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME);
                if (isExternal) {
                    external++;
                    if (!item.get("code").getAsString().isEmpty() || !item.get("decompileStatus").getAsString().equals("external")) mismatches.add(address + ": imported function incorrectly decompiled");
                    continue;
                }
                if (!currentProgram.getListing().getInstructions(function.getBody(), true).hasNext()) continue;
                DecompileResults result = engine.decompileFunction(function, options.getDefaultTimeout(), monitor);
                if (!result.decompileCompleted() || result.getCCodeMarkup() == null) { mismatches.add(address + ": reference decompilation failed"); continue; }
                String reference = new PrettyPrinter(function, result.getCCodeMarkup(), null).print().getC();
                if (!reference.equals(item.get("code").getAsString())) mismatches.add(address + ": pseudocode differs");
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                for (JsonElement rowElement : item.getAsJsonArray("instructions")) {
                    JsonObject row = rowElement.getAsJsonObject();
                    if (!instructions.hasNext()) { mismatches.add(address + ": extra instruction"); break; }
                    Instruction inst = instructions.next();
                    StringBuilder bytes = new StringBuilder();
                    for (byte b : inst.getBytes()) bytes.append(String.format("%02x ", b & 255));
                    if (!row.get("address").getAsString().equals(inst.getAddress().toString()) || !row.get("text").getAsString().equals(inst.toString()) || !row.get("bytes").getAsString().equals(bytes.toString().trim())) mismatches.add(address + ": instruction differs");
                }
                compared++;
            }
        } finally { engine.dispose(); }
        JsonObject report = new JsonObject();
        report.addProperty("engineVersion", Application.getApplicationVersion());
        report.addProperty("language", currentProgram.getLanguageID().toString());
        report.addProperty("comparedFunctions", compared);
        report.addProperty("externalEntries", external);
        report.add("mismatches", mismatches);
        report.addProperty("passed", mismatches.isEmpty() && compared > 0);
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(report));
    }
}
