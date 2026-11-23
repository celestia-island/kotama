//@category Kotama
//@description Batch-decompile functions to a single C file, for kotama's oracle lane.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Headless post-script: decompile up to `limit` functions and write them, with
 * entry-point headers, to the output path given as the first script argument.
 * Usage inside analyzeHeadless:
 *   -scriptPath <repo>/support/ghidra -postScript KotamaDecompile.java <out.c> [limit]
 */
public class KotamaDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "kotama-decomp.c";
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 20;

        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        if (!ifc.openProgram(currentProgram)) {
            println("KotamaDecompile: openProgram failed: " + ifc.getLastMessage());
            return;
        }
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(outPath)))) {
            int n = 0;
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && n < limit) {
                Function f = it.next();
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                out.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
                if (res != null && res.getDecompiledFunction() != null) {
                    out.println(res.getDecompiledFunction().getC());
                } else {
                    out.println("// decompile failed: "
                        + (res != null ? res.getErrorMessage() : "null result"));
                }
                n++;
            }
            out.println("// ==== total: " + n + " ====");
            println("KotamaDecompile: wrote " + n + " functions to " + outPath);
        } finally {
            ifc.dispose();
        }
    }
}