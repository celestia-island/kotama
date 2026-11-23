//@category Kotama
//@description Dump the function list (RVA + name) for kotama's differential oracle.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Headless post-script for the oracle lane: writes one "<rva-decimal>\t<name>" line
 * per function, with the RVA normalized by subtracting the program image base
 * (ELF PIE loads at 0x100000, PE at 0x140000000 / 0x400000 — the subtraction makes
 * the addresses comparable with kotama's own RVA space).
 *
 * Usage inside analyzeHeadless:
 *   -scriptPath <repo>/support/ghidra -postScript KotamaFunctionList.java <out.txt>
 */
public class KotamaFunctionList extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "functions.txt";
        long imageBase = currentProgram.getImageBase().getOffset();
        int n = 0;
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(outPath)))) {
            out.println("# kotama function list: rva(decimal)\\tname");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                long rva = f.getEntryPoint().getOffset() - imageBase;
                if (rva <= 0) {
                    continue;
                }
                out.println(rva + "\t" + f.getName());
                n++;
            }
            out.println("# total: " + n);
        }
        println("KotamaFunctionList: wrote " + n + " functions to " + outPath);
    }
}