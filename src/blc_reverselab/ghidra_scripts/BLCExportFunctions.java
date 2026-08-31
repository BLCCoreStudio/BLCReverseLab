// @category BLCReverseLab

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class BLCExportFunctions extends GhidraScript {
    private String clean(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected output TSV path");
        }

        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                long bodySize = function.getBody() == null ? 0 : function.getBody().getNumAddresses();
                writer.printf(
                    "%s\t%s\t%s\t%s\t%d%n",
                    clean(function.getEntryPoint().toString()),
                    clean(function.getName()),
                    Boolean.toString(function.isExternal()),
                    Boolean.toString(function.isThunk()),
                    bodySize
                );
            }
        }
    }
}
