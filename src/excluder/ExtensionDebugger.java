package excluder;

import burp.IBurpExtenderCallbacks;

import java.io.PrintWriter;

public class ExtensionDebugger {

    private static PrintWriter error;

    private static PrintWriter output;

    public static void initialize(IBurpExtenderCallbacks callbacks) {
        ExtensionDebugger.output = new PrintWriter(callbacks.getStdout(),true);
        ExtensionDebugger.error = new PrintWriter(callbacks.getStderr(),true);
    }

    public static void error(String message) {
        ExtensionDebugger.error.println(message);
    }

    public static void output(String message) {
        ExtensionDebugger.output.println(message);
    }

}
