package burp;

import excluder.ExtensionDetails;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.views.Tab;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    private Tab tab = new Tab();

    private ExtensionOptions options = new ExtensionOptions(tab);

    private Graph graph = new Graph(options);

    private Lists lists = new Lists();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);

        HttpListener httpListener = new HttpListener(options, callbacks.getHelpers(), graph, lists);

        callbacks.setExtensionName(ExtensionDetails.TITLE);
        callbacks.registerHttpListener(httpListener);
        callbacks.addSuiteTab(this);
    }


    @Override
    public String getTabCaption() {
        return ExtensionDetails.TITLE;
    }

    @Override
    public Component getUiComponent() {
        return tab.getPanel();
    }
}