package burp;

import excluder.ExtensionDebugger;
import excluder.ExtensionDetails;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.views.Tab;

import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {

    private Tab tab;

    private Graph graph;

    private ExtensionOptions options;

    private Lists lists = new Lists();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        ExtensionDetails.initialize();
        ExtensionDebugger.initialize(callbacks);

        this.tab = new Tab();
        this.options = new ExtensionOptions(tab);
        this.graph = new Graph(options);

        HttpListener httpListener = new HttpListener(options, callbacks.getHelpers(), tab, graph, lists);

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
