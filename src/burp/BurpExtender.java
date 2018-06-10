package burp;

import excluder.ExtensionDetails;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.views.Tab;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    private Tab tab = new Tab();

    private ExtensionOptions options = new ExtensionOptions(tab);

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);

        callbacks.setExtensionName(ExtensionDetails.TITLE);
        callbacks.registerHttpListener(new HttpListener());
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