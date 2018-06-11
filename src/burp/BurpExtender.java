package burp;

import excluder.ExtensionDetails;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.views.Tab;

import java.awt.*;
import java.io.*;

public class BurpExtender implements IBurpExtender, ITab {

    private Tab tab;

    private ExtensionOptions options;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        ExtensionDetails.initialize();

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(),true);

        this.tab = new Tab();
        this.options = new ExtensionOptions(tab);

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