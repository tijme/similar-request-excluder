package burp;

import excluder.ExtensionDebugger;
import excluder.ExtensionDetails;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.data.Node;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.views.Tab;
import org.json.JSONObject;

import java.awt.*;
import java.util.Timer;
import java.util.TimerTask;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;

    private Tab tab;

    private Timer delayedFetcher = new Timer();;

    private Graph graph;

    private ExtensionOptions options;

    private Lists lists = new Lists();

    class DelayedFetcher extends TimerTask {

        DelayedFetcher() {
            run();
        }

        public void run() {
            JSONObject config = new JSONObject(callbacks.saveConfigAsJson("target.scope"));
            config.getJSONObject("target").getJSONObject("scope").put("advanced_mode", true);

            for (Node newNode : lists.getNewSimilarRequests()) {
                tab.getSimilarRequestsModel().addElement(newNode.getUrl().toString());
                config.getJSONObject("target").getJSONObject("scope").getJSONArray("exclude").put(newNode.getJSONRepresentation());
            }

            callbacks.loadConfigFromJson(config.toString());
        }

    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        ExtensionDetails.initialize();
        ExtensionDebugger.initialize(callbacks);

        this.callbacks = callbacks;
        this.tab = new Tab();
        this.options = new ExtensionOptions(tab);
        this.graph = new Graph(options);

        HttpListener httpListener = new HttpListener(options, callbacks.getHelpers(), tab, graph, lists);

        callbacks.setExtensionName(ExtensionDetails.TITLE);
        callbacks.registerHttpListener(httpListener);
        callbacks.registerExtensionStateListener(this);
        callbacks.addSuiteTab(this);

        delayedFetcher.schedule(new DelayedFetcher(), 0, 5000);
    }

    @Override
    public void extensionUnloaded() {
        delayedFetcher.cancel();
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
