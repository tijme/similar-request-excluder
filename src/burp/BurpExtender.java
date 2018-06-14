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

public class BurpExtender implements IBurpExtender, ITab {

    private IBurpExtenderCallbacks callbacks;

    private Tab tab;

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

            ExtensionDebugger.output("New items: " + lists.getNewSimilarRequests().size());

            for (Node newNode : lists.getNewSimilarRequests()) {
                tab.getSimilarRequestsModel().addElement(newNode.getUrl().toString());
                ExtensionDebugger.output("New: " + newNode.getJSONRepresentation().toString());
                config.getJSONObject("target").getJSONObject("scope").getJSONArray("exclude").put(newNode.getJSONRepresentation());
            }

            ExtensionDebugger.output(config.toString());

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
        callbacks.addSuiteTab(this);

        new Timer().schedule(new DelayedFetcher(), 0, 5000);
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
