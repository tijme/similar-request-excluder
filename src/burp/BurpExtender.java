package burp;

import excluder.ExtensionDebugger;
import excluder.ExtensionDetails;
import excluder.adapters.NodesAdapter;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.data.Node;
import excluder.http.HttpListener;
import excluder.ExtensionOptions;
import excluder.sets.OrderedHashSet;
import excluder.views.Tab;
import org.json.JSONObject;

import java.awt.*;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener, Tab.TabListener {

    private Timer delayedFetcher = new Timer();

    private Lists lists = new Lists();

    private IBurpExtenderCallbacks callbacks;

    private NodesAdapter nodesAdapter;

    private Tab tab;

    private Graph graph;

    private ExtensionOptions options;

    class DelayedFetcher extends TimerTask {

        DelayedFetcher() {
            run();
        }

        public void run() {
            JSONObject config = new JSONObject(callbacks.saveConfigAsJson("target.scope"));
            config.getJSONObject("target").getJSONObject("scope").put("advanced_mode", true);

            ArrayList<Node> newSimilarRequests = lists.getNewSimilarRequests();

            for (Node newNode : newSimilarRequests) {
                config.getJSONObject("target").getJSONObject("scope").getJSONArray("exclude").put(newNode.getJSONRepresentation());
            }

            callbacks.loadConfigFromJson(config.toString());
        }

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ExtensionDetails.initialize();
        ExtensionDebugger.initialize(callbacks);

        this.nodesAdapter = new NodesAdapter(lists.getSimilarRequests());

        this.callbacks = callbacks;
        this.tab = new Tab(this);
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

    @Override
    public OrderedHashSet getUniqueRequests() {
        return this.lists.getUniqueRequests();
    }

    @Override
    public OrderedHashSet getSimilarRequests() {
        return this.lists.getSimilarRequests();
    }

    @Override
    public NodesAdapter getNodesAdapter() {
        return this.nodesAdapter;
    }

    @Override
    public void cleanGraph() {
        this.lists.clean();
        this.graph.clean();
    }

}
