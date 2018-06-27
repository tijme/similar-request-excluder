package excluder.http;

import burp.*;
import excluder.ExtensionOptions;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.data.Node;
import excluder.views.Tab;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class HttpListener implements IHttpListener, ChangeListener {

    private final ExtensionOptions options;

    private final IExtensionHelpers helpers;

    private final Tab tab;

    private final Graph graph;

    private final Lists lists;

    private boolean enabled;

    private long averageMilliseconds = 0;
    private long averageMillisecondsCount = 0;

    public HttpListener(ExtensionOptions options, IExtensionHelpers helpers, Tab tab, Graph graph, Lists lists) {
        this.options = options;
        this.helpers = helpers;
        this.tab = tab;
        this.graph = graph;
        this.lists = lists;

        JCheckBox checkbox = (JCheckBox) options.get(ExtensionOptions.OPTION_STATUS).getComponent();
        this.enabled = checkbox.isSelected();
        checkbox.addChangeListener(this);
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        JCheckBox source = (JCheckBox) e.getSource();

        if (source == options.get(ExtensionOptions.OPTION_STATUS).getComponent()) {
            this.enabled = source.isSelected();
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!this.enabled) {
            return;
        }

        if (!isIntendedForUs(toolFlag, messageIsRequest, messageInfo)) {
            return;
        }

        long start = System.currentTimeMillis();

        IRequestInfo request = helpers.analyzeRequest(messageInfo);
        IResponseInfo response = helpers.analyzeResponse(messageInfo.getResponse());
        String html = helpers.bytesToString(messageInfo.getResponse());

        if (shouldCertainlyMarkMessageAsUnique(request, response, html)) {
            lists.addUnique(tab, new Node(request.getUrl(), html));
            return;
        }

        Node node = new Node(request.getUrl(), html);
        boolean is_similar = graph.tryToAddNode(node);

        long elapsed = (System.currentTimeMillis() - start);
        if (elapsed > 0) {
            averageMillisecondsCount ++;
            if (averageMilliseconds == 0) {
                averageMilliseconds = elapsed;
            } else {
                averageMilliseconds -= averageMilliseconds / averageMillisecondsCount;
                averageMilliseconds += elapsed / averageMillisecondsCount;
                tab.setAmountAdditionalMilliseconds(averageMilliseconds);
            }
        }

        if (is_similar) {
            lists.addSimilar(tab, node);
            return;
        }

        lists.addUnique(tab, node);
    }

    private boolean isIntendedForUs(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return false;
        }

        return toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER;
    }

    private boolean shouldCertainlyMarkMessageAsUnique(IRequestInfo request, IResponseInfo response, String html) {
        if (response.getStatusCode() != 200) {
            return true;
        }

        if (!response.getStatedMimeType().toLowerCase().contains("html")) {
            return true;
        }

        return !SimilarityBlacklist.shouldProcess(html);

    }
}
