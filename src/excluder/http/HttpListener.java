package excluder.http;

import burp.*;
import excluder.ExtensionOptions;
import excluder.data.Graph;
import excluder.data.Lists;
import excluder.data.Node;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class HttpListener implements IHttpListener, ChangeListener {

    private ExtensionOptions options;

    private IExtensionHelpers helpers;

    private Graph graph;

    private Lists lists;

    private boolean enabled;

    public HttpListener(ExtensionOptions options, IExtensionHelpers helpers, Graph graph, Lists lists) {
        this.options = options;
        this.helpers = helpers;
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

        IRequestInfo request = helpers.analyzeRequest(messageInfo);
        IResponseInfo response = helpers.analyzeResponse(messageInfo.getResponse());
        String html = helpers.bytesToString(messageInfo.getResponse());
        String url = request.getUrl().toString();

        if (!shouldCertainlyMarkMessageAsUnique(request, response, html)) {
            lists.addUnique(url);
            return;
        }

        boolean is_similar = graph.tryToAddNode(new Node(url, html));

        if (is_similar) {
            lists.addSimilar(url);
            return;
        }

        lists.addUnique(url);
    }

    private boolean isIntendedForUs(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return false;
        }

        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_SPIDER) {
            return false;
        }

        return true;
    }

    private boolean shouldCertainlyMarkMessageAsUnique(IRequestInfo request, IResponseInfo response, String html) {
        if (response.getStatusCode() != 200) {
            return false;
        }

        if (!response.getStatedMimeType().toLowerCase().contains("html")) {
            return false;
        }

        if (!SimilarityBlacklist.shouldProcess(html)) {
            return false;
        }

        return true;
    }
}
