package excluder;

import excluder.views.rows.*;
import excluder.views.Tab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;

public class ExtensionOptions {

    public static final String OPTION_STATUS = "status";
    public static final String OPTION_DEBUG = "debug";
    public static final String OPTION_MINIMUM_SIMILAR_REQUESTS = "minimumSimilarRequests";
    public static final String OPTION_SIMILARITY_POINTS_REQUIRED = "similarityPointsRequired";
    public static final String OPTION_MINIMUM_TREE_SIMILARITY = "minimumTreeSimilarity";
    public static final String OPTION_URL_PATH_EXACT_MATCH = "urlPathExactMatch";
    public static final String OPTION_URL_PATH_NUMBER_MATCH = "urlPathNumberMatch";
    public static final String OPTION_URL_PATH_WORD_MATCH = "urlPathWordMatch";
    public static final String OPTION_URL_PATH_SLUG_MATCH = "urlPathSlugMatch";
    public static final String OPTION_URL_QUERY_EXACT_MATCH = "urlQueryExactMatch";
    public static final String OPTION_URL_QUERY_NUMBER_MATCH = "urlQueryNumberMatch";
    public static final String OPTION_URL_QUERY_WORD_MATCH = "urlQueryWordMatch";
    public static final String OPTION_URL_QUERY_SLUG_MATCH = "urlQuerySlugMatch";
    public static final String OPTION_URL_META_PROTOCOL_MATCH = "urlMetaProtocolMatch";
    public static final String OPTION_URL_META_HOST_MATCH = "urlMetaHostMatch";

    private Tab tab;

    private int index = 0;

    private HashMap<String, BaseRow> options = new HashMap<String, BaseRow>();

    private ArrayList<String> optionsOrder = new ArrayList<String>();

    public ExtensionOptions(Tab tab) {
        this.tab = tab;

        this.addGroup("General settings");
        this.add(OPTION_STATUS, new CheckBoxRow("Status", "Tick to enable.", true));
        this.add(OPTION_DEBUG, new CheckBoxRow("Debug", "Tick to enable.", false));
        this.add(OPTION_MINIMUM_SIMILAR_REQUESTS, new SliderRow("Minimum similar requests", "The minimum amount of similar requests to scan (to prevent false positives).", 10, 1, 100));
        this.add(OPTION_SIMILARITY_POINTS_REQUIRED, new SliderRow("Similarity points required", "The minimum amount of points to mark the request as similar.", 205, 1, 300));

        this.addSeparator();

        this.addGroup("HTML similarity points", "The default settings should be sufficient.");
        this.add(OPTION_MINIMUM_TREE_SIMILARITY, new SliderRow("Minimum tree similarity", "The percentage of similarity an HTML tree requires to mark the request as similar. The percentage of similarity will be used as the points if it is at least this minimum.", 50));

        this.addSeparator();

        this.addGroup("URL path points", "The default settings should be sufficient.");
        this.add(OPTION_URL_PATH_EXACT_MATCH, new SliderRow("Exact match in URL path", "Exact match on a certain part of the URL path.", 15));
        this.add(OPTION_URL_PATH_NUMBER_MATCH, new SliderRow("Number match in URL path", "Matches on the regular expression: <code>/[0-9]+?/</code>.", 15));
        this.add(OPTION_URL_PATH_WORD_MATCH, new SliderRow("Word match in URL path", "Matches on the regular expression: <code>/A-Za-z]+?/</code>.", 5));
        this.add(OPTION_URL_PATH_SLUG_MATCH, new SliderRow("Slug match in URL path", "Matches on the regular expression: <code>/[A-Za-z0-9-_\\.]+?/</code>.", 2));

        this.addSeparator();

        this.addGroup("URL query points", "The default settings should be sufficient.");
        this.add(OPTION_URL_QUERY_EXACT_MATCH, new SliderRow("Exact match in URL query", "Exact match on a certain part of the URL query.", 15));
        this.add(OPTION_URL_QUERY_NUMBER_MATCH, new SliderRow("Number match in URL query", "Matches on the regular expression: <code>/[0-9]+?/</code>.", 15));
        this.add(OPTION_URL_QUERY_WORD_MATCH, new SliderRow("Word match in URL query", "Matches on the regular expression: <code>/A-Za-z]+?/</code>.", 5));
        this.add(OPTION_URL_QUERY_SLUG_MATCH, new SliderRow("Slug match in URL query", "Matches on the regular expression: <code>/[A-Za-z0-9-_\\.]+?/</code>.", 2));

        this.addSeparator();
        this.addGroup("URL meta points", "The default settings should be sufficient.");
        this.add(OPTION_URL_META_PROTOCOL_MATCH, new SliderRow("Exact match on URL protocol", "Exact match on the URL protocol (e.g. https or http).", 2));
        this.add(OPTION_URL_META_HOST_MATCH, new SliderRow("Exact match on URL hostname", "Exact match on the hostname (e.g. google.com).", 100));

        this.render();
    }

    public void add(String key, BaseRow option) {
        this.options.put(key, option);
        this.optionsOrder.add(key);
    }

    private void addSeparator() {
        this.add("separator", new SeparatorRow());
    }

    private void addGroup(String title) {
        this.add(title, new GroupRow(title));
    }

    private void addGroup(String title, String description) {
        this.add(title, new GroupRow(title, description));
    }

    private void render() {
        for (int i = 0; i < this.optionsOrder.size(); i++) {
            BaseRow option = this.options.get(this.optionsOrder.get(i));

            boolean isLast = i + 1 == this.optionsOrder.size();
            this.index = option.appendTo(this.tab.getOptionsWrapper(), this.index, isLast);
        }
    }

    public BaseRow get(String key) {
        return this.options.get(key);
    }

    public Integer getSliderValue(String key) {
        return ((JSlider) get(key).getComponent()).getValue();
    }

}
