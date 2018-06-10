package excluder;

import excluder.views.rows.*;
import excluder.views.Tab;

import java.util.ArrayList;
import java.util.HashMap;

public class ExtensionOptions {

    private Tab tab;

    private int index = 0;

    private HashMap<String, BaseRow> options = new HashMap<String, BaseRow>();

    private ArrayList<String> optionsOrder = new ArrayList<String>();

    public ExtensionOptions(Tab tab) {
        this.tab = tab;

        this.addGroup("General settings");
        this.add("status", new CheckBoxRow("Status", "Tick to enable.", true));
        this.add("debug", new CheckBoxRow("Debug", "Tick to enable.", false));
        this.add("minimumSimilarRequests", new SliderRow("Minimum similar requests", "The minimum amount of similar requests to scan (to prevent false positives).", 15));
        this.add("similarityPointsRequired", new SliderRow("Similarity points required", "The minimum amount of points to mark the request as similar.", 100, 200));

        this.addSeparator();

        this.addGroup("HTML similarity points", "The default settings should be sufficient.");
        this.add("minimumTreeSimilarity", new SliderRow("Minimum tree similarity", "The percentage of similarity an HTML tree requires to mark the request as similar. The percentage of similarity will be used as the points if it is at least this minimum.", 50));

        this.addSeparator();

        this.addGroup("URL path points", "The default settings should be sufficient.");
        this.add("urlPathExactMatch", new SliderRow("Exact match in URL path", "Exact match on a certain part of the URL path.", 15));
        this.add("urlPathNumberMatch", new SliderRow("Number match in URL path", "Matches on the regular expression: <code>/[0-9]+?/</code>.", 15));
        this.add("urlPathWordMatch", new SliderRow("Word match in URL path", "Matches on the regular expression: <code>/A-Za-z]+?/</code>.", 5));
        this.add("urlPathSlugMatch", new SliderRow("Slug match in URL path", "Matches on the regular expression: <code>/[A-Za-z0-9-_\\.]+?/</code>.", 2));

        this.addSeparator();

        this.addGroup("URL query points", "The default settings should be sufficient.");
        this.add("urlQueryExactMatch", new SliderRow("Exact match in URL query", "Exact match on a certain part of the URL query.", 15));
        this.add("urlQueryNumberMatch", new SliderRow("Number match in URL query", "Matches on the regular expression: <code>/[0-9]+?/</code>.", 15));
        this.add("urlQueryWordMatch", new SliderRow("Word match in URL query", "Matches on the regular expression: <code>/A-Za-z]+?/</code>.", 5));
        this.add("urlQuerySlugMatch", new SliderRow("Slug match in URL query", "Matches on the regular expression: <code>/[A-Za-z0-9-_\\.]+?/</code>.", 2));

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

}
