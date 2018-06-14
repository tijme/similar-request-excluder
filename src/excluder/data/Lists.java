package excluder.data;

import excluder.ExtensionDebugger;
import excluder.views.Tab;

import java.util.ArrayList;
import java.util.HashSet;

public class Lists {

    private HashSet<Node> uniqueRequests = new HashSet<>();

    private HashSet<Node> similarRequests = new HashSet<>();

    private HashSet<Node> newSimilarRequests = new HashSet<>();

    public void addUnique(Tab tab, Node node) {
        uniqueRequests.add(node);

        tab.setAmountUniqueResponsesFound(uniqueRequests.size());
        tab.setAmountResponsesScanned(uniqueRequests.size() + similarRequests.size());
    }

    public void addSimilar(Tab tab, Node node) {
        newSimilarRequests.add(node);
        similarRequests.add(node);

        tab.setAmountSimilarResponsesFound(similarRequests.size());
        tab.setAmountResponsesScanned(similarRequests.size() + uniqueRequests.size());
    }

    public HashSet<Node> getUniqueRequests() {
        return this.uniqueRequests;
    }

    public HashSet<Node> getSimilarRequests() {
        return this.similarRequests;
    }

    public ArrayList<Node> getNewSimilarRequests() {
        ArrayList<Node> result = new ArrayList<>(newSimilarRequests);
        newSimilarRequests = new HashSet<>();
        return result;
    }

}
