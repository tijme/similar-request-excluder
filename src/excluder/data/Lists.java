package excluder.data;

import excluder.ExtensionDebugger;
import excluder.sets.OrderedHashSet;
import excluder.views.Tab;

import java.util.ArrayList;

public class Lists {

    private OrderedHashSet uniqueRequests = new OrderedHashSet();

    private OrderedHashSet similarRequests = new OrderedHashSet();

    private OrderedHashSet newSimilarRequests = new OrderedHashSet();

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

    public OrderedHashSet getUniqueRequests() {
        return this.uniqueRequests;
    }

    public OrderedHashSet getSimilarRequests() {
        return this.similarRequests;
    }

    public ArrayList<Node> getNewSimilarRequests() {
        ArrayList<Node> result = new ArrayList<>(newSimilarRequests);
        newSimilarRequests = new OrderedHashSet();
        return result;
    }

    public void clean() {
        this.uniqueRequests.clear();
        this.similarRequests.clear();
        this.newSimilarRequests.clear();
    }

}
