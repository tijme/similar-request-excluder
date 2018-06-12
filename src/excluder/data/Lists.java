package excluder.data;

import excluder.views.Tab;

import java.util.HashSet;

public class Lists {

    private HashSet<String> uniqueRequests = new HashSet<String>();

    private HashSet<String> similarRequests = new HashSet<String>();

    public void addUnique(Tab tab, String url) {
        uniqueRequests.add(url);

        tab.setAmountUniqueResponsesFound(uniqueRequests.size());
        tab.setAmountResponsesScanned(uniqueRequests.size() + similarRequests.size());
    }

    public void addSimilar(Tab tab, String url) {
        if (!similarRequests.contains(url)) {
            tab.getSimilarRequestsModel().addElement(url);
        }

        similarRequests.add(url);

        tab.setAmountSimilarResponsesFound(similarRequests.size());
        tab.setAmountResponsesScanned(similarRequests.size() + uniqueRequests.size());
    }

}
