package excluder.data;

import java.util.ArrayList;

public class Lists {

    private ArrayList<String> uniqueRequests = new ArrayList<String>();

    private ArrayList<String> similarRequests = new ArrayList<String>();

    public void addUnique(String url) {
        uniqueRequests.add(url);
    }

    public void addSimilar(String url) {
        similarRequests.add(url);
    }

}
