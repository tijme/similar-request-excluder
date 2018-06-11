package excluder.data;

import java.util.ArrayList;

public class Node {

    private String url;

    private String html;

    private ArrayList<Edge> properties = new ArrayList<Edge>();

    public Node(String url, String html) {
        this.url = url;
        this.html = html;

        initializeProperties();
    }

    public ArrayList<Edge> getProperties() {
        return this.properties;
    }

    public int getSimilarity(Node otherNode) {
        // @TODO
        return 1;
    }

    private void initializeProperties() {
        // @TODO
    }

}
