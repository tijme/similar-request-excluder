package excluder.data;

import excluder.helpers.EdgeHelper;
import excluder.helpers.SimilarityHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.util.ArrayList;
import java.util.HashSet;

public class Node {

    private String url;

    private String html;

    private ArrayList<Edge> properties;

    private String[] elements;

    private String[] styleClasses;

    public Node(String url, String html) {
        this.url = url;
        this.html = html;

        this.properties = EdgeHelper.getEdges(url, html);
    }

    public ArrayList<Edge> getProperties() {
        return this.properties;
    }

    public int getSimilarity(Node otherNode) {
        int treeSimilarity = SimilarityHelper.getTreeSimilarity(this, otherNode);
        int styleSimilarity = SimilarityHelper.getStyleSimilarity(this, otherNode);

        return (treeSimilarity / 100 * 80) + (styleSimilarity / 100 * 20);
    }

    @Override
    public int hashCode() {
        return this.url.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return this.hashCode() == obj.hashCode();
    }

    public void setElements(String[] elements) {
        this.elements = elements;
    }

    public String[] getElements() {
        return this.elements;
    }

    public void setStyleClasses(String[] styleClasses) {
        this.styleClasses = styleClasses;
    }

    public String[] getStyleClasses() {
        return this.styleClasses;
    }

    public String getUrl() {
        return this.url;
    }

    public String getHtml() {
        return this.html;
    }

}
