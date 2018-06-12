package excluder.data;

import excluder.helpers.EdgeHelper;
import excluder.helpers.SimilarityHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.util.ArrayList;

public class Node {

    private String url;

    private String html;

    private ArrayList<Edge> properties;

    private ArrayList<String> elements;

    private ArrayList<String> styleClasses;

    public Node(String url, String html) {
        this.url = url;
        this.html = html;

        this.properties = EdgeHelper.getEdges(url, html);
    }

    public ArrayList<Edge> getProperties() {
        return this.properties;
    }

    public int getSimilarity(Node otherNode) {
        Document thisDocument = Jsoup.parse(this.getHtml());
        Document otherDocument = Jsoup.parse(otherNode.getHtml());

        int treeSimilarity = SimilarityHelper.getTreeSimilarity(this, otherNode, thisDocument, otherDocument);
        int styleSimilarity = SimilarityHelper.getStyleSimilarity(this, otherNode, thisDocument, otherDocument);

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

    public void setElements(ArrayList<String> elements) {
        this.elements = elements;
    }

    public ArrayList<String> getElements() {
        return this.elements;
    }

    public void setStyleClasses(ArrayList<String> styleClasses) {
        this.styleClasses = styleClasses;
    }

    public ArrayList<String> getStyleClasses() {
        return this.styleClasses;
    }

    public String getUrl() {
        return this.url;
    }

    public String getHtml() {
        return this.html;
    }

}
