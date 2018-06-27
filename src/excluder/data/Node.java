package excluder.data;

import excluder.helpers.EdgeHelper;
import excluder.helpers.SimilarityHelper;
import org.json.JSONObject;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Pattern;

public class Node {

    private URL url;

    private String html;

    private boolean propertiesLoaded = false;

    private ArrayList<Edge> properties;

    private HashSet<String> elements;

    private HashSet<String> styleClasses;

    private JSONObject jsonRepresentation;

    public Node(URL url, String html) {
        this.url = url;
        this.html = html;
    }

    public ArrayList<Edge> getProperties() {
        if (!this.propertiesLoaded) {
            this.properties = EdgeHelper.getEdges(url, html);
            this.propertiesLoaded = true;
        }

        return this.properties;
    }

    public int getSimilarity(Node otherNode) {
        double treeSimilarity = SimilarityHelper.getTreeSimilarity(this, otherNode);
        double styleSimilarity = SimilarityHelper.getStyleSimilarity(this, otherNode);

        if (treeSimilarity == -1 && styleSimilarity > -1) {
            return (int) styleSimilarity;
        }

        if (styleSimilarity == -1 && treeSimilarity > -1) {
            return (int) treeSimilarity;
        }

        return (int) ((treeSimilarity / 100 * 80) + (styleSimilarity / 100 * 20));
    }

    @Override
    public int hashCode() {
        return this.url.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return this.hashCode() == obj.hashCode();
    }

    @Override
    public String toString() {
        return getUrl().toString();
    }

    public void setElements(HashSet<String> elements) {
        this.elements = elements;
    }

    public HashSet<String> getElements() {
        return this.elements;
    }

    public void setStyleClasses(HashSet<String> styleClasses) {
        this.styleClasses = styleClasses;
    }

    public HashSet<String> getStyleClasses() {
        return this.styleClasses;
    }

    public URL getUrl() {
        return this.url;
    }

    public String getHtml() {
        return this.html;
    }

    public JSONObject getJSONRepresentation() {
        if (this.jsonRepresentation == null) {
            jsonRepresentation = new JSONObject();
            jsonRepresentation.put("enabled", true);
            jsonRepresentation.put("file", "^" + Pattern.quote(url.getFile()) + "$");
            jsonRepresentation.put("host", "^" + Pattern.quote(url.getHost()) + "$");
            jsonRepresentation.put("port", "^" + url.getPort() + "$");
            jsonRepresentation.put("protocol", url.getProtocol().toUpperCase());
        }

        return this.jsonRepresentation;
    }

}
