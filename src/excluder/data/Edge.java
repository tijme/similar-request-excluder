package excluder.data;

public class Edge {

    private final String edgeIdentifier;

    private final String optionIdentifier;

    public Edge(String edgeIdentifier, String optionIdentifier) {
        this.edgeIdentifier = edgeIdentifier;
        this.optionIdentifier = optionIdentifier;
    }

    public String getEdgeIdentifier() {
        return this.edgeIdentifier;
    }

    public String getOptionIdentifier() {
        return this.optionIdentifier;
    }

    @Override
    public int hashCode() {
        return this.optionIdentifier.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return this.hashCode() == obj.hashCode();
    }
}
