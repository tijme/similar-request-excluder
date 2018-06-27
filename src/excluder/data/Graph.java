package excluder.data;

import excluder.ExtensionOptions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class Graph {

    private final ExtensionOptions options;

    private final HashMap<Edge, ArrayList<Node>> edgesWithNodes = new HashMap<>();

    private final HashMap<Node, Boolean> results = new HashMap<>();

    public Graph(ExtensionOptions options) {
        this.options = options;
    }

    public boolean tryToAddNode(Node node) {
        if (results.containsKey(node)) {
            return results.get(node);
        }

        int similarityPointsRequired = options.getSliderValue(ExtensionOptions.OPTION_SIMILARITY_POINTS_REQUIRED);

        if (getSimilarityPoints(node) >= similarityPointsRequired) {
            results.put(node, true);
            return true;
        }

        // Add edges
        for (Edge property : node.getProperties()) {
            if (!edgesWithNodes.containsKey(property)) {
                edgesWithNodes.put(property, new ArrayList<Node>());
            }

            edgesWithNodes.get(property).add(node);
        }

        results.put(node, false);
        return false;
    }

    private int getSimilarityPoints(Node node) {
        int similarityPoints = 0;

        int stylometrySimilarityValue = 0;
        int stylometrySimilarityCount = 0;

        HashSet<Node> propertyNodes = new HashSet<Node>();

        // Property similarities
        for(Edge property : node.getProperties()) {
            if (!edgesWithNodes.containsKey(property)) {
                continue;
            }

            if (edgesWithNodes.get(property).size() < options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_SIMILAR_REQUESTS)) {
                continue;
            }

            propertyNodes.addAll(edgesWithNodes.get(property));
            similarityPoints += options.getSliderValue(property.getOptionIdentifier());
        }

        // Stylometry similarity
        for (Node otherNode : propertyNodes) {
            int similarity = node.getSimilarity(otherNode);

            if (similarity < options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_TREE_SIMILARITY)) {
                continue;
            }

            stylometrySimilarityCount ++;
            stylometrySimilarityValue += similarity;
        }

        if (stylometrySimilarityCount >= options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_SIMILAR_REQUESTS)) {
            similarityPoints += stylometrySimilarityValue / stylometrySimilarityCount;
        }

        return similarityPoints;
    }

    public void clean() {
        edgesWithNodes.clear();
        results.clear();
    }

}
