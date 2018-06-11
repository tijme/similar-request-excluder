package excluder.data;

import excluder.ExtensionOptions;

import java.util.ArrayList;
import java.util.HashMap;

public class Graph {

    private final ExtensionOptions options;

    private final HashMap<Edge, ArrayList<Node>> edgesWithNodes = new HashMap<>();
    private final HashMap<Node, ArrayList<Edge>> nodesWithEdges = new HashMap<>();

    public Graph(ExtensionOptions options) {
        this.options = options;
    }

    public boolean tryToAddNode(Node node) {
        if (nodesWithEdges.containsKey(node)) {
            return false;
        }

        int similarityPointsRequired = options.getSliderValue(ExtensionOptions.OPTION_SIMILARITY_POINTS_REQUIRED);

        if (getSimilarityPoints(node) >= similarityPointsRequired) {
            return true;
        }

        // Add edges
        for (Edge property : node.getProperties()) {
            if (!edgesWithNodes.containsKey(property)) {
                edgesWithNodes.put(property, new ArrayList<Node>());
            }

            edgesWithNodes.get(property).add(node);
        }

        // Add node
        nodesWithEdges.put(node, node.getProperties());

        return false;
    }

    private int getSimilarityPoints(Node node) {
        int similarityPoints = 0;

        int stylometrySimilarityHighest = 0;
        int stylometrySimilarityCount = 0;

        // Property similarities
        for(Edge property : node.getProperties()) {
            if (!edgesWithNodes.containsKey(property)) {
                continue;
            }

            if (edgesWithNodes.get(property).size() < options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_SIMILAR_REQUESTS)) {
                continue;
            }

            similarityPoints = options.getSliderValue(property.getOptionIdentifier());
        }

        // Stylometry similarity
        for (Node otherNode : nodesWithEdges.keySet()) {
            int similarity = node.getSimilarity(otherNode);

            if (similarity < options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_TREE_SIMILARITY)) {
                continue;
            }

            stylometrySimilarityCount ++;

            if (similarity > stylometrySimilarityHighest) {
                stylometrySimilarityHighest = similarity;
            }
        }


        if (stylometrySimilarityCount < options.getSliderValue(ExtensionOptions.OPTION_MINIMUM_SIMILAR_REQUESTS)) {
            similarityPoints += stylometrySimilarityHighest;
        }

        return similarityPoints;
    }

}
