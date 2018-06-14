package excluder.helpers;

import excluder.algorithms.JaccardSimilarity;
import excluder.data.Node;
import excluder.http.DocumentParser;

import java.util.ArrayList;
import java.util.HashSet;

public class SimilarityHelper {

    public static int getTreeSimilarity(Node nodeOne, Node nodeTwo) {
        HashSet<String> elementsOne = getElements(nodeOne);
        HashSet<String> elementsTwo = getElements(nodeTwo);

        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static int getStyleSimilarity(Node nodeOne, Node nodeTwo) {
        HashSet<String> elementsOne = getStyleClasses(nodeOne);
        HashSet<String> elementsTwo = getStyleClasses(nodeTwo);

        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static HashSet<String> getElements(Node node) {
        if (node.getElements() == null) {
            node.setElements(new DocumentParser(node).getElements());
        }

        return node.getElements();
    }

    public static HashSet<String> getStyleClasses(Node node) {
        if (node.getStyleClasses() == null) {
            node.setStyleClasses(new DocumentParser(node).getStyleClasses());
        }

        return node.getStyleClasses();
    }
}
