package excluder.helpers;

import excluder.ExtensionDebugger;
import excluder.algorithms.JaccardSimilarity;
import excluder.data.Node;
import excluder.http.DocumentParser;

public class SimilarityHelper {

    public static int getTreeSimilarity(Node nodeOne, Node nodeTwo) {
        String[] elementsOne = getElements(nodeOne);

        ExtensionDebugger.output(elementsOne.toString());

        String[] elementsTwo = getElements(nodeTwo);



        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static int getStyleSimilarity(Node nodeOne, Node nodeTwo) {
        String[] elementsOne = getStyleClasses(nodeOne);
        String[] elementsTwo = getStyleClasses(nodeTwo);

        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static String[] getElements(Node node) {
        if (node.getElements() == null) {
            node.setElements(new DocumentParser(node).getElements());
        }

        return node.getElements();
    }

    public static String[] getStyleClasses(Node node) {
        if (node.getStyleClasses() == null) {
            node.setStyleClasses(new DocumentParser(node).getStyleClasses());
        }

        return node.getStyleClasses();
    }
}
