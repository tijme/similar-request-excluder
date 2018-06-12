package excluder.helpers;

import excluder.ExtensionDebugger;
import excluder.algorithms.JaccardSimilarity;
import excluder.data.Node;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;

// @TODO
public class SimilarityHelper {

    public static int getTreeSimilarity(Node nodeOne, Node nodeTwo, Document soupOne, Document soupTwo) {

        ArrayList<String> elementsOne = getElements(nodeOne, soupOne);
        ArrayList<String> elementsTwo = getElements(nodeTwo, soupTwo);

        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static int getStyleSimilarity(Node nodeOne, Node nodeTwo, Document soupOne, Document soupTwo) {
        ArrayList<String> elementsOne = getStyleClasses(nodeOne, soupOne);
        ArrayList<String> elementsTwo = getStyleClasses(nodeTwo, soupTwo);

        return JaccardSimilarity.apply(elementsOne, elementsTwo);
    }

    public static ArrayList<String> getElements(Node node, Document soup) {
        if (node.getElements() != null) {
            return node.getElements();
        }

        ArrayList<String> elements = new ArrayList<String>();

        Elements selected = soup.getAllElements();
        for (String element: elements) {
            ExtensionDebugger.output(element);
        }

//        Document defaultDoc = Jsoup.parse(defaultString);
//        Elements values = defaultDoc.getElementsByAttribute("value"); //DropDownList Values
//        String s[] = {""};
//        for(int a=0; a<values.size(); a++){
//            s[a] = values.get(a).toString();
//        }

        return elements;
    }

    public static ArrayList<String> getStyleClasses(Node node, Document soup) {
        if (node.getStyleClasses() != null) {
            return node.getStyleClasses();
        }

        ArrayList<String> styleClasses = new ArrayList<String>();

//        Document defaultDoc = Jsoup.parse(defaultString);
//        Elements values = defaultDoc.getElementsByAttribute("value"); //DropDownList Values
//        String s[] = {""};
//        for(int a=0; a<values.size(); a++){
//            s[a] = values.get(a).toString();
//        }

        return styleClasses;
    }
}
