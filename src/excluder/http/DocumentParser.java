package excluder.http;

import excluder.data.Node;

import java.util.ArrayList;
import java.util.Arrays;

public class DocumentParser {

    public ArrayList<String> elements = new ArrayList<String>();

    public ArrayList<String> styleAttributes = new ArrayList<String>();

    public ArrayList<String> styleClasses = new ArrayList<String>();

    private boolean isInElement = false;
    private boolean isInAttribute = false;
    private boolean isInClassAttribute = false;

    private String attributeCharacters = "\"'`";

    private Character currentAttributeQuote;

    private int elementIndex = 0;

    public DocumentParser(Node node) {
        for (char character: node.getHtml().toCharArray()) {
            // Check for new element
            if (!isInElement && character == '<') {
                isInElement = true;
            }

            // If in element, add character to current element
            if (isInElement) {
                addCharacterToCurrentElement(character);
            }

            // If is in attribute and closing
            if (isInAttribute && character == currentAttributeQuote) {
                isInAttribute = false;
                isInClassAttribute = false;
                currentAttributeQuote = null;
            } else {
                // If in class attribute
                addCharacterToCurrentClass(character);

                // If opening an attribute
                if (!isInAttribute && isInElement && attributeCharacters.indexOf(character) == -1) {
                    currentAttributeQuote = character;
                    isInAttribute = true;

                    // Check if class attribute
                    if (elements.get(elementIndex).endsWith("class=" + character)) {
                        isInClassAttribute = true;
                    }
                }
            }

            // If is in element and closing
            if (isInElement && character == '>' && !isInAttribute) {
                isInElement = false;
                elementIndex ++;
            }
        }

        // Convert style attributes to classes
        for (String attribute : styleAttributes) {
            styleClasses.addAll(Arrays.asList(attribute.split(" ")));
        }

        // Garbage collection
        styleAttributes = null;
    }

    private void addCharacterToCurrentElement(char character) {
        String currentElement = elements.get(elementIndex);

        if (currentElement == null) {
            elements.add(elementIndex, "");
            currentElement = "";
        }

        elements.add(elementIndex, currentElement + character);
    }

    private void addCharacterToCurrentClass(char character) {
        String currentStyleClass = styleAttributes.get(elementIndex);

        if (currentStyleClass == null) {
            styleAttributes.add(elementIndex, "");
            currentStyleClass = "";
        }

        elements.add(elementIndex, currentStyleClass + character);
    }

    public String[] getElements() {
        return (String[])  this.elements.toArray();
    }

    public String[] getStyleClasses() {
        return (String[]) this.styleClasses.toArray();
    }

}