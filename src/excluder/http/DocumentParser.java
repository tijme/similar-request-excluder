package excluder.http;

import excluder.data.Node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DocumentParser {

    private HashSet<String> elements = new HashSet<String>();

    private HashSet<String> styleClasses = new HashSet<String>();

    public DocumentParser(Node node) {
        Pattern reTags = Pattern.compile("<([a-zA-Z0-9]+)(([^<>])+)?>");
        Matcher mTags = reTags.matcher(node.getHtml());

        while (mTags.find()) {
            elements.add(mTags.group().replaceAll("=([\"'`]).+?\\1", ""));
        }

        Pattern reClasses = Pattern.compile("class=(['\\\"`])(.+?)\\1");
        Matcher mClasses = reClasses.matcher(node.getHtml());

        while (mClasses.find()) {
            styleClasses.addAll(Arrays.asList(mClasses.group(2).trim().split(" ")));
        }
    }

    public HashSet<String> getElements() {
        return this.elements;

    }

    public HashSet<String> getStyleClasses() {
        return this.styleClasses;
    }


}