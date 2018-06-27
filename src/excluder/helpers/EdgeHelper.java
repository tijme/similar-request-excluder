package excluder.helpers;

import excluder.ExtensionOptions;
import excluder.data.Edge;

import java.net.URL;
import java.util.ArrayList;

public class EdgeHelper {

    private static String wordMatch ="^\\d+$";

    private static String numberMatch = "^\\w+$";

    private static String slugMatch = "^[.A-Za-z0-9_-]+$";

    public static ArrayList<Edge> getEdges(URL url, String html) {
        ArrayList<Edge> properties = new ArrayList<Edge>();

        addUrlMetaEdges(properties, url);
        addUrlPathEdges(properties, url);
        addUrlQueryEdges(properties, url);

        return properties;
    }

    private static void addUrlMetaEdges(ArrayList<Edge> properties, URL url) {
        properties.add(new Edge(url.getProtocol(), ExtensionOptions.OPTION_URL_META_PROTOCOL_MATCH));
        properties.add(new Edge(url.getHost(), ExtensionOptions.OPTION_URL_META_HOST_MATCH));
    }

    private static void addUrlPathEdges(ArrayList<Edge> properties, URL url) {
        if (url.getPath() == null) {
            return;
        }

        String[] parts = url.getPath().split("/");

        int index = -1;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }

            index ++;

            // Exact match
            properties.add(new Edge(part + String.valueOf(index), ExtensionOptions.OPTION_URL_PATH_EXACT_MATCH));

            // Number match
            if (part.matches(numberMatch)) {
                properties.add(new Edge(String.valueOf(index), ExtensionOptions.OPTION_URL_PATH_NUMBER_MATCH));
                continue;
            }

            // Word match
            if (part.matches(wordMatch)) {
                properties.add(new Edge(String.valueOf(index), ExtensionOptions.OPTION_URL_PATH_WORD_MATCH));
                continue;
            }

            // Slug match
            if (part.matches(slugMatch)) {
                properties.add(new Edge(String.valueOf(index), ExtensionOptions.OPTION_URL_PATH_SLUG_MATCH));
            }
        }
    }

    private static void addUrlQueryEdges(ArrayList<Edge> properties, URL url) {
        if (url.getQuery() == null) {
            return;
        }

        String[] parts = url.getQuery().split("&");

        int index = -1;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }

            index ++;

            String[] keyValue = part.split("=", 2);
            String key = keyValue[0];
            String value = keyValue.length == 2 ? keyValue[1] : keyValue[0];

            // Exact match
            properties.add(new Edge(part + String.valueOf(index), ExtensionOptions.OPTION_URL_QUERY_EXACT_MATCH));

            // Number match
            if (value.matches(numberMatch)) {
                properties.add(new Edge(key + String.valueOf(index), ExtensionOptions.OPTION_URL_QUERY_NUMBER_MATCH));
                continue;
            }

            // Word match
            if (value.matches(wordMatch)) {
                properties.add(new Edge(key + String.valueOf(index), ExtensionOptions.OPTION_URL_QUERY_WORD_MATCH));
                continue;
            }

            // Slug match
            if (value.matches(slugMatch)) {
                properties.add(new Edge(key + String.valueOf(index), ExtensionOptions.OPTION_URL_QUERY_SLUG_MATCH));
            }
        }
    }

}
