package excluder.http;

public class SimilarityBlacklist {

    public static boolean shouldProcess(String html) {
//        if (html.contains("Index of /") && html.contains("Last modified") && html.contains("<a href=\"?C=N;O=")) {
//            return false;
//        }

        return true;
    }
}
