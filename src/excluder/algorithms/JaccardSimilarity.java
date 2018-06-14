package excluder.algorithms;

import java.util.*;

public class JaccardSimilarity {

    public static int apply(HashSet<String> left, HashSet<String> right) {
        int leftSize = left.size();
        int rightSize = right.size();

        if (leftSize == 0 || rightSize == 0) {
            return -1;
        }

        left.retainAll(right);

        double intersection = (double) left.size();
        double denominator = leftSize + rightSize - intersection;

        double result = (intersection) / (Math.max(denominator, 1));
        double percentage = result * 100;

        return (int) Math.round(percentage);
    }

}
