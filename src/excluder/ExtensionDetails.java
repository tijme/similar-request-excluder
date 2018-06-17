package excluder;

import excluder.helpers.FileHelper;

public class ExtensionDetails {

    public static final String TITLE = "Similar Request Excluder";

    public static String VERSION = "Unknown";

    public static final String DOCUMENTATION_URL = "https://github.com/tijme/similar-request-excluder/wiki";

    public static final String REPORT_BUG_URL = "https://github.com/tijme/similar-request-excluder/issues";

    public static final String VERSION_URL = "https://github.com/tijme/similar-request-excluder/releases/tag";

    public static void initialize() {
        VERSION = FileHelper.getResource(".semver").trim();
    }

}
