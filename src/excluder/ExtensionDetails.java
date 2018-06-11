package excluder;

import excluder.helpers.FileHelper;

public class ExtensionDetails {

    public static final String TITLE = "Similar Request Excluder";

    public static String VERSION = "Unknown";

    public static final String DOCUMENTATION_URL = "https://github.com/tijme/excluder/wiki";

    public static final String REPORT_BUG_URL = "https://github.com/tijme/excluder/issues";

    public static void initialize() {
        VERSION = FileHelper.getResource(".semver").trim();
    }

}
