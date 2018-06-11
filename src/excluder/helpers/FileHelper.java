package excluder.helpers;

import burp.BurpExtender;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class FileHelper {

    public static String getResource(String filename) {
        InputStream inputStream = BurpExtender.class.getResourceAsStream("/" + filename);
        StringBuilder stringBuilder = new StringBuilder();

        try {
            InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(reader);

            String line = null;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return stringBuilder.toString();
    }

}
