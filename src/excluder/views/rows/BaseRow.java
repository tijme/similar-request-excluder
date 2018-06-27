package excluder.views.rows;

import javax.swing.*;
import java.awt.*;

public abstract class BaseRow {

    private String title;

    private String description;

    public abstract JLabel getTitleComponent();
    public abstract JLabel getDescriptionComponent();
    public abstract Component getComponent();

    public abstract int appendTo(JPanel panel, int verticalIndex, boolean isLast);

    BaseRow(String title, String description) {
        this.title = title;
        this.description = description;
    }

    Component getSeparatorComponent() {
        return new JSeparator();
    }

    String getTitle() {
        return title;
    }

    String getTitle(Integer value) {
        return getTitle() + " (" + String.valueOf(value) + ")";
    }

    String getDescription() {
        return description;
    }

}
