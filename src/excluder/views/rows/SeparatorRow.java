package excluder.views.rows;

import javax.swing.*;
import java.awt.*;

public class SeparatorRow extends BaseRow {

    public SeparatorRow() {
        this("", "");
    }

    public SeparatorRow(String title, String description) {
        super(title, description);
    }

    @Override
    public JLabel getTitleComponent() {
        return null;
    }

    @Override
    public JLabel getDescriptionComponent() {
        return null;
    }

    @Override
    public Component getComponent() {
        return null;
    }

    public int appendTo(JPanel panel, int verticalIndex, boolean isLast) {
        GridBagLayout layout = (GridBagLayout) panel.getLayout();
        GridBagConstraints constraints = layout.getConstraints(panel);

        constraints.gridx = 0;
        constraints.gridy = verticalIndex;
        constraints.fill = isLast ? GridBagConstraints.VERTICAL : GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.PAGE_START;
        constraints.weightx = 1.0;
        constraints.weighty = isLast ? 1.0 : 0.0;
        constraints.insets = new Insets(0, 0, 0, 0);

        Component separator = getSeparatorComponent();
        panel.add(separator, constraints);

        return ++ verticalIndex;
    }

}
