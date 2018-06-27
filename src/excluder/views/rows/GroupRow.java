package excluder.views.rows;

import javax.swing.*;
import java.awt.*;

public class GroupRow extends BaseRow {

    public GroupRow(String title) {
        this(title, "");
    }

    public GroupRow(String title, String description) {
        super(title, description);
    }

    @Override
    public JLabel getTitleComponent() {
        JLabel title = new JLabel(getTitle());

        title.setFont(new Font("Dialog", Font.BOLD, 16));

        return title;
    }

    @Override
    public JLabel getDescriptionComponent() {
        if (getDescription().isEmpty()) {
            return null;
        }

        return new JLabel("<html>" + getDescription() + "</html>");
    }

    @Override
    public Component getComponent() {
        return null;
    }

    public int appendTo(JPanel panel, int verticalIndex, boolean isLast) {
        GridBagLayout layout = (GridBagLayout) panel.getLayout();
        GridBagConstraints constraints = layout.getConstraints(panel);

        boolean hasDescription = !getDescription().isEmpty();

        constraints.gridx = 0;
        constraints.gridy = ++ verticalIndex;
        constraints.weightx = 1.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.CENTER;
        constraints.insets = new Insets(10, 10, hasDescription ? 0 : 8, 10);

        Component component = getTitleComponent();
        panel.add(component, constraints);

        if (hasDescription) {
            constraints.gridx = 0;
            constraints.gridy = ++verticalIndex;
            constraints.weightx = 1.0;
            constraints.weighty = 0.0;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.anchor = GridBagConstraints.CENTER;
            constraints.insets = new Insets(0, 10, 8, 10);

            JLabel description = getDescriptionComponent();
            panel.add(description, constraints);
        }

        return ++ verticalIndex;
    }

}
