package excluder.views.rows;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;

public class CheckBoxRow extends BaseRow implements ChangeListener {

    private JCheckBox checkBox = new JCheckBox(getDescription());

    private Boolean value;

    public CheckBoxRow(String title, String description, Boolean value) {
        super(title, description);
        this.setValue(value);
    }

    public Boolean getValue() {
        return value;
    }

    public void setValue(Boolean value) {
        this.checkBox.setSelected(value);
        this.value = value;
    }

    @Override
    public JLabel getTitleComponent() {
        JLabel title = new JLabel(getTitle());

        title.setFont(new Font("Dialog", Font.BOLD, 13));
        title.setForeground(Color.DARK_GRAY);

        return title;
    }

    @Override
    public JLabel getDescriptionComponent() {
        return null;
    }

    @Override
    public Component getComponent() {
        checkBox.setForeground(Color.DARK_GRAY);
        checkBox.addChangeListener(this);

        return checkBox;
    }

    public int appendTo(JPanel panel, int verticalIndex, boolean isLast) {
        GridBagLayout layout = (GridBagLayout) panel.getLayout();
        GridBagConstraints constraints = layout.getConstraints(panel);

        constraints.gridx = 0;
        constraints.gridy = verticalIndex;
        constraints.weightx = 1.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.CENTER;
        constraints.insets = new Insets(0, 10, 2, 10);

        JLabel title = getTitleComponent();
        panel.add(title, constraints);

        constraints.gridx = 0;
        constraints.gridy = ++ verticalIndex;
        constraints.weightx = 1.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.CENTER;
        constraints.insets = new Insets(2, 10, 10, 10);

        Component component = getComponent();
        panel.add(component, constraints);

        return ++ verticalIndex;
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        JCheckBox source = (JCheckBox) e.getSource();
        this.setValue(source.isSelected());
    }
}
