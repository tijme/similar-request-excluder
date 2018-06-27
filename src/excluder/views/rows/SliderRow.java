package excluder.views.rows;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;

public class SliderRow extends BaseRow implements ChangeListener {

    private Integer defaultValue;

    private Integer value;

    private JLabel title = new JLabel();

    private JSlider slider = new JSlider();

    public SliderRow(String title, String description, Integer defaultValue) {
        this(title, description, defaultValue, 0, 100);
    }

    public SliderRow(String title, String description, Integer value, Integer minValue, Integer maxValue) {
        super(title, description);

        this.slider.setMinimum(minValue);
        this.slider.setMaximum(maxValue);
        this.setValue(value);
    }

    public Integer getValue() {
        return value;
    }

    public void setValue(Integer value) {
        this.slider.setValue(value);
        this.value = value;
    }

    @Override
    public JLabel getTitleComponent() {
        title.setFont(new Font("Dialog", Font.BOLD, 13));
        title.setForeground(Color.DARK_GRAY);
        title.setText(getTitle(this.value));

        return title;
    }

    @Override
    public JLabel getDescriptionComponent() {
        JLabel description = new JLabel("<html>" + getDescription() + "</html>");

        description.setForeground(Color.DARK_GRAY);

        return description;
    }

    @Override
    public Component getComponent() {
        slider.addChangeListener(this);
        slider.setMajorTickSpacing(1);
        slider.setMinorTickSpacing(1);

        return slider;
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
        constraints.insets = new Insets(0, 10, 0, 10);

        JLabel description = getDescriptionComponent();
        panel.add(description, constraints);

        constraints.gridx = 0;
        constraints.gridy = ++ verticalIndex;
        constraints.weightx = 1.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.CENTER;
        constraints.insets = new Insets(0, 10, 5, 10);

        Component component = getComponent();
        panel.add(component, constraints);

        return ++ verticalIndex;
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        JSlider source = (JSlider) e.getSource();

        this.setValue(source.getValue());
        this.title.setText(getTitle(this.value));
    }
}