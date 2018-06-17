package excluder.views.custom;

import javax.swing.*;
import java.awt.*;

public class ScrollableSidebar extends JPanel implements Scrollable {

    public ScrollableSidebar() {
        this(new GridLayout(0, 1));
    }

    public ScrollableSidebar(LayoutManager manager) {
        super(manager);
    }

    public ScrollableSidebar(Component component) {
        this();
        this.add(component);
    }

    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return (getPreferredSize());
    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return (15);
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return (100);
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return (true);
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        return (false);
    }

}