package excluder.adapters;

import excluder.sets.OrderedHashSet;
import excluder.data.Node;

import javax.swing.*;

public class NodesAdapter extends AbstractListModel implements OrderedHashSet.OrderedHashSetListener {

    private OrderedHashSet nodes;

    public NodesAdapter(OrderedHashSet nodes) {
        this.nodes = nodes;
        this.nodes.setListener(this);
    }

    @Override
    public int getSize() {
        return nodes.size();
    }

    @Override
    public Node getElementAt(int index) {
        return (Node) nodes.get(index);
    }

    @Override
    public void indexAdded(int start, int end) {
        this.fireIntervalAdded(this, start, end);
    }

    @Override
    public void indexChanged(int start, int end) {
        this.fireContentsChanged(this, start, end);
    }

    @Override
    public void indexRemoved(int start, int end) {
        this.fireIntervalRemoved(this, start, end);
    }

}
